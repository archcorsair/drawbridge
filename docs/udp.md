# UDP support — design and execution plan

> Status: BUILT (2026-07-30, U1–U4; U5 auto-discovery deferred). Results and
> findings folded into plan.md's "UDP results"; this doc records the design
> and its rejected alternatives. Companion to [plan.md](plan.md) (architecture,
> phase results) and [HANDOFF.md](HANDOFF.md) (open items). Scope: both
> directions — guest UDP listeners mirrored onto Mac localhost (inbound), and
> Mac loopback UDP services reachable from the guest at `127.0.0.1:P`
> (outbound). Workload to optimize for: DNS-shaped request/response traffic —
> small datagrams, many short-lived flows, frequently one client socket per
> query.

## Where UDP stands today (verified against the tree, 2026-07-30)

Already working:

- **Guest-side steering** — `guest_ports` / `mac_ports` key on
  `{proto, v4-mapped addr, port}`; `cgroup/sendmsg4/6` + `recvmsg4/6` steer
  unconnected UDP per-datagram; `connect4/6` covers connected UDP sockets;
  `recvmsg` un-rewrites reply sources statelessly (same-port scheme). Phase 1
  assertion 4 proves unconnected demux: one socket, two mapped ports,
  per-flow reply ports.
- **Guest gateway UDP proxy** (`internal/proxy/udp.go`) — per-client relay
  sockets, replies written from the gateway listener so the BPF un-rewrite
  stays stateless. Backend is currently a fixed UDP dial (in-guest dummies).
- **Tracker** — `fexit/udp_{v4,v6}_get_port` + `fentry/udp_lib_unhash`,
  refcounted into `guest_ports`, netns-scoped, events carry `proto:"udp"`.
- **Transport plumbing** — `'S'`/`'D'` activation header is
  `{proto u8, port u16 BE, reserved u8}`; the proto byte already exists, both
  ends currently reject `proto != 6`.

Missing (this plan): datagram framing over the byte-stream transport, the Mac
mirror's UDP path, a real Mac backend behind the gateway UDP proxy, Mac-side
UDP port configuration, idle-flow expiry, tests and bench legs.

**`internal/bpf/` changes: NONE.** Every mechanism this plan needs is already
in the kernel side. One tempting BPF change exists (see "The client-socket
problem") and is explicitly deferred with rationale.

## Design overview

Both directions use the same shape: **one framed stream per (proto=17, port),
muxing all client flows over it, with each frame carrying the flow's client
`AddrPort`.** Datagrams are length-prefixed frames on the existing `'S'`
(inbound) and `'D'` (outbound) stream kinds, selected by proto byte 17 in the
unchanged 4-byte activation header.

- **Inbound** (guest listener → Mac localhost): drawbridged binds a UDP
  socket on `127.0.0.1:P`, opens one `'S'` stream with header `{17, P, 0}`,
  and pumps frames both ways. The agent end keeps one relay UDP socket per
  Mac client (distinct guest-side ephemeral source ports → the guest server
  sees distinct peers, replies demux natively) and frames replies back with
  the client's address. The Mac end is **stateless**: reply frames carry the
  destination, so it just `WriteToUDPAddrPort`s.
- **Outbound** (guest → Mac service): `AddMacPort(UDP, P, backend="")` runs a
  stream-backed gateway proxy. On the first datagram it activates a parked
  `'D'` conn via the existing `macDialer` (pop + header `{17, P, 0}`), then
  frames `{guest client AddrPort, payload}`. The Mac end (syncer) keeps one
  UDP socket connected to `127.0.0.1:P` per guest client and frames replies
  back; the guest gateway writes them from its listener socket to the client,
  so the BPF `recvmsg` un-rewrite works exactly as in Phase 1. The guest end
  keeps **no per-flow sockets** in Mac mode — flow state lives on the side
  that dials the real backend.

### Why mux, when Phase 3 rejected it

The Phase 3 decision ("park-ahead pool over a mux protocol — no per-byte
framing") was about **byte streams**: muxing TCP would tax every byte of
every connection with framing. Datagrams invert that calculus — they *must*
be framed over a TCP transport anyway (message boundaries cannot be inferred
from a byte stream), so the marginal cost of muxing is 18 bytes of addressing
per datagram, not a new framing layer. Meanwhile the alternative
(stream-per-flow) is maximally hostile to the target workload: stub resolvers
routinely open **one socket per DNS query**, so every query would pay a
transport conn setup (~1 ms over the SSH forwarder, per the bench) and burn a
parked pool conn. Muxed per-port streams make a new flow cost exactly one
frame.

Head-of-line coupling is the real price of the mux and it is acceptable here:
frames are bounded at ~64 KiB, the transport moves ~450 MB/s, so a maximal
datagram delays a queued DNS query by ~150 µs — and only within the same
port; different ports ride different streams.

**What would make stream-per-flow win instead:** a workload of few,
long-lived, latency-critical flows per port where cross-flow HOL matters
(e.g. a game server plus a bulk telemetry stream on one port), or if the
per-frame addressing proved bug-prone. Neither applies to DNS-shaped traffic.

### Why reuse `'S'`/`'D'` rather than a new `'U'` kind

The activation header already carries a proto byte; both ends already branch
on it (today: reject). Reusing the kinds keeps: one parked pool (no second
pool sizing question), the unchanged watchdog contract, one transport doc
comment, and symmetric Mac-dials-everything topology. A new kind would buy
nothing unless UDP needed *different parking semantics* (e.g. guest-initiated
channels or keepalives) — it doesn't. The reserved byte in the activation
header is the version escape hatch (see frame layout).

### Invariants check (all preserved)

- **Parked `'D'` conns stay silent until the guest writes the 4-byte
  header.** Outbound activation is exactly the existing `macDialer` pop +
  header write; frames flow only after it. The Mac end writes nothing on a
  `'D'` conn until it has read the header and received a request frame
  (request/response traffic — the Mac never sends unsolicited). The watchdog
  and `probeLive` are untouched.
- **Frames are transport-agnostic.** Framing lives above `net.Conn`; the
  vsock swap still only touches the dial/listen seam.
- **No per-flow orig-dst maps, stateless un-rewrites.** Replies are always
  written from the gateway/mirror listener socket itself; the same-port
  scheme is what lets both stream ends stay thin.
- **Reservations (`'R'`) stay TCP-only**; `seccomp.IsInetStream` continues to
  exclude datagram sockets. UDP bind arbitration is out of scope.
- **Mirrors bind `127.0.0.1` only.** No multicast, no broadcast, no LAN
  exposure (mDNS to `224.0.0.251` is explicitly a non-goal).

## The client-socket problem (tracker events include every UDP bind)

`fexit/udp_v4_get_port` fires for **every** successful UDP bind — including
the kernel autobind a client socket gets on its first `sendto`/`connect`.
So the `'E'` event stream (and the `/proc/net` seed) reports every guest DNS
*client* socket as `udp 0.0.0.0:<ephemeral>`, indistinguishable by address
from a genuine wildcard server. Mirroring those would bind/unbind a Mac UDP
socket per guest query — churn, Mac ephemeral-space pollution, and noise.
(This was invisible until now because `mirror.add` drops all UDP.)

**Decision: filter by port range on the Mac mirror side.** `mirrorable()`
rejects UDP listeners whose port falls in the Linux default ephemeral range
**32768–60999**. Autobound sockets are always allocated from that range, so
the filter is a pure function of port — which makes add/del filtering
self-consistent (no refcount skew: an ephemeral client's del can never
decrement a mirrored server's entry, because a mirrored port is by definition
outside the range).

Costs, stated honestly:

- *False negative:* a guest UDP server deliberately bound inside 32768–60999
  is not mirrored. Log once per port at debug level so it's diagnosable.
- *False positive:* a client that explicitly binds a port outside the range
  gets a useless (traffic-less) Mac mirror. Harmless.
- The guest's range could be tuned via `ip_local_port_range`; we hardcode the
  default and document it. Not worth a knob until someone hits it.

**Rejected (for now): the precise fix is a one-line BPF change** — the hook
already receives `snum` (the *requested* port), so `snum == 0` identifies
autobind/ephemeral exactly. Passing an "explicit bind" flag through would
require: a `ListenerEvent` layout change, storing the flag in the `sk_keys`
value so teardown events carry it too (dels have no `snum`), `just gen` +
regenerated-Go commit, and event-schema coupling between agent and
drawbridged versions. That is the expensive surface; the range heuristic is
free and reversible. **If the false negative ever matters, the `snum` flag is
the upgrade path — flagged loudly here because it is the one place this
design was tempted to touch `internal/bpf/`.**

## Frame layout (protocol surface — byte-exact, cannot be taken back)

### Activation header (unchanged)

Both `'S'` and `'D'`, immediately after the kind byte ('S') or at pop-time
('D'), 4 bytes:

```
offset  size  field
0       1     proto     — 6 = TCP raw splice (existing), 17 = UDP framed
1       2     port      — u16 big-endian, nonzero
3       1     reserved  — MUST be 0; receiver closes the conn on nonzero
```

`reserved` is the framing-version escape hatch: today 0 means "v1 datagram
frames follow". A future incompatible framing bumps it; an old peer closes
the conn, which degrades to no-UDP, never to corrupt splicing.

### Datagram frame (both directions, symmetric)

After a proto-17 activation header, the stream carries a sequence of frames.
Fixed 21-byte header, then payload:

```
offset  size  field
0       2     length  — u16 big-endian, payload bytes N, 0 ≤ N ≤ 65507
2       1     flags   — MUST be 0; receiver closes the stream on nonzero
3       16    addr    — flow peer address, IPv6 or IPv4-mapped
                        (::ffff:a.b.c.d), network byte order
19      2     port    — flow peer port, u16 big-endian, nonzero
21      N     payload — the datagram, verbatim (N = 0 is legal UDP)
```

- **Flow peer** is the *client* side of the flow — the Mac client's
  `AddrPort` for inbound, the guest client's for outbound. Reply frames MUST
  echo the peer of the request flow; it is the demux key and the reply
  destination.
- **Max frame** = 21 + 65507 = 65528 bytes. `length > 65507` or nonzero
  `flags` is an unrecoverable desync: close the stream (the owner redials /
  re-activates; in-flight datagrams are lost, which is UDP).
- Each frame is written with a **single `Write`** (header + payload in one
  buffer) under a per-stream write mutex — multiple relay goroutines share
  one stream. Go's default `TCP_NODELAY` keeps request latency down.

Layout rationale, and what was rejected:

- *u16 length* — 65507 fits with headroom; a u32 buys nothing.
- *Fixed 16-byte v4-mapped address* over `{family u8, 4-or-16 bytes}` —
  fixed-size header reads, no variable-length parsing, matches the
  `port_key` v4-mapped convention, and is already v6-ready for the IPv6
  outbound roadmap item. Costs 12 bytes/datagram on v4; irrelevant at DNS
  sizes and ~0.02% at max size.
- *`flags` must-be-zero* — enforced now so it is actually usable later
  (e.g. an explicit flow-close control frame if idle-expiry-only teardown
  ever proves insufficient). Deliberate room, no speculative semantics.
- *No port in frames* — streams are per-port; repeating it per datagram is
  redundant. Rejected the alternative (one global UDP stream, port in every
  frame): couples all ports' HOL and complicates per-port lifecycle for zero
  benefit.

Implementation: new portable package `internal/udpframe` —
`WriteFrame(w, mu, addrport, payload)`, `ReadFrame(r, buf) (addrport,
payload, err)`, constants `MaxPayload = 65507`, `HeaderLen = 21`. Used by
`internal/proxy`, `internal/mirror`, `internal/macsync`, `internal/agent`.

## Inbound: guest UDP listener → Mac localhost

### Mac side (`internal/mirror/mirror.go`)

1. **Proto-keyed mirrors.** `mirrors map[uint16]*mirrorEntry` becomes
   `map[mirrorKey]*mirrorEntry` with `mirrorKey{proto string, port uint16}` —
   a guest TCP and UDP listener on the same port are independent mirrors.
   `reconcile`/`add`/`del` count refs per key. Reservations (`handleReserve`)
   look up `{tcp, port}` only. `Mirrors(port)` (used by drawbridged's sync
   exclusion) becomes `Mirrors(proto string, port uint16)`.
2. **`mirrorable`** accepts `proto == "udp"` with the same address filter,
   plus the ephemeral-range rejection (32768–60999) described above.
3. **UDP mirror entry.** `openLocked` for UDP binds
   `net.ListenUDP("udp", 127.0.0.1:P)` (bind errors: same log-and-skip as
   TCP, including the <1024 privileged-port message — macOS reserves low
   ports for root regardless of proto, so mirroring guest `:53` needs
   privileged drawbridged, same story as TCP `:80`). A per-entry manager
   goroutine maintains the stream: dial `AgentAddr`, write `'S'` +
   `{17, P, 0}`, then two pumps:
   - socket→stream: `ReadFromUDPAddrPort` → frame `{client, payload}`.
   - stream→socket: `ReadFrame` → `WriteToUDPAddrPort(payload, client)`.
   On stream error: close it, back off 1 s, redial while the entry lives
   (datagrams read meanwhile are dropped — UDP semantics). On `del`/refs==0:
   close socket and stream. The stream is **eager** (opened at mirror-add):
   mirrors are few, one idle transport conn each is cheap, and the first
   inbound datagram pays nothing.
4. The Mac side keeps **no flow table** — reply frames carry the
   destination.

### Guest side (`internal/agent/transport.go` + new `internal/agent/udpstream.go`)

`serveStream` header branch: `proto == 17 && port != 0` →
`serveUDPStream(c, port)` (proto 6 unchanged; anything else still closes).

`serveUDPStream` (per-conn state, nothing shared — concurrent/reconnecting
streams for the same port are naturally independent):

- `relays map[netip.AddrPort]*relay` — on a frame from a new client,
  `net.DialUDP("udp", nil, 127.0.0.1:P)` (native under the connect4 hook:
  P is in `guest_ports`, that's why it was mirrored). Distinct ephemeral
  source ports per Mac client preserve the guest server's own per-peer
  demux, exactly mirroring `proxy/udp.go`'s shape.
- Per-relay reader goroutine frames replies back with the client's
  `AddrPort` under the stream write mutex.
- Idle expiry + flow cap (see "Flow state" below). Stream close tears down
  all relays.

## Outbound: guest → Mac UDP service

### Guest side

- **`internal/proxy`**: new stream-backed variant
  `NewUDPStream(listen netip.AddrPort, dial DialFunc, stats *Stats)` —
  the seam is the same `DialFunc` TCP got in Phase 3; here it yields a
  framed stream, not a per-flow socket:
  - readLoop on the gateway listener: datagram from guest client →
    ensure stream (lazily `dial()` on first need, serialized by mutex) →
    `WriteFrame(client, payload)`.
  - reply pump: `ReadFrame` → `p.ln.WriteToUDPAddrPort(payload, client)` —
    written from the gateway listener, so the client sees source
    `gateway:P` and the BPF recvmsg un-rewrite maps it to `127.0.0.1:P`
    statelessly (Phase 1 semantics, unchanged).
  - Stream error: drop it; the next datagram re-activates. Guest clients
    never observe the churn — their reply source is always `127.0.0.1:P`
    (the Mac-side ephemeral ports behind the stream are invisible to them).
  - If `dial()` fails (no parked conn / Mac gone): drop the datagram. The
    sync session's death removes the port anyway, restoring native
    behavior for subsequent traffic.
- **`internal/agent/agent.go`** `AddMacPort`: the
  `proto == ProtoUDP && backend == ""` arm stops erroring and builds
  `proxy.NewUDPStream(gwAddr, a.macDialer(bpf.ProtoUDP, port), a.Stats)`.
  `macDialer` is reused **verbatim** — pop parked `'D'`, write
  `{17, port, 0}`. Lazy activation (first datagram) rather than eager at
  add-time: pop is ~150 µs (bench), so the first datagram pays essentially
  nothing, and synced-but-idle UDP ports don't each pin a pool conn.
- **`internal/agent/macsync.go`**: drop the `pn != bpf.ProtoTCP` gates in
  `addSyncPort` and `applySyncSnapshot` (the `want` filter). Session
  ownership/cleanup already handles both protos (`delSyncPort`,
  `removeSyncOwned` are proto-agnostic).

### Mac side (`internal/macsync/sync.go`)

- **Syncing** (what gets offered to the guest): `normalize` accepts
  `proto == "udp"` **only for explicitly configured ports** (see discovery
  section): new `Syncer.UDPPorts []uint16` config. Each configured port is
  synthesized into the synced set as `udp 0.0.0.0:P` unconditionally
  (no liveness probe — if nothing is bound on the Mac, guest datagrams are
  dropped at the Mac-side dial/ICMP, which is honest UDP). The existing
  `Exclude` hook must also cover UDP so drawbridged can exclude its own UDP
  mirrors (`Mirrors("udp", port)`) — belt-and-braces against sync loops
  (BPF arbitration already lets `guest_ports` win, but don't rely on it).
- **`handleStream`**: `proto == 17` → the Mac-side flow handler:
  `flows map[netip.AddrPort]*net.UDPConn`, each connected to
  `127.0.0.1:port` via a new `DialLocalUDP func(port) (*net.UDPConn, error)`
  seam (test-injectable, like `DialLocal`); per-flow reader goroutine frames
  replies with the guest client's `AddrPort`; idle expiry + cap. Stream
  death tears down all flows (guest re-activates a fresh stream; new
  Mac-side source ports are invisible to guest clients, per above).
- `parkOne` already passes the header through generically — only
  `handleStream`'s proto check changes.

### Mac UDP "listener" discovery — deliberately out of scope this iteration

HANDOFF's "Mac UDP sync is rejected explicitly" stands, for the inbound
reason it was rejected: `net.inet.udp.pcblist_n` has **no LISTEN state** —
every bound UDP socket appears, including every transient DNS client socket
the Mac ever opens. A wrong filter syncs those into `mac_ports`, steering
guest traffic into black holes and churning the map at query rate. The
plausible filter (unconnected `inp_fport == 0` + local port outside
`net.inet.ip.portrange` + loopback/any bind) rests on xnu-private offsets in
a *different* pcb layout than the TCP one we pinned (no `xt_tcpcb` block;
group layout must be verified against netstat sources, not assumed) — the
expensive-to-verify surface, for a filter that is still heuristic.

**This iteration: explicit configuration only.** drawbridged gains a
repeatable flag (`-udp 53 -udp 8125` style, or comma list) wired to
`Syncer.UDPPorts`. Cheap, zero false positives, fully reversible, and it
unblocks the real use cases (a local DNS server, a statsd agent) today.
Auto-discovery via `udp.pcblist_n` is **Phase U5, deferred pending user
decision** (open question #1); if built, it lands behind `-udp-sync=auto`
defaulting off, with darwin offset-pinning tests like the TCP ones.

## Flow state and idle expiry

UDP has no FIN; every flow table above needs expiry. One policy everywhere:

- **Idle timeout: 60 s** since last datagram in either direction. DNS
  transactions finish in milliseconds; 60 s comfortably covers stub-resolver
  socket reuse and sits inside the conventional NAT UDP range (30–120 s;
  Linux conntrack uses 120 s for "assured" streams). One number, easy to
  reason about; a package-level `var` so tests can shrink it.
- **Sweep every 10 s** per flow table (timestamp check under the table's
  mutex; closing the flow's `UDPConn` unblocks its reader goroutine, which
  exits).
- **Cap: 4096 flows per stream/table.** At cap, new-client datagrams are
  dropped (throttled log). Bounds memory and goroutines against a
  socket-per-query storm; 4096 concurrent 60 s flows is far beyond the
  target workload.
- Expiry is invisible to correctness: a late reply to an expired flow is
  dropped (UDP); a client reusing its socket after expiry just looks like a
  new flow (outbound: the Mac-side source port changes, which the guest
  client cannot observe; inbound: the guest-side relay port changes, which a
  guest server treats as a new peer — same as any NAT rebinding).

Where each table lives (the side that dials the real backend):

| direction | flow table + expiry | stateless side |
|---|---|---|
| inbound (`'S'` proto 17) | agent `serveUDPStream` (relay per Mac client) | Mac mirror (frames carry reply addr) |
| outbound (`'D'` proto 17) | Mac `handleStream` (socket per guest client) | guest gateway (`NewUDPStream` writes replies from its listener) |

Additionally, the **existing in-guest-backend `udpProxy` gets the same
expiry** (it currently leaks one relay socket per client forever — a latent
leak worth fixing while we're here; Phase 1 semantics otherwise unchanged).

## Affected files

New:
- `internal/udpframe/frame.go`, `frame_test.go` — frame codec (portable).
- `internal/agent/udpstream.go` (linux) — inbound relay handler.
- `internal/proxy/udpstream.go` — stream-backed gateway proxy (portable).

Modified:
- `internal/proxy/udp.go` — idle expiry + cap in the existing relay proxy.
- `internal/proxy/proxy.go` — optional `Stats.UDPFlows` counter for tests.
- `internal/agent/transport.go` — proto-17 branch in `serveStream`; protocol
  doc comment updated (framing, version rule).
- `internal/agent/agent.go` — `AddMacPort` UDP-with-empty-backend arm.
- `internal/agent/macsync.go` — remove the two TCP-only gates.
- `internal/mirror/mirror.go` — proto-keyed mirror map, UDP entries +
  stream manager, ephemeral-range filter, `Mirrors(proto, port)`.
- `internal/macsync/sync.go` — `UDPPorts` config, `normalize` UDP arm,
  `handleStream` proto-17 flow handler, `DialLocalUDP` seam.
- `cmd/drawbridged/` — `-udp` flag(s); updated `Exclude` wiring.
- `internal/harness/harness_test.go`, `internal/harness/macsync_test.go`,
  `internal/e2e/e2e_test.go`, `internal/benchtool/*`,
  `internal/bench/bench_test.go` — per-phase verification below.
- `docs/plan.md` (results + decisions log), `docs/HANDOFF.md` (open items).

**`internal/bpf/`: nothing.** No map, key, hook, or event change. The one
candidate (explicit-bind `snum` flag) is deferred — see "The client-socket
problem"; if it is ever adopted it escalates cost (`just gen`, regen commit,
event-ABI coupling) and gets its own mini-plan.

## Phases

Each phase lands independently; the system works (TCP fully, UDP
incrementally) after every one.

### U1 — frame codec + proxy seams (no wire behavior change)

Build: `internal/udpframe` (codec, exhaustive boundary tests: N=0, N=65507,
N=65508 rejected, nonzero flags rejected, v4-mapped round-trip, torn reads);
idle expiry + cap in `udpProxy`; `proxy.NewUDPStream` tested against
`net.Pipe`-style fake streams (activation on first datagram, reply routing to
two clients, stream-death re-activation, expiry). All portable Go.

Verify:
```
go test ./internal/...        # on the Mac, includes -race in CI habit
just test-guest               # Phase 1 assertion 4 still green (expiry must not break demux)
```

### U2 — inbound mirror (tracker events already flow)

Build: mirror proto-keyed refactor + UDP entries + stream manager +
ephemeral-range filter; agent `serveUDPStream`; transport doc comment. Add a
portable mirror unit test against a fake agent (in-process TCP listener
speaking `'E'` + proto-17 `'S'`): UDP add event → mirror socket appears →
datagrams round-trip with boundaries; ephemeral-range events produce no
mirror; TCP+UDP same-port coexistence.

Verify:
```
go test ./internal/...        # Mac: mirror + agent-portable units
just test-guest               # agent-side suites
just agent-up                 # redeploy agent BEFORE e2e (old agent rejects proto 17)
just e2e                      # + new TestGuestUDPListenerReachableOnMacLocalhost
```
New e2e: start a guest UDP echo (`systemd-run` + a python one-liner, like the
HTTP pattern); from the Mac, **three concurrent client sockets** on
`localhost:P` each send tagged datagrams and must get their own replies
(reply routing), including a ~60000-byte datagram (boundary + size). Optional
container leg: `--network host` container UDP listener mirrored (reuses the
OCI e2e pattern) — the tracker path is identical, so this is a smoke test.

### U3 — outbound (real Mac backend behind the gateway)

Build: `AddMacPort` UDP arm + `macsync.go` gate removal (agent);
`Syncer.UDPPorts` + `normalize` + `handleStream` proto-17 + `DialLocalUDP`
(Mac); drawbridged `-udp` flag + UDP-aware `Exclude`.

Verify:
```
just test-guest   # extend harness/macsync_test.go: in-guest fake Mac session
                  # ('M' sync offering a UDP port + parked 'D' conns with the
                  # proto-17 flow handler) — assert the Phase 1 assertion-4
                  # shape end-to-end over framed streams: one unconnected
                  # guest socket, two synced ports, correct demux; plus a
                  # connected-UDP-client leg (connect4 path) and
                  # session-drop → entries removed.
just agent-up
just e2e          # + new TestMacUDPServiceReachableFromGuest
just bench        # regression only — the dial pool is now shared with UDP
```
New e2e: real Mac UDP echo on `127.0.0.1:P`, drawbridged in-process with
`UDPPorts: []uint16{P1, P2}`; guest clients via `guest()`: (a) unconnected
socket → both ports, demuxed (Phase 1 guarantee, now against real Mac
backends); (b) connected socket round-trip; (c) two concurrent guest
clients → one port, distinct replies.

### U4 — bench legs + results write-up

Build: `internal/benchtool` gains `benchudpserve` / UDP legs in
`benchclient`; `internal/bench` orchestrates:
- **DNS-shaped RTT** p50/p95 both directions (64 B query / 512 B reply, 300
  iterations), vs native loopback baselines each side.
- **Socket-per-query burst**: k = 4/8/16/32 fresh client sockets per wave,
  outbound — exercises flow-table churn and the lazy activation path (only
  the first wave should show the pop+header cost).
- **Large datagram**: 60 KiB round-trips, integrity-checked — HOL and
  framing throughput.

Verify: `just bench`; record numbers + findings in `plan.md` (new "UDP
results" section), update HANDOFF (UDP moves out of open items; discovery
remains listed).

### U5 — Mac UDP auto-discovery (DEFERRED — do not start without answer to Q1)

`net.inet.udp.pcblist_n` walker in `internal/macsync/pcblist_darwin.go`:
xinpcb_n-only groups (no `xt_tcpcb` — verify group/flush behavior against
netstat sources, never assume the TCP layout transfers); filter =
unconnected (`inp_fport == 0`) ∧ loopback/any bind ∧ local port outside
`sysctl net.inet.ip.portrange.first..last`; offsets pinned by darwin tests
against live bound sockets (the existing TCP test pattern). Behind
`-udp-sync=auto`, default off. Explicit `-udp` ports always sync regardless.

## Resolved questions (user-decided 2026-07-30)

1. **Explicit `-udp` ports only**; `udp.pcblist_n` auto-discovery stays
   deferred as U5 (xnu-private offsets + heuristic filter — riskiest surface,
   least certain payoff).
2. **Ephemeral-range heuristic** (32768–60999) for the inbound client-socket
   filter; the BPF `snum` flag remains the documented upgrade path if the
   false negative ever matters.
3. **No `:53` demo** — high ports, consistent with the TCP `:8080` decision;
   the privileged-`drawbridged` story stays where it is on the roadmap.
4. **Timeout/cap defaults accepted** — 60 s idle / 10 s sweep / 4096 flows,
   as package-level vars.
5. **Non-goals confirmed:** multicast/broadcast (mDNS, SSDP) and UDP bind
   arbitration stay out; loopback unicast only.
