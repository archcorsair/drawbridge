# Transport swap: off the SSH forwarder, onto the best Lima-compatible endpoint

Status: **designed, not yet built** (2026-07-30; amended same day — §2.6
DPI-safe conn-type frames as Phase 0, premise and Phase 5 refreshed after
the Local Network grant and the recorded vzNAT baseline). Companion to the
"Transport rides TCP, not vsock" open item in [HANDOFF.md](HANDOFF.md) and the
Benchmark/UDP findings in [plan.md](plan.md).

Goal: every transport byte between the Mac side (drawbridged, e2e, bench) and
the guest agent stops paying the SSH-forwarder tax — no half-close fragility,
no shared-tunnel head-of-line between bulk `'S'`/`'D'` legs and the
`'E'`/`'M'`/`'R'` control streams, burst latency bounded by the VM boundary.
Constraint (user-decided): **no Lima changes** — no patches, no forked
hostagent, no sidecar that owns the VM. Second environmental fact (refreshed
2026-07-30): macOS Local Network permission **is now granted** via the
subnet exemption ([notes/local-network-permission.md](notes/local-network-permission.md))
— vzNAT-direct is live, the resolver picks it by default, and its
pre-refactor baseline is recorded in plan.md §Benchmark. The forwarder
remains the fallback; nothing may hard-require the permission. Third
environmental fact: a DPI middlebox class (Little Snitch's network extension
on this machine; corporate endpoint security generally) holds ambiguous
lone-byte first segments on the vzNAT path for ~2 s — wire-proven, finding 3
of the note above — which motivates the §2.6 conn-type frames, landing
first as Phase 0.

---

## 1. The vsock question, settled (verified against Lima v2.2.0, 2026-07-21)

**Conclusion: a third-party host process cannot reach a guest vsock port on a
Lima vz VM. True AF_VSOCK is out for this iteration; `vsock://` lands as a
reserved scheme.** What was verified, and where:

- **Virtualization.framework scopes vsock to the VM-owning process.**
  `VZVirtioSocketDevice` is an object hanging off the `VZVirtualMachine`
  instance; `-connectToPort:completionHandler:` and vsock listeners are
  in-process API calls on that object. There is no filesystem or Mach endpoint
  a second process can use. Whoever owns the VM object (Lima's vz driver
  process) is the only host process that can dial guest vsock ports. This is
  an Apple API design fact, not a Lima limitation.
- **Lima uses vsock internally, and only internally.** In the current tree
  (`master` ≈ v2.2.0):
  - `pkg/driver/vz/vm_darwin.go` — the driver calls
    `wrapper.startVsockForwarder(ctx, 22, hostAddress)`: when the guest's
    sshd is detected listening on **vsock port 22** (requires guest
    systemd ≥ v256 for sshd socket activation on vsock), Lima re-points its
    own host-side SSH address at an in-process proxy into that vsock port.
    Hardcoded to port 22; the forwarder lives in
    `pkg/driver/vz/vsock_forwarder.go`; not configurable for other ports.
  - `pkg/hostagent/hostagent.go` — the hostagent carries a `vSockPort` for
    the guest-agent gRPC channel (vz driver reports it via
    `limaDriver.Info(ctx).VsockPort`); the connection is made inside Lima's
    processes.
  - The only user-facing vsock knob in `pkg/limatype/lima_yaml.go` is
    `ssh.overVsock *bool` — a toggle for the port-22 behavior above. There is
    **no** `lima.yaml` surface that bridges an arbitrary guest vsock port to a
    host unix/TCP socket.
- **QEMU vmType is not an escape hatch**: vhost-vsock needs a Linux host
  kernel (`/dev/vhost-vsock`); open issue lima-vm/lima#4209 ("QEMU on Linux
  hosts should utilize vsock") confirms vsock+QEMU is a Linux-host ambition,
  not a macOS option.

Two useful corollaries:

1. **If Lima ever ships generic vsock exposure, it will surface as a
   host-side unix or TCP socket** (that is the only shape an out-of-process
   consumer can use — exactly what `startVsockForwarder` already does for
   ssh). Our endpoint grammar therefore needs `unix://` and `tcp://` today
   and `vsock://` only as a reserved spelling for a future "drawbridge as
   Lima networking driver" integration, where drawbridge (or a Lima plugin it
   provides) is the VM-owning process.
2. **On guests with systemd ≥ 256, Lima's SSH path itself already rides
   vsock** under the SSH encryption. Our Ubuntu 24.04 guest has systemd 255,
   so our forwarder fallback rides the gvisor usernet NIC. This is a
   fallback-quality lever (newer guest image), not a design input — the SSH
   mux head-of-line and crypto cost remain either way.

**So the best endpoint reachable without modifying Lima is the vzNAT guest IP
over plain TCP** — end-to-end, no forwarder, one independent TCP flow per
purpose, native half-close. That path already exists (`internal/limaaddr`,
`networks: [vzNAT]` in the template); this iteration turns it from a probed
address string into a first-class transport seam, fixes the agent's bind
scope, and makes the Local Network permission story diagnosable instead of a
silent `EHOSTUNREACH`-then-fallback.

### Why vzNAT-direct actually solves the head-of-line problem

The Mac side already uses one TCP connection per purpose (six dial sites, one
conn per 'E'/'M'/'R' session, per 'S' splice, per parked 'D'). The stall
documented in the UDP results (bulk legs starving the `'E'` stream into
subscriber overflow) happens because **all** of those conns are channels
inside one SSH connection — one TCP flow, one congestion window, one
head-of-line. On vzNAT-direct, each conn is its own TCP flow across the
virtio NIC: independent flow control, no shared byte queue, no SSH channel
scheduler. No additional separation work is needed on our side — the
existing conn-per-purpose design was built for exactly this.

### Rejected alternatives (and what would make them win)

| Alternative | Why rejected | What would revive it |
|---|---|---|
| True AF_VSOCK now | Requires owning the `VZVirtualMachine` (Lima's vz driver process). No Lima config exposes it (verified above). | drawbridge ships as a Lima external driver / upstream Lima grows a generic vsock↔unix bridge. Then `vsock://` (or `unix://` to the bridge socket) activates with zero changes to the six call sites. |
| drawbridge-owned SSH mux (dial guest sshd directly, one SSH conn per purpose) | Six crypto'd SSH transports to escape Lima's single tunnel; real complexity (keys, known_hosts, reconnect) for a path that is strictly worse than vzNAT-direct and only marginally better than Lima's forwarder. | Local Network permission proves permanently ungrantable **and** fallback bulk throughput becomes a shipping requirement. |
| Per-purpose Lima portForwards (6 forwarded ports) | All forwarded conns still share the single SSH master connection → same head-of-line; more template surface. | Never — dominated by both current options. |
| Unix-socket-over-shared-mount | AF_UNIX endpoints don't cross the VM boundary via a shared filesystem; a socket inode is not a wire. | Never. |
| Patch/fork Lima for a vsock bridge | Violates the user constraint outright. | The constraint changing (e.g. an upstreamed contribution — see open question 3). |

---

## 2. What changes

### 2.1 `internal/transport` (new) — the seam

A small package owning the endpoint grammar and the two operations everything
else needs. **String-first API**: endpoints travel as strings, existing
`AgentAddr string` fields keep their type, and every harness test that does
`AgentAddr: ln.Addr().String()` keeps working unmodified. (A typed-endpoint
API was considered; string-first is the cheaper-to-reverse surface and keeps
the Phase 1 diff mechanical.)

Grammar:

```
endpoint   = scheme "://" address | bare
scheme     = "tcp" | "unix" | "vsock"
tcp        address = host ":" port          e.g. tcp://192.168.64.5:4777
unix       address = absolute path          e.g. unix:///Users/x/.lima/drawbridge/db.sock
vsock      address = cid ":" port           e.g. vsock://3:4777   (reserved — see below)
bare       = host ":" port                  → tcp (back-compat: flags, tests, Addr().String())
```

API (all of it):

```go
package transport

// Parse validates an endpoint string and returns its canonical form.
// Bare "host:port" canonicalizes to "tcp://host:port".
func Parse(endpoint string) (Endpoint, error)

type Endpoint struct {
    Scheme string // "tcp", "unix", "vsock"
    Addr   string // host:port | /path | cid:port
}
func (e Endpoint) String() string
func (e Endpoint) Port() uint16 // tcp/vsock port, 0 for unix — replaces the ad-hoc SplitHostPort in drawbridged/mirror

// Dial connects with the package default timeout (3s, matching today's six
// call sites). DialTimeout overrides it. Both accept endpoint strings and
// tolerate bare host:port.
func Dial(endpoint string) (net.Conn, error)
func DialTimeout(endpoint string, d time.Duration) (net.Conn, error)

// Listen binds the endpoint (guest agent, tests).
func Listen(endpoint string) (net.Listener, error)
```

Contract, stated in the package doc because future transports must obey it
(these restate existing invariants — see AGENTS.md):

- **Reliable, ordered, per-connection flow control.** The `'E'` stream must
  never silently drop or reorder; each conn must backpressure independently.
- **Half-close must propagate.** Returned conns implement
  `interface{ CloseWrite() error }` (`*net.TCPConn` and `*net.UnixConn` both
  do; assert in tests). This is the property Lima's gRPC tunnel lacks and the
  reason the SSH forwarder is pinned.
- **Dial writes nothing.** This binds the transport *layer*: `Dial` returns
  a conn on which the transport itself has sent zero bytes — no banners, no
  handshakes, ever; a transport that needs its own preamble cannot be added
  behind `Dial`. The 4-byte conn-type frame (§2.6) is *application*
  protocol, written by the dial sites after `Dial` returns — keep the two
  distinct so future transports don't confuse them. The dial-pool invariant
  is unchanged: the agent's dispatch consumes the type frame before parking,
  so a parked `'D'` conn is byte-silent until the guest writes the 4-byte
  activation header, and the watchdog treats ANY earlier byte as a dead
  conn.
- The conn-type frame (§2.6), the per-type headers, and all five stream
  kinds (`'E' 'S' 'R' 'M' 'D'`) stay byte-identical across schemes.

`vsock://` parses successfully (so it can appear in config/docs today) but
`Dial`/`Listen` return a typed `ErrUnsupported("vsock: requires a VM-owning
integration; see docs/transport.md §1")`.

### 2.2 `internal/limaaddr` — resolver returns an endpoint + diagnosis

`Transport(vmName, port) string` becomes:

```go
type Resolution struct {
    Endpoint string // canonical, e.g. "tcp://192.168.64.5:4777"
    Source   string // "vznat-direct" | "ssh-forwarder" (for logs/bench headers)
    Note     string // non-empty when falling back: classified reason + remediation
}
func Resolve(vmName string, port uint16) Resolution
```

Probe classification (the actionable-UX requirement):

| Probe outcome against the vzNAT IP | Classification | `Note` content |
|---|---|---|
| dial OK | use vznat-direct | — |
| `EHOSTUNREACH` (route + ARP exist) | **suspected macOS Local Network denial** | "host→guest vzNAT blocked — likely macOS Local Network permission. Grant it in System Settings → Privacy & Security → Local Network for your terminal app (CLI tools inherit the terminal's grant) and/or drawbridged if listed; a cached denial may need the app relaunched or a reboot. Falling back to the SSH forwarder (slower, shared tunnel)." |
| timeout / `ECONNREFUSED` | agent not (yet) listening on vzNAT | "agent not reachable on the vzNAT address — is `just agent-up` current? Falling back to the SSH forwarder." |
| no vzNAT IP found | template/VM state | "no host-reachable guest IP (vzNAT missing?) — falling back to the SSH forwarder." |

The classification above is an *input*, not a verdict: it reports what the
dial did, and host-side gates can make it read the wrong thing — macOS
27.0b4's Local Network denial presents as a silent timeout (so it files under
"agent not reachable"), and a per-binary LS-class filter drop looks like a
network fault. `drawbridge doctor` check 6 carries the discriminating
diagnosis ([doctor.md](doctor.md) §4).

`guestIP()` stays as-is (skips the outbound-only 192.168.5.0/24 usernet
subnet). Resolution stays a **startup-time** decision, plus: the mirror
client re-runs `Resolve` on `'E'`-session reconnect (already a 1 s-backoff
path) via an optional hook, so granting the permission mid-run heals to
vznat-direct without restarting drawbridged. That hook is one nullable field
(`ReResolve func() string` on `mirror.Client` and `macsync.Syncer`, wired by
drawbridged through a shared atomic string) — cheap to delete if it proves
fussy.

### 2.3 The six dial sites + one listen — mechanical swap

Every `net.DialTimeout("tcp", X.AgentAddr, 3*time.Second)` becomes
`transport.Dial(X.AgentAddr)`:

| Site | File:func |
|---|---|
| `'E'` session | `internal/mirror/mirror.go` — `Client.session` (line ~89) |
| `'S'` splice (TCP, proto 6) | `internal/mirror/mirror.go` — `Client.splice` (~254) |
| `'R'` reserve session | `internal/mirror/mirror.go` — `Client.reserveSession` (~313) |
| `'S'` UDP stream (proto 17) | `internal/mirror/udp.go` — `udpMirror.dialStream` (~96) |
| `'M'` session | `internal/macsync/sync.go` — `Syncer.session` (~171) |
| `'D'` park | `internal/macsync/sync.go` — `Syncer.parkOne` (~258) |

Guest listen: `cmd/drawbridge-agent/main_linux.go` `net.Listen("tcp",
*transport)` (~103) becomes the multi-listen described in §2.4 (which uses
`transport.Listen` per address).

Field types don't change (`Client.AgentAddr string`,
`Syncer.AgentAddr string` — now documented as "endpoint string, bare
host:port accepted as tcp"). `mirror.New` and the harness/e2e/bench
constructors are untouched except where they gain endpoint logging.
`drawbridged` and the harnesses call `transport.Parse` once at the flag/env
boundary to fail fast on typos, then pass the canonical string down. The
`agentPort` extraction in `drawbridged/main.go` and `mirror.New` switches to
`transport.Parse(...).Port()`.

(Phase 0 lands the 4-byte type frames at these same six sites first — see
§2.6; the Phase 1 swap then replaces only the dial call, not the writes.)

### 2.4 Agent bind scope — a security fix, not just hygiene

Today the agent listens on `:4777` — **all interfaces**. In the guest that
includes every Docker bridge gateway (e.g. `172.17.0.1`), so **any container
can dial the transport and speak the protocol**: park a fake `'D'` conn and
receive real guest→Mac traffic handed to it, open `'S'` splices, or feed a
bogus `'M'` listener set. The transport must be reachable from exactly two
places: the Mac via vzNAT, and the guest's own loopback (Lima's SSH forward
terminates at sshd, which dials `127.0.0.1:4777`).

Change in `cmd/drawbridge-agent/main_linux.go` (+ a small helper in
`internal/agent`):

- `-transport` default becomes `auto`: listen on `127.0.0.1:4777`
  immediately (fatal if that fails), and on `<vzNAT-ip>:4777` via a retry
  loop (find the interface with a private v4 not in `192.168.5.0/24` — same
  rule as `limaaddr.guestIP`; retry every 2 s ×30 then every 30 s, log once
  when bound, warn once if still absent after the first minute). Each bound
  listener gets its own `go a.ServeTransport(ln)` — `ServeTransport` already
  takes a listener, so no agent-package protocol changes.
- Explicit values keep working: `-transport 127.0.0.1:4777,192.168.64.5:4777`
  (comma-separated endpoint strings) and `-transport :4777` restores today's
  wildcard for debugging.
- **Belt-and-suspenders source check** (because a later `bridged` network or
  another Lima VM on the shared vmnet would land inside the vzNAT subnet):
  wrap accepted conns and drop any whose source is neither loopback nor the
  vzNAT subnet's host address (the `.1` of the interface's /24 — macOS's
  side of the NAT). Configurable escape hatch `-transport-allow CIDR[,CIDR]`.
  Rejected conns are closed immediately after accept, before any protocol
  read, and logged at most once per source per minute.
- The control (`unix`), notify, and OCI sockets are untouched.

Residual exposure after this: none beyond the Mac host itself. The Lima
forward keeps working (loopback listener, sshd source is 127.0.0.1).

### 2.5 drawbridged / e2e / bench wiring

- `cmd/drawbridged/main.go`: `-agent` now accepts any endpoint string
  (`auto` default unchanged → `limaaddr.Resolve`). Startup log states
  endpoint **and source**, and prints `Resolution.Note` as a warning when on
  the forwarder. Wires the re-resolve hook (§2.2).
- `internal/e2e/e2e_test.go` `requireE2E`: use `limaaddr.Resolve`, log
  endpoint + source (so a green run is attributable to the path it actually
  tested). New env override `DRAWBRIDGE_AGENT` (endpoint string) skips
  resolution — this is how the forwarder gets exercised on demand once
  vznat-direct becomes the resolved default.
- New e2e test `TestForwarderHalfClose`: forces `tcp://127.0.0.1:4777` and
  runs the existing upload-then-ack body (`TestUploadThroughSpliceChain`'s
  helper, factored out). Purpose: once the permission is granted and every
  default run rides vznat-direct, the forwarder path — still the fallback —
  keeps a regression guard for the half-close property that made us pin
  `LIMA_SSH_PORT_FORWARDER=true`. Skips (with reason) if 127.0.0.1:4777
  doesn't answer. **Decision (open question 4): resolved-best + this one
  forced-forwarder smoke, not a full matrix** — a full duplicate matrix
  doubles e2e/bench wall time to mostly re-test Lima's forwarder, which only
  needs the one property guarded.
- `internal/bench/bench_test.go` `requireBench`: same `Resolve` + override;
  the results header now records the endpoint source so recorded tables are
  never ambiguous about what they measured. Optional (small, do it if cheap):
  an `'E'`-liveness probe during the bulk legs — subscribe a canary session
  and assert no reconnect/overflow occurs while 256 MiB moves — turning the
  UDP-results finding ("bulk stalled `'E'` into overflow") into a pass/fail
  head-of-line assertion.
- `lima/drawbridge-dev.yaml`: **no changes.** vzNAT is already configured;
  the 4777 forward stays as the fallback. No VM rebuild required by this
  design. `justfile`: no changes (`agent-up` inherits the new `-transport
  auto` default).

### 2.6 DPI-safe conn-type frames (Phase 0 — architect-proposed amendment, 2026-07-30)

**Problem (wire-proven on this machine, guest-side tcpdump;
[notes/local-network-permission.md](notes/local-network-permission.md)
finding 3).** A DPI middlebox class — here the Little Snitch 6.5 nightly's
network extension, but the class includes corporate endpoint security
generally — holds any TCP first segment that is a **lone byte prefixing an
HTTP method** (`'D'` → DELETE, `'G'` → GET) for ~2.0–2.15 s waiting for the
rest of a request line, releasing held flows in batches, and does so even
when the user "disables" filtering (only deactivating the extension stops
it). Loopback is exempt; the vzNAT path — the resolver's default since the
permission grant — is not. A first segment of `'D'` + 3 zero bytes passes in
sub-ms: the prefix is disambiguated. Effect today: every parked `'D'` refill
stalls ~2 s → outbound first-byte p95 ≈ 2 s, burst k ≥ 16 hits the dial
pool's 3 s pop timeout (client sees RST), inbound bulk hangs. e2e absorbs
the stalls; **bench is invalid while such a middlebox is active.**

**Change.** The conn-type announcement grows from one byte to a fixed
**4-byte type frame**: `{type u8, reserved u8 ×3}`, reserved MUST be 0. The
agent's `handleTransportConn` reads the full frame (`io.ReadFull`, 4 bytes)
and closes the conn on any nonzero reserved byte **before** dispatching —
the same convention as the `'S'`/`'D'` activation header and the frozen v1
UDP activation header: the reserved bytes are the frame's only version
escape hatch, and an incompatible future revision degrades to a failed conn,
never a misdispatched stream. No version number is spent now — a hard
cutover is acceptable (agent and drawbridged always ship together via
`just agent-up`), and zeros-with-strict-validation is the
cheapest-to-reverse encoding: a protocol byte, once given meaning, can never
be taken back.

*Amendment (Phase 4.5, 2026-07-31 — [transport-auth.md](transport-auth.md)):*
the first reserved byte was spent as planned. The frame is now
`{type u8, auth u8, 0, 0}` — `auth=0` is today's wire byte-identically,
`auth=1` appends a 32-byte direction- and type-bound HMAC-SHA256 proof in
the same first `Write`, answered by the agent's own proof before any
dispatch side effect. Bytes 2–3 remain the reserved-zero escape hatch
(`auth=2` is reserved for a future channel-bound scheme). The resolver's
probe stays a bare TCP connect, unauthenticated, on purpose: answering a
probe now confers *reachability* only; trust requires the handshake.

Everything after the frame is byte-identical to today:

| Type | Mac writes at dial time (one `Write` syscall → one first segment) | Today |
|---|---|---|
| `'E'` | `45 00 00 00` (4 B), then quiet — server speaks | lone `'E'` — exposed |
| `'M'` | `4D 00 00 00` (4 B); JSON snapshot follows in a later write | lone `'M'` — exposed |
| `'R'` | `52 00 00 00` (4 B), then quiet — server speaks | lone `'R'` — exposed |
| `'D'` | `44 00 00 00` (4 B), then byte-silent until guest activation | lone `'D'` — **the proven ~2 s stall** |
| `'S'` tcp | 8 B: frame + `{6, port BE, 0}`, one write | 5 B coalesced — likely safe; framed anyway |
| `'S'` udp | 8 B: frame + `{17, port BE, 0}`, one write | 5 B coalesced — likely safe; framed anyway |

**Uniform, not `'D'`-only.** Only `'D'`/`'G'` are in the proven matrix, but
the classifier's method table is unknowable and the middlebox class includes
WebDAV/UPnP-aware boxes — nearly every type letter prefixes *some* method
(`'M'` MOVE/MKCOL, `'R'` REPORT, `'S'` SEARCH/SUBSCRIBE; `'E'` has no
standard method, but "none we know of" is not a wire guarantee). `'E'` and
`'R'` clients never write another byte; `'M'`'s JSON follows in a separate
segment. A `'D'`-only carve-out saves 3 bytes per `'S'` conn and buys a
second dispatch path plus a per-type rule to remember. Uniform is one
`ReadFull`, one rule, and every future conn type is born safe.

**Watchdog invariant preserved (AGENTS.md).** The frame is consumed inside
the agent's pre-dispatch read — the same read path that consumes today's
single type byte — so `pool.park(c)` receives a conn whose stream position
is already past the frame. The watchdog still arms on a byte-silent conn,
and every downstream reader (the `'S'` header parse, the JSON decoders, the
pool) sees a stream byte-identical to today's. This is **not** a banner
added to the reverse-stream protocol; it is the existing type announcement,
widened, consumed in the existing pre-park read.

**Guest→Mac direction: structurally safe, no change.** Every transport conn
is Mac-dialed; the guest never dials the Mac, so a Mac-side inbound
classifier only ever sees guest bytes as the *response* direction of a flow
whose client-side first segment is now always ≥ 4 bytes and disambiguated.
The guest's own first write per type: `'E'`/`'R'` — a complete JSON line per
write syscall (`json.Encoder` encodes, then writes once; first byte `{`);
`'M'` — the agent never writes; `'S'` — spliced backend bytes on an
already-classified flow; `'D'` — the 4-byte binary activation header
(first byte `0x06`/`0x11`, not an ASCII method prefix, and exactly the
length the proven matrix passes). No guest-written first byte is ever a
lone ambiguous ASCII segment.

**Deferred, named: activation-header batching.** Outbound first-byte
regressed 0.9 → 1.68 ms p50 on vzNAT (plan.md §Benchmark) because the path
pays several sequential lone-small-packet Mac↔guest exchanges at
~350–450 µs each (vs ~120 µs loopback). Batching the guest's 4-byte
activation header with the first backend payload bytes on `'D'` activation
would cut one such exchange — expected win ~0.3–0.4 ms of the 1.68. It is
**not** a DPI issue (the 4-byte binary header is proven-safe) and it touches
the gateway proxy's splice path, not the type announcement:
client-speaks-first flows batch for free, but server-speaks-first flows
(SMTP-style) need a small wait-for-payload timeout so the header is never
withheld indefinitely. Deferred — see §4, architect item 8.

Files (all Phase 0; **no BPF anywhere in this amendment — `just gen` is not
needed**):

| File | Change |
|---|---|
| `internal/agent/transport.go` | `handleTransportConn` reads `[4]byte`, rejects nonzero reserved pre-dispatch; protocol comment updated |
| `internal/agent/transport_test.go` (new; linux-tagged like `transport.go`, runs via `just test-guest`) | framed `'D'` parks byte-silent (watchdog stays armed); nonzero reserved closes before park/dispatch |
| `internal/macsync/sync.go` | `session` (`'M'`) and `parkOne` (`'D'`) write 4-byte frames |
| `internal/mirror/mirror.go` | `session` (`'E'`) and `reserveSession` (`'R'`) write 4-byte frames; `splice` builds the 8-byte write |
| `internal/mirror/udp.go` | `dialStream` builds the 8-byte write |
| `internal/macsync/sync_test.go`, `internal/mirror/udp_test.go` | fake agents read the 4-byte frame |

`internal/agent/dialpool.go` and `dialpool_test.go` are untouched — the pool
receives conns post-frame, exactly as it receives them post-type-byte today.

### 2.7 Files touched, complete list (Phase 0 files are listed in §2.6)

| File | Change |
|---|---|
| `internal/transport/transport.go` (new) | grammar, Parse/Dial/DialTimeout/Listen, contract doc |
| `internal/transport/transport_test.go` (new) | parse table; tcp+unix round-trips; CloseWrite propagation; dial-writes-nothing (server sees 0 bytes until client writes); vsock ErrUnsupported |
| `internal/limaaddr/limaaddr.go` | `Resolve` returning `Resolution`; probe classification |
| `internal/mirror/mirror.go` | 3 dials → `transport.Dial`; `Port()` for agentPort; optional `ReResolve` hook |
| `internal/mirror/udp.go` | 1 dial → `transport.Dial` |
| `internal/macsync/sync.go` | 2 dials → `transport.Dial`; optional `ReResolve` hook |
| `cmd/drawbridged/main.go` | Parse at boundary; Resolve + source/note logging; hook wiring |
| `cmd/drawbridge-agent/main_linux.go` | `-transport auto` multi-listen, retry, source allowlist, `-transport-allow` |
| `internal/agent/` (small addition, e.g. `listen_linux.go`) | vzNAT-iface discovery + allowlist wrapper (unit-testable) |
| `internal/e2e/e2e_test.go` | `Resolve` in `requireE2E`; `DRAWBRIDGE_AGENT` override; `TestForwarderHalfClose` |
| `internal/bench/bench_test.go` | `Resolve` in `requireBench`; endpoint in header; optional canary |
| `internal/harness/*_test.go` | untouched by design (bare `Addr().String()` still parses as tcp) — verify, don't edit |
| `docs/plan.md`, `docs/HANDOFF.md`, `AGENTS.md` | results + open-item + environment-note updates (Phase 4) |

Explicitly untouched: `internal/bpf/**` (and generated code), the
frame/stream protocol **after the §2.6 conn-type frame** (the frame itself
is the one protocol change, Phase 0), `internal/proxy`, `internal/udpframe`
(frozen v1), seccomp supervisor, `lima/drawbridge-dev.yaml`, `justfile`.

---

## 3. Phases

Each lands independently; the system stays green on the **resolved-best
path** throughout — since the 2026-07-30 permission grant that is
vznat-direct, with the forwarder as fallback (its half-close guard arrives
in Phase 4). Phase 0 goes first because every later phase's e2e/bench
verification rides the DPI-exposed vzNAT path.

### Phase 0 — DPI-safe conn-type frames (§2.6)

The one protocol change, kept out of Phase 1 so that phase stays a pure
refactor ("behavior identical by construction" must stay literally true).
Hard cutover: Mac side and agent rebuild together (`just build`,
`just agent-up`); no cross-version compat, by user decision — the reserved
bytes are the only escape hatch, held at zero.

Verify:
- `go test ./internal/...` — updated fake-agent tests (macsync, mirror)
  green; dial-pool tests untouched-green.
- `just build` — both arches; **`just gen` not needed** (no BPF).
- `just test-guest` — includes the new `internal/agent` dispatch test:
  framed `'D'` parks and stays byte-silent (watchdog armed); nonzero
  reserved closes before dispatch.
- `just agent-up && just e2e` — green over vznat-direct **with the DPI
  middlebox active** (Little Snitch is on this machine, normal mode).
  Pre-change, every pool refill stalls ~2 s (visible in `just agent-log`
  timing); post-change, none.
- `just bench` **with Little Snitch active** — the acceptance test: numbers
  must match the recorded clean vzNAT-direct baseline (plan.md §Benchmark)
  within noise — outbound first-byte p50 ≈ 1.7 ms (not p95 ≈ 2 s), burst
  k = 32 with zero pop timeouts, inbound bulk completes. That is half the
  point of the change: bench validity no longer requires deactivating the
  extension. (Caveat: keep LS free of pending-alert pileup and rule the
  bench binaries — finding 3's escalation mode black-holes SYNs outright,
  which no framing fixes.)
- Record in plan.md §Benchmark that post-Phase-0 vzNAT numbers are valid
  with the extension active.

### Phase 1 — transport seam (pure refactor)

`internal/transport` + tests; swap the six dials and the agent's single
listen (`transport.Listen(*transport)`, still `:4777` default this phase);
`limaaddr.Resolve` (drawbridged/e2e/bench switch to it, logging source).
Behavior identical to today by construction.

Verify:
- `go test ./internal/...` — new transport tests green; everything else untouched-green.
- `just build` (both arches produced), `just gen` **not** needed (no BPF).
- `just test-guest` — harness tests prove bare-addr compatibility.
- `just agent-up && just e2e` — green; `requireE2E` log line says `source=vznat-direct` (the resolver's default since the permission grant).
- `just bench` — all legs within noise of the recorded **vzNAT-direct** table in plan.md §Benchmark (movement here means the refactor broke something; the forwarder table is no longer the comparison point).

### Phase 2 — agent bind scope

`-transport auto` multi-listen + retry + source allowlist, as §2.4.

Verify:
- `go test ./internal/...` for the discovery/allowlist units (pure functions over interface lists / netip).
- `just test-guest` — harness unaffected (it passes explicit `127.0.0.1:0` listeners).
- `just agent-up`, then in the guest: `ss -ltnp | grep 4777` shows exactly `127.0.0.1:4777` and `<vzNAT-ip>:4777` — **no** `*:4777`.
- Negative check (containers locked out): `limactl shell drawbridge -- docker run --rm busybox nc -w 2 172.17.0.1 4777; echo $?` — fails (no listener on the bridge gateway at all now; if `-transport :4777` debugging mode is used, the allowlist still drops it post-accept).
- `just e2e` — still green (vznat-direct; the loopback listener that serves sshd's forward gets its dedicated guard in Phase 4's forced-forwarder run).

### Phase 3 — resolver diagnostics + live re-resolve

Probe classification table (§2.2), `Note` surfaced by drawbridged at startup
and by `requireE2E`/`requireBench`; `ReResolve` hook on session reconnect.

Verify:
- Unit-test the classifier with injected dial errors (`EHOSTUNREACH`, timeout, `ECONNREFUSED`).
- Permission is now granted on this machine, so the live `EHOSTUNREACH` diagnosis is covered by the classifier unit tests only (reproducing it for real means removing the subnet-exemption defaults + reboot — not worth automating). The timeout/`ECONNREFUSED` classification **is** live-testable: run the agent with an explicit `-transport 127.0.0.1:4777` (no vzNAT listener) and check drawbridged logs the "agent not reachable on the vzNAT address" note and falls back to the forwarder.
- Heal check (simulated the same way): stop the agent's vzNAT listener, start drawbridged (falls back), restart the listener — drawbridged flips to vznat-direct on the next `'E'` reconnect without restart, and logs the flip.

### Phase 4 — harness polish, bench truth, docs

`DRAWBRIDGE_AGENT` override in e2e+bench; `TestForwarderHalfClose`; bench
header endpoint stamp; optional `'E'` canary during bulk; update
`docs/plan.md` (benchmark section gains a "transport endpoint" column note),
`docs/HANDOFF.md` (rewrite the open item to "vsock reserved; vznat-direct
shipped; permission gate documented"), `AGENTS.md` environment notes
(`-transport auto`, endpoint grammar one-liner) and a sentence appended to
the parked-`'D'` invariant: the conn-type announcement is a 4-byte frame
(type + 3 zero reserved bytes, §2.6 here) consumed by agent dispatch before
parking — never shrink it back to a lone byte (DPI middleboxes stall
ambiguous method-prefix first segments).

Verify:
- `just e2e` — `TestForwarderHalfClose` green (forwarder explicitly), everything else on resolved-best.
- `DRAWBRIDGE_AGENT=tcp://127.0.0.1:4777 just e2e` — full suite green when forced onto the forwarder (proves the fallback stays complete, not just half-close).
- `just bench` — header records the source; numbers archived in plan.md **labeled with the path they rode**.

### Phase 5 — post-refactor bench truth (updated 2026-07-30)

The original premise ("after the user grants Local Network permission") is
overtaken: the grant happened pre-build (2026-07-30, subnet exemption —
procedure preserved in
[notes/local-network-permission.md](notes/local-network-permission.md) for
other machines), and a pre-refactor vzNAT-direct baseline is already
recorded in **plan.md §Benchmark, "vzNAT-direct (pre-refactor baseline)"**.
The old "expected movement" hypotheses are superseded by measurements:
throughput moved ~6× both directions (and inbound bulk, which the gRPC
forwarder killed, just works); burst flattened (k=32: 4.9 → 3.66 ms,
sub-linear in k — the head-of-line fix, confirmed); inbound first-byte
0.53 → 0.35 ms; UDP roughly halved. One hypothesis was **refuted**:
outbound first-byte *regressed* 0.9 → 1.68 ms p50, because the outbound path
pays several sequential lone-small-packet Mac↔guest exchanges and
vzNAT/virtio delivers isolated small packets at ~350–450 µs vs ~120 µs via
the loopback-hopping forwarder. The named lever for that is
activation-header batching (§2.6, deferred — §4 item 8). If latency ever
needs to go below the vzNAT small-packet floor, the reserved vsock path is
the someday answer.

Phase 5 is therefore: after Phases 0–4, `just agent-up && just e2e` (expect
`source=vznat-direct` everywhere) and `just bench` — run **with the DPI
middlebox active**, which Phase 0 made valid — and compare against the
recorded baseline: within noise means the seam refactor and the type frames
are latency-neutral; the `'E'` canary (Phase 4) must show zero
overflows/reconnects during bulk. Record the post-refactor table in plan.md
next to the baseline, labeled with the path and middlebox state it rode.

---

## 4. Resolved questions (user-decided 2026-07-30)

1. **Local Network permission will be granted** during this work (user
   performs the grant before/alongside the build; Phase 5 verifies and
   records the vznat-direct bench table).
2. **Bind scope: strict.** Containers deliberately lose the ability to reach
   `:4777`; loopback + vzNAT listeners with the `.1`-source allowlist;
   `-transport` / `-transport-allow` remain the escape hatches.
3. **Upstream Lima vsock bridge: noted, not pursued now** — recorded in
   HANDOFF as the path that would make real vsock reachable if drawbridge
   ever ships as a Lima networking driver.
4. **Test matrix: resolved-best + forced-forwarder half-close guard** +
   `DRAWBRIDGE_AGENT` manual override; full duplicate matrix rejected
   (~2× wall time to mostly re-test Lima's forwarder).
5. **Guest image bump (systemd ≥ 256 for vsock-SSH fallback): deferred** to
   the next forced VM rebuild, opportunistically.

### Architect-proposed (2026-07-30 — user-approved same day)

Items 1–5 above are user-locked and unchanged. The following were proposed
with the §2.6 amendment and **approved by the user 2026-07-30** (uniform
framing; Phase 0 placement; batching deferred):

6. **Uniform 4-byte conn-type frame for all five types, reserved bytes
   strict-zero (§2.6).** Rejected alternatives: *`'D'`-only padding*
   (minimal diff — two sites — but leaves `'E'`/`'M'`/`'R'` exposed to
   unknown method tables in the same middlebox class, and splits dispatch
   into two read paths); *a version number in the reserved bytes now*
   (spends protocol meaning with no consumer; strict-zero +
   close-on-nonzero already **is** the escape hatch — the same pattern as
   the frozen UDP activation header — and is the cheaper-to-reverse
   encoding).
7. **Sequencing: Phase 0, ahead of the Phase 1 seam** (not folded in, not a
   standalone pre-refactor patch). Keeps Phase 1's "behavior identical by
   construction" literally true, and every later phase's bench/e2e
   verification needs DPI-valid runs on the now-default vzNAT path. No
   baseline-purity reason to delay: the pre-refactor vzNAT baseline is
   already recorded.
8. **Activation-header batching: deferred, named open question (§2.6).**
   Expected win ~0.3–0.4 ms of the 1.68 ms outbound first-byte p50; touches
   the gateway proxy's splice path and needs a server-speaks-first
   wait-for-payload timeout — out of scope for a framing amendment.

Ranked open questions for the user (by how much the answer changes the
plan): (1) approve uniform framing (item 6) — a "`'D'`-only" answer
reshapes the §2.6 frame table, the dispatch, and four of six dial sites;
(2) approve Phase 0 placement (item 7) — folding into Phase 1 merges two
verify gates into one larger diff; (3) batching now vs deferred (item 8) —
"now" adds a gateway-proxy work item and a new outbound latency target to
Phase 5, "deferred" changes nothing today.
