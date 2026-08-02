# drawbridge — repo scaffold + Phase 1 (Kernel Loopback Gateway)

> **Status: Phases 1 and 2 COMPLETE (2026-07-30).** Phase 1's five assertions pass;
> Phase 2 (TCP) is verified end to end — a guest listener is reachable on Mac
> localhost. See “Phase 1 results” and “Phase 2 results” below, and
> [HANDOFF.md](HANDOFF.md) for what Phase 2 left open.

## Context

`--network host` on macOS container runtimes shares the *Linux VM's* network namespace, not the Mac's — macOS/XNU has no network namespaces, so true parity is impossible. The goal: **drawbridge**, an open-source, standalone daemon delivering OrbStack/Docker-Desktop-style **L4 host networking semantics** (bidirectional loopback merge: container binds appear on Mac localhost; container connects to `127.0.0.1` reach native Mac services) that Lima/Colima/Podman-machine can adopt as a networking driver. No system extensions or restricted entitlements needed — pure user-space (BSD sockets, Virtualization.framework vsock) plus eBPF inside the guest.

Binaries: `drawbridge` (CLI), `drawbridged` (Mac daemon), `drawbridge-agent` (guest agent).

Full roadmap (this plan executes only the scaffold + Phase 1):
1. **Phase 1 — Kernel loopback gateway** (pure Linux VM; no macOS/vsock deps) ← this plan
2. Phase 2 — Guest listener tracking (`fexit/inet_listen`, `inet_unhash` TCP_LISTEN-filtered, `udp_{v4,v6}_get_port`, `udp_lib_unhash`) + vsock events + Mac mirror listeners + inbound byte proxying (MVP: `docker run --net host nginx` → Mac `localhost:80`)
3. Phase 3 — Mac listener sync (`sysctl net.inet.tcp.pcblist_n` poll 50–100ms → `mac_ports` map) + outbound dial to Mac loopback
4. Phase 4 — Synchronous binds via seccomp-unotify OCI hook (reserve-before-ACK on Mac, deny path answers `-EADDRINUSE`, timeout/failure answers `SECCOMP_USER_NOTIF_FLAG_CONTINUE`)

## Prerequisites (dev Mac: arm64, macOS 27)

- Tools are pinned in `mise.toml` (go, lima, just — see that file for current versions; go.mod's `go 1.25.0` is the deliberate downstream *minimum*, per cilium/ebpf, not the dev toolchain): `mise install && mise reshim`. (Docker CLI + OrbStack already present; unused in Phase 1, useful later as reference behavior.)
- clang/LLVM for BPF compilation lives **inside the Lima guest**, not on the Mac. `make gen` runs bpf2go in the guest; generated Go files are committed so Mac-side `go build` never needs clang.

## Repo scaffold

Location: `/Users/nxc/ghq/github.com/archcorsair/drawbridge` (already created). Module path placeholder: `github.com/archcorsair/drawbridge` (trivially changeable). License: Apache-2.0 (compatible with reusing gvisor-tap-vsock later). Go floor: `go 1.25.0` in go.mod, **proven by CI 2026-07-31** — the {1.25.x, 1.26.x} × {macOS, ubuntu-24.04} matrix went 4/4 green on the first Phase 1 run (ergonomics.md §"Phase 1 results"), so the floor stands.

```
cmd/drawbridge/        # CLI (minimal stubs: version, dev helpers)
cmd/drawbridged/       # Mac daemon — stub only in Phase 1
cmd/drawbridge-agent/  # Guest agent: loads/attaches BPF, runs gateway proxy, harness subcommands
internal/bpf/          # loopback_gw.c + bpf2go-generated Go (committed)
internal/proxy/        # gateway proxy: TCP splice + UDP per-flow relay
internal/harness/      # dummy targets + Phase 1 assertions (go test, runs in guest)
docs/                  # this plan + future design notes
lima/drawbridge-dev.yaml  # Ubuntu LTS arm64 (BTF kernel, cgroup v2), clang/llvm/libbpf, rw mount of repo
Makefile               # vm-up, gen, build, test-phase1
README.md              # architecture + roadmap
LICENSE                # Apache-2.0
```

## Phase 1 implementation (all inside the Lima VM)

### BPF programs (`internal/bpf/loopback_gw.c`, cilium/ebpf, CO-RE)

- **Maps** — `port_key { u8 proto; u8 pad0; u8 addr[16]; u16 port; u8 pad1[2]; }` with **explicit padding** (byte-wise hash lookups; compiler padding holes cause nondeterministic misses). IPv4 stored v4-mapped. Maps: `guest_ports` (hash) and `mac_ports` (hash) — **only these two**; see the same-port scheme below.
- **Same-port gateway scheme** (implementation-time simplification): the rewrite swaps ONLY the IP, `127.0.0.1:P → 127.0.0.2:P` (v6: `::1 → fd77::2`), and the agent runs **one proxy listener per Mac-owned port** on the gateway address. The proxy learns the original destination from its own local port; `getpeername`/`recvmsg` un-rewrites become stateless IP transforms; multi-destination unconnected UDP demuxes naturally by reply port. This eliminated the originally planned `origdst_sk` / `origdst_tuple` / `udp_flows` stash maps entirely.
- **`cgroup/connect4` + `connect6`** — decision order is load-bearing: (1) dst not exactly `127.0.0.1`/`::1` (includes the gateway itself) → pass; (2) port served by `guest_ports` (exact bind addr, v4-any, v6-any) → pass (native VM loopback; also keeps Phase 2's inbound splice loop-free); (3) served by `mac_ports` → swap IP to gateway, keep port; (4) neither → pass (guest kernel yields fast native `ECONNREFUSED`).
- **`cgroup/sendmsg4/6`, `recvmsg4/6`** — same per-datagram decision for unconnected UDP (`sendto` never hits connect hooks); recvmsg maps reply source `gateway:P → 127.0.0.1:P` statelessly.
- **`cgroup/getpeername4/6`** — stateless `gateway → loopback` un-rewrite so apps see `127.0.0.1:P`.
- Attach to the guest root cgroup (`/sys/fs/cgroup`) via cilium/ebpf links.

### Gateway proxy (`internal/proxy`, part of `drawbridge-agent`)

- TCP: listen `127.0.0.2:10450`; on accept, resolve original dst from `origdst_tuple` by peer tuple; dial the dummy target; bidirectional copy.
- UDP: allocate a **distinct gateway-side reply port per flow**, record it in `udp_flows`, relay datagrams; replies demux naturally by reply port.
- In Phase 1 "the Mac side" is simulated: proxy dials dummy targets on `127.0.0.2` high ports; `mac_ports` / `guest_ports` are populated by the harness (real populators are Phases 2–3).

### Test harness (`internal/harness`, `make test-phase1` → `limactl shell` → `go test`)

Acceptance assertions:
1. Unmapped loopback port → native `ECONNREFUSED`, sub-ms, proxy untouched.
2. `mac_ports`-mapped TCP port → payload round-trip through proxy; `getpeername()` reports the original `127.0.0.1:P`.
3. `guest_ports`-owned port → served natively; proxy never sees the connection.
4. Unconnected UDP echo round-trip, **including one socket talking to two mapped ports concurrently** (demux via per-flow reply ports).
5. Report connect-path latency overhead (the empirical number this phase exists to produce).

## Verification

```
mise install && mise reshim
just vm-up        # boots lima/drawbridge-dev.yaml, installs guest toolchain
just gen          # bpf2go inside guest, commits generated Go
just test-phase1  # runs the 5 assertions inside the guest, prints latency numbers
```

Success = all five assertions green on Ubuntu LTS arm64 under Lima. No Mac-side networking is touched in this phase.

## Phase 1 results (2026-07-30, Ubuntu 24.04 arm64 / kernel 6.8, Lima vz)

All five assertions green on the first full run:

1. Unmapped port → native `ECONNREFUSED` in **60µs**, proxy untouched.
2. Mac-mapped TCP port → proxied round-trip OK; raw `getpeername()` reports `127.0.0.1:P` (gateway never leaks).
3. Port owned by both guest and Mac → served natively by the guest listener; proxy saw zero connections.
4. One unconnected UDP socket → two Mac-mapped ports: correct payload demux, reply sources un-rewritten to `127.0.0.1`.
5. Connect latency p50/p95 — native `23.8µs/42.7µs`, proxied `15.1µs/49.6µs`, refused `6.1µs/27.0µs`.

Reading #5 honestly: proxied-vs-native connect deltas are inside measurement noise
(connect() completes on the listener backlog's SYN-ACK in both paths — the proxy's
backend dial happens after accept). Conclusion: the gateway adds **no measurable
connect-time overhead** at this scale. A first-byte-RTT benchmark is the right
follow-up and belongs in the Phase 2 harness.

Implementation notes for future phases:
- BPF C lives in `internal/bpf/c/` (a `.c` file in a Go package dir breaks non-cgo builds).
- `clang -target bpf` needs explicit `-I/usr/include/<triple>-linux-gnu` on Ubuntu multiarch.
- cilium/ebpf v0.22 requires Go ≥ 1.25 (both sides run current stable 1.26.5, pinned in mise.toml and the Lima provision script; go.mod keeps the 1.25.0 minimum).

## Phase 2 results (2026-07-30)

Built: `internal/bpf/c/tracker.c` (fexit `inet_csk_listen_start` / `udp_{v4,v6}_get_port`, fentry `inet_csk_listen_stop` / `udp_lib_unhash`, refcounted `guest_ports`, ringbuf events), agent `TrackerHub` + `/proc/net` seed + `'E'`/`'S'` transport, `internal/mirror` (Mac mirror listeners + splice), real `drawbridged`. Tests: `TestPhase2Tracker` in-guest, `internal/e2e` from the Mac (`just e2e`) — guest `:47999` served on Mac `localhost:47999`.

Two findings that changed the design:

1. **Teardown keys cannot be rebuilt from the socket.** A socket bound with port 0 (ephemeral) never gets `SOCK_BINDPORT_LOCK`, so `tcp_set_state(TCP_CLOSE)` calls `inet_put_port()` and zeroes `skc_num` *before* `inet_csk_listen_stop` runs — the teardown hook sees port 0 and cannot identify what to remove. Explicit binds keep their port, which is exactly why a first probe with a hardcoded port looked healthy while every Go/`:0` listener leaked a `guest_ports` entry (and stale entries then broke Phase 1's mac-port path, since guest ownership wins arbitration). Fix: `sk_keys` remembers the key at bind time, keyed by socket pointer.
2. **macOS reserves ports <1024 for root** — verified empirically (80/22/443 `EACCES`, 1024 OK), and macOS 27 has no `net.inet.ip.portrange.reservedhigh` sysctl to relax it. This **corrects an earlier assumption recorded in this plan's framing** that low ports were unprivileged on macOS. Consequence: the `--net host nginx` → Mac `:80` demo requires a privileged `drawbridged`; unprivileged runs log an actionable message and skip the port.

Also: BPF refcount atomics (`__sync_sub_and_fetch`) require `-mcpu=v3`.

## Phase 3 results (2026-07-30)

Built: `internal/macsync` — darwin `pcblist_n` poller plus a portable syncer that diffs the Mac's listener set every 75 ms and streams it over a new `'M'` transport frame (same JSON shape as `'E'`, direction reversed), and keeps parked `'D'` reverse-stream conns that gateway proxies activate with the existing 4-byte header. Agent side: `proxy.NewTCP` backend seam is now a `DialFunc`; `AddMacPort` with an empty backend pops from the parked pool; `'M'` sessions own their `mac_ports` entries and drop them on disconnect (Mac gone ⇒ fast native `ECONNREFUSED`, not connect-then-hang). `drawbridged` runs mirror + syncer, excluding its own mirrors and the agent port from the sync (loop prevention). Verified: unit suites on the Mac (`-race`), `TestPhase3MacSync` in-guest, and e2e — a Mac loopback HTTP server served **inside** the guest at the same `127.0.0.1:port`.

Findings:

1. **`struct xinpcb_n` is packed.** No alignment padding after `inp_lport`: `inp_ppcb` at 20, `inp_vflag` at 44, `inp_dependladdr` at 64 (v4 in its last 4 bytes). The public SDK ships neither the `_n` structs nor the `XSO_*` kinds (xnu-private; netstat carries copies), so the offsets are documented in `pcblist_darwin.go` and pinned by tests against live listeners.
2. **An expired read deadline masks a queued FIN.** Go's poll layer fails an expired-deadline read *before* issuing the syscall, so the pool's deadline-poke handoff could return a conn whose peer had already closed. `probeLive` (a 200 µs future-deadline read, pre-header so it can't steal backend bytes) surfaces the queued FIN as instant EOF.
3. **v4-only outbound scoping.** Mac binds on `127.0.0.1`/`0.0.0.0` sync as-is; dual-stack `::` syncs as `0.0.0.0` (the Mac-side backend dial is `127.0.0.1`, which dual-stack listeners accept); `::1`-only binds are skipped. Rationale: a v6 `mac_ports` key would steer guest `::1` connects into `fd77::2`, where no gateway listener exists yet — worse than the native refusal they get today.
4. **Park-ahead pool over a mux protocol.** Reverse streams need Mac→guest data channels the guest can open; a yamux-style mux would work but adds framing to every byte. Parked conns keep the transport's one-conn-per-purpose model, cost nothing on the wire, and stay transport-agnostic for the vsock swap. Trade-off: connect bursts beyond `PoolSize` (4) serialize on the replenish RTT — sizing is an open item for the benchmark.

## Phase 4 results (2026-07-30)

Built: `internal/seccomp` — pure-Go user-notification machinery (bind-only filter with `TSYNC|TSYNC_ESRCH|NEW_LISTENER`, `NOTIF_RECV`/`SEND`/`ID_VALID` ioctls sized from `GET_NOTIF_SIZES`, sockaddr read from `/proc/pid/mem`, socket classification via `pidfd_getfd`) plus `RunBindProbe`, the stand-in for a container process under the OCI hook. Agent side: a unix socket receives notify fds by `SCM_RIGHTS` and supervises them; each blocked TCP bind to a mirrorable address asks the Mac to reserve the port over a new `'R'` frame (500 ms deadline) and answers `-EADDRINUSE` or CONTINUE. Mac side: `handleReserve` **binds the real mirror listener before acking** — no TOCTOU window — as a *pending* entry that the tracker's add event adopts, or that `ReserveTTL` (10 s) releases if nothing binds.

Every uncertain path answers CONTINUE (no `'R'` session, RPC timeout, unreadable sockaddr, non-stream socket, port 0, non-mirrorable scope), so the failure mode is Phase 2/3 async behavior, never a broken bind. Verified: `TestPhase4SyncBind` in-guest (deny, reserve-and-adopt, native-conflict passthrough, TTL release, degradation with no Mac) and `TestGuestBindGetsSynchronousEADDRINUSE` from the Mac — a guest bind onto a real Mac-held port fails synchronously with Linux `EADDRINUSE`. **Docker Desktop does not offer these semantics** — this is the differentiator.

Findings:

1. **Go 1.24+ opens TCP listeners as Multipath TCP**, so `SO_PROTOCOL` on a target socket reports `IPPROTO_MPTCP` (262), not `IPPROTO_TCP` (6). An equality check on protocol silently CONTINUEs every ordinary Go server — the arbitration looks wired up and does nothing. Classify on `SO_TYPE == SOCK_STREAM` plus an INET domain instead (covers TCP and MPTCP, still excludes UDP). Regression: `TestClassifiesGoListenerAsStream`.
2. **One `net.Listen` produces several bind notifications.** Go probes IPv6 capability first (`::1:0`, `::ffff:127.0.0.1:0`), then binds for real, and a v4 request can arrive v6-mapped — so a supervisor must expect repeats per logical bind, `Unmap()` before matching, and never block between receiving a notification and answering it (an early version deadlocked itself exactly there).
3. **Hand the notify fd over before installing the filter.** Go's `net` package makes its own syscalls on first use; if the filter is installed first, the dial that delivers the fd can itself be trapped by a supervisor that does not exist yet.
4. **`errno` crosses the VM boundary as a number, not a Go constant** — the Mac-side test must compare against Linux's `EADDRINUSE` (98), not darwin's (48).

## Benchmark (2026-07-30)

`just bench` — `internal/bench` orchestrates from the Mac; the guest side runs through the agent binary's `benchclient`/`benchserve` subcommands (`internal/benchtool`). Numbers over the SSH-forwarded transport (see finding 1), 300-iteration RTT sets, 256 MiB bulk transfers:

**Every table below is qualified by the transport endpoint it rode** — the two paths differ by ~6× on throughput, so an unlabeled number is meaningless. `requireBench` logs `agent transport: <endpoint> source=<vznat-direct|ssh-forwarder|override:…>` as the first line of the run; copy that source into any table recorded here, together with the DPI-middlebox state (Little Snitch active or deactivated). Force a path with `DRAWBRIDGE_AGENT=tcp://127.0.0.1:4777 just bench`.

| path | connect p50 | first-byte RTT p50 / p95 | throughput (each way) |
|---|---|---|---|
| guest→Mac outbound (Phase 3) | 37 µs | 0.9 ms / 1.9 ms | ~450–490 MB/s |
| guest loopback native (baseline) | 21 µs | 44 µs / 61 µs | — |
| Mac→guest inbound (Phase 2) | 63 µs | 0.53 ms / 0.71 ms | ~410–475 MB/s |
| Mac loopback native (baseline) | 96 µs | 0.12 ms / 0.20 ms | — |

Outbound burst (k simultaneous connect+echo waves, 5 rounds): RTT p50 ≈ 1.2 / 2.5 / 3.0 / 4.9 ms at k = 4 / 8 / 16 / 32 — graceful, no cliffs, no timeouts. Pool pop stays ≤ ~150 µs p50 throughout, so the parked-conn pool is **not** the burst limiter at ≥4 — the shared forwarded transport is. `DefaultPoolSize` = 8 for tail headroom.

### vzNAT-direct (2026-07-30, pre-refactor baseline)

Same code, same bench, transport resolved to `192.168.64.2:4777` (source=vznat-direct). Taken after clearing the machine-level DPI stall documented in [notes/local-network-permission.md](notes/local-network-permission.md) finding 3 — numbers with that filter active are invalid.

| path | connect p50 | first-byte RTT p50 / p95 | throughput (each way) |
|---|---|---|---|
| guest→Mac outbound (Phase 3) | 46 µs | 1.68 ms / 1.89 ms | 2804 / 3280 MB/s |
| Mac→guest inbound (Phase 2) | 82 µs | 0.35 ms / 0.46 ms | 3132 / 3386 MB/s |

Outbound burst RTT p50 ≈ 1.85 / 2.25 / 2.73 / 3.66 ms at k = 4 / 8 / 16 / 32 (max 5.9 ms, no failures). UDP RTT p50/p95: outbound 129/154 µs (forwarder: 237/310), inbound 157/273 µs (forwarder: 312/582).

**Post-refactor (transport.md Phases 0–4 complete, 2026-07-30, LS extension deactivated — the Phase 5 record):** `source=vznat-direct` stamped by `requireBench`; latency-neutral against the baseline above. Outbound first-byte connect p50 37 µs, rtt p50/p95 **1.67/1.82 ms** (baseline 1.68/1.89); outbound bulk 2615/3488 MB/s; burst k=4/8/16/32 rtt p50 2.01/2.43/2.67/3.93 ms, zero failures; inbound first-byte 0.31/0.47 ms; inbound bulk 3316/3331 MB/s; UDP outbound 128/150 µs, inbound 152/369 µs, zero drops; `'E'` canary alive across outbound bulk. e2e 9/9 including `TestForwarderHalfClose` (forced forwarder). The seam, type frames, bind scoping, and resolver diagnostics cost nothing measurable.

Post-Phase 0 (4-byte type frames, transport.md §2.6, 2026-07-30): outbound, burst, and UDP legs re-validated **with the DPI middlebox active** — outbound first-byte p50/p95 1.77/1.94 ms, burst k=32 p50 3.46 ms with zero pop timeouts, bulk 2.7 GB/s — so bench validity no longer requires deactivating the extension, with one exception: the **inbound bulk leg wedges with Little Snitch active on any code version** — diagnosed 2026-07-30: the LS extension breaks TCP half-close on non-loopback flows; inbound bytes arriving after the Mac process's `shutdown(SHUT_WR)` are kernel-ACKed but never delivered to the process ([notes/local-network-permission.md](notes/local-network-permission.md) finding 4). The wire is clean — tcpdump on both `bridge100` and `lima0` shows all 256 MiB, the sink ack, and both FINs completing in 0.12 s; only app-side delivery dies. Repros with a 1-byte upload and with plain direct TCP to the guest (zero drawbridge components); prior outbound traffic is irrelevant (the earlier correlation was bench ordering). Passes on the loopback-exempt forwarder and with the extension deactivated. In the obdev bug-report material; deliberately not worked around in code (would take in-band EOF framing on the splice streams to dodge a third-party bug that equally breaks direct connections). Repro: `DRAWBRIDGE_WEDGE=1 go test -run TestWedgeRepro ./internal/bench/`.

Against the §Phase 5 hypotheses (transport.md): **throughput** moved ~6× (450–490 → 2800–3400 MB/s, both directions — and inbound bulk, which the gRPC forwarder killed outright, just works); **burst flattened** (k=32: 4.9 → 3.66 ms, and k-scaling is now sub-linear — head-of-line removal confirmed); **inbound first-byte** improved 0.53 → 0.35 ms; **UDP halved**. But **outbound first-byte regressed 0.9 → 1.68 ms p50**, refuting the "roughly halves" hypothesis: the outbound path pays several sequential lone-small-packet Mac↔guest exchanges (activation header, then the echo), and vzNAT/virtio delivers isolated small packets with noticeably higher per-packet latency than the loopback-hopping SSH forwarder (a raw 1-byte echo over vzNAT runs ~350–450 µs vs ~120 µs loopback). Batching the activation header with first payload bytes is the obvious lever if outbound first-byte matters later.

Findings:

1. **Lima's default (gRPC) port forward drops TCP half-close** — a FIN through the tunnel kills the whole stream, breaking any upload-then-ack flow crossing `'S'`/`'D'`. Probe-verified: identical raw-stream upload acks in-guest and dies across the forward. Shipped mitigations: `just vm-up` pins `LIMA_SSH_PORT_FORWARDER=true` (SSH channels propagate EOF correctly), and the VM gains a `vzNAT` network so the transport can dial the guest IP directly — `internal/limaaddr` resolves it (used by `drawbridged -agent auto`, e2e, bench) with loopback fallback. Direct vzNAT was blocked by macOS **Local Network permission** (symptom: `EHOSTUNREACH` with valid route and ARP) until the subnet exemption was applied 2026-07-30; the resolver now picks it up automatically — see the vzNAT-direct table above and [notes/local-network-permission.md](notes/local-network-permission.md) for the full three-layer diagnosis. Regression guard: `TestUploadThroughSpliceChain` + the bench bulk legs.
2. **Outbound `connect()` is near-native (~37 µs)** — the gateway proxy accepts locally before any Mac round trip; the real per-connection cost is first-byte (~0.85 ms over the forwarder). Postgres-style long-lived connections pay it once.

## OCI integration results (2026-07-30)

Design and rationale in [oci-hook.md](oci-hook.md); built as planned, Docker-first
via the `drawbridge-runc` wrapper runtime (registered as `default-runtime`), agent
speaking the runtime-spec seccomp-agent protocol on `/run/drawbridge-oci.sock`.
Guest engine: rootful docker.io 29.1.3 / runc 1.3.4 (listenerPath needs runc ≥
1.1.0), provisioned by `scripts/provision-docker.sh` (`just vm-docker` / `oci-up`
— idempotent, no VM rebuild, offline `docker import` test image). No BPF changes.
Verified: the chain with a hand-written listenerPath profile through **stock**
runc (zero drawbridge binaries involved); `TestPhase4OCIProtocol` in-guest;
container e2e from the Mac — `TestContainerBindGetsSynchronousEADDRINUSE`
(errno 98 from a real `--network host` container), `TestHostNetContainerListenerMirrored`,
`TestBridgedContainerNotArbitrated`; agent-down degradation (host-net container
starts with stock behavior).

Findings:

1. **`NOTIF_RECV` on a dead filter blocks forever.** When the filter's last task
   exits the kernel raises EPOLLHUP on the notify fd — but a pending RECV ioctl
   never returns and never errors (6.8; the widely-assumed ENOENT does not
   happen, pinned by `TestNotifyFilterExitSemantics`). Supervision is therefore
   poll-first (`seccomp.PollNotif`): HUP-without-IN is the only termination
   signal; recv-looping would leak an OS thread and an fd per exited container.
   Relatedly, the old loop wrapped the recv errno with `%v`, so its
   `errors.Is(ENOENT)` branch was unreachable and any recv error silently ended
   supervision.
2. **runc's parent delivers the fd before the entrypoint runs**, so the Phase 4
   "hand the fd over before installing the filter" ordering concern dissolves
   under the runtime: the agent is always supervising before the workload's
   first syscall. A spec send failure is a container-start failure — hence the
   wrapper probes the agent socket and, on any doubt (agent down, bridged
   container, opt-out annotation, profile that doesn't provably allow bind),
   execs runc with the spec untouched.
3. **The tracker was not netns-scoped.** fexit hooks on
   `inet_csk_listen_start` are kernel-global, so a *bridged* container's
   listener produced tracker events and drawbridged attempted a Mac mirror of
   a listener that guest-loopback splicing can never reach. Bind *arbitration*
   was already scoped (agent-side `SameNetNS` backstop plus the wrapper's
   namespace check); the tracker fix followed immediately — see "Tracker netns
   scoping" below.
4. Guest apt egress to `ports.ubuntu.com` proved unreliable from the VM
   (large debs stall; the Mac fetches the same URLs instantly). The provision
   script installs docker.io normally, but when it fails, fetch the debs on the
   Mac (`apt-get install --print-uris`) into the rw mount and install from
   local paths.

## Tracker netns scoping (2026-07-30, post-OCI)

The OCI integration put docker in the guest, and the tracker's fexit/fentry hooks
are kernel-global — they also fired for listeners inside bridged containers'
private netns. A bridged `0.0.0.0:P` bind produced a `guest_ports` entry and a
tracker event, so `drawbridged` tried to mirror `127.0.0.1:P` on the Mac
(`EADDRINUSE` when the Mac held P; a successful mirror would splice to guest
loopback where nothing listens). The seccomp path was already netns-scoped
(`seccomp.SameNetNS`); the tracker path was not.

Fix: `tracker.c` compares the socket's `sk->__sk_common.skc_net.net->ns.inum`
(minimal CO-RE stubs for `possible_net_t`/`net`/`ns_common`) against a
`volatile const __u32 host_netns_inum`, which `LoadTracker` sets from
`stat("/proc/self/ns/net").Ino` via `spec.Variables` before load — the scoping
can't be forgotten by a caller; 0 disables the filter. **Both `track_add` and
`track_del` filter**: an unfiltered `track_del` would miss `sk_keys` (the add
was filtered) and fall back to `fill_key`, letting a foreign `0.0.0.0:P` close
decrement the refcount of the host's identically-keyed entry.

Verified: `TestPhase2Tracker/ForeignNetns` (a `unshare(CLONE_NEWNET)` listener
stays untracked over a hold window, and a same-key foreign close leaves the host
entry intact), full `just test-guest` + `just e2e`, and live docker: a bridged
`bindtest` holding `0.0.0.0:8080` produced no `guest_ports` entry while a
`--network host` one on `:8081` still did.

Finding: Go's `net.Listen("tcp", "0.0.0.0:p")` treats the v4 wildcard as "any"
and binds a dual-stack `[::]` socket — the tracker keys it as `::`, not
`0.0.0.0`. Tests that assert on the v4-wildcard key must listen on `tcp4`.

## UDP results (2026-07-30)

Design in [udp.md](udp.md); built as planned (U1–U4; U5 auto-discovery stays
deferred). Both directions ride the existing `'S'`/`'D'` kinds with proto byte
17 and the frozen 21-byte v1 frame (`internal/udpframe`); the stateful relay
end is one shared implementation (`udpframe.RelayStream`) dialed differently
per side. Guest listeners mirror to Mac localhost (ephemeral autobind range
32768–60999 excluded); Mac services are offered by explicit `drawbridged
-udp PORT,PORT` only. No BPF changes.

Numbers (64 B datagrams, 300 iters, SSH-forwarded transport, zero drops in
every leg):

| path | rtt p50 / p95 | native baseline p50 |
|---|---|---|
| guest→Mac udp (outbound) | 237 µs / 310 µs | 3 µs (guest loopback) |
| Mac→guest udp (inbound) | 312 µs / 582 µs | 21 µs (Mac loopback) |

Socket-per-query bursts (k fresh sockets × 5 waves, outbound): p50 ≈
0.6–1.4 ms across k = 4/8/16/32, zero drops — the muxed per-port stream makes
a new flow cost one frame, so DNS-style socket churn never touches the parked
pool. A 60000-byte guest→Mac datagram round-trips intact (FNV hash ack).
UDP RTTs beat TCP first-byte (~0.9–1.1 ms) because after the one-time stream
activation no per-connection setup crosses the transport at all.

Findings:

1. **macOS caps a UDP send at the socket's send buffer** (seeded from
   `net.inet.udp.maxdgram`, default 9216) — this bites the *delivery* hop on
   the Mac, not just Mac clients: the syncer's relay socket and the mirror's
   reply socket both need `SetWriteBuffer(65507)` or guest datagrams over
   ~9 KiB die `EMSGSIZE` mid-path. Mac *clients* sending >9216 to a mirror
   still need the sysctl raised — a platform limit drawbridge inherits
   honestly (wire tests use 8 KiB inbound).
2. **The tracker event stream was ~97% UDP client-socket noise.**
   `udp_get_port` fires for every kernel autobind, so guest DNS churn alone
   produced 324 of 334 events in one bench run; combined with `'E'` sharing
   the forwarded transport with 512 MiB of bulk legs, a subscriber buffer
   overflowed and silently dropped a real TCP add (bench's sink mirror went
   missing — reproducibly, but only under bench concurrency). Three-part fix:
   the hub filters autobind-range UDP events at the source (pure port
   predicate, add/del symmetric); a subscriber overflow now closes the
   subscription so the session reconnects and the snapshot heals; and
   `Subscribe` enqueues its snapshot under the hub lock so an add can never
   outrun its own snapshot and be reconciled away.
3. The pre-existing in-guest-backend UDP relay leaked one socket per client
   forever; all flow tables (guest relay, agent inbound, Mac outbound) now
   share one expiry policy — 60 s idle, 10 s sweep, 4096-flow cap.

## Privileged daemon results (2026-07-30)

Design and rationale in [privileged-daemon.md](privileged-daemon.md); all three
phases shipped same day — phases 1–2 (leases discovery, install machinery) were
user-acceptance-tested against an installed LaunchDaemon, phase 3 added the
root-gated e2e legs. The full MVP demo passed on this machine as an installed
LaunchDaemon:

- `sudo drawbridge install` → `status`: `state=running`, transport
  `tcp://192.168.64.2:4777 (source=vznat-leases)` — root-path endpoint
  discovery via `/var/db/dhcpd_leases` worked with no access to the user's
  `$LIMA_HOME`, first try.
- **Inbound <1024**: `docker run --network host nginx` in the guest →
  `curl http://localhost:80` on the Mac served the nginx welcome page. The
  first sub-1024 mirror in the project's history.
- **Reverse <1024**: Mac-native `python3 -m http.server 80` reachable from
  the guest at `127.0.0.1:80`.
- **Synchronous EADDRINUSE on a privileged port**: with the Mac holding
  `:80`, a host-network busybox `nc -l -p 80` failed instantly with
  `nc: bind: Address already in use`.
- **Root loopback guard**: `drawbridged -mirror-ip 0.0.0.0` under root is
  fatal with a remediation message (root must never publish guest listeners
  off-loopback).
- `uninstall` removed plist/binary/newsyslog entry, kept logs, and `status`
  reports not-installed (exit 3).

Phase 3 (root-gated e2e, `internal/e2e/privileged_test.go`) turns the first
three of those legs into repeatable tests: `TestPrivilegedMirror` (guest `:80`
→ Mac `127.0.0.1:80`) and `TestPrivilegedReserve` (Mac-held `:80` → guest bind
refused with Linux `EADDRINUSE(98)`), both behind a capability probe rather
than a euid check — an unprivileged `just e2e` skips them with the exact root
recipe in the message, `just e2e-root` runs them. Neither needs an installed
daemon: the suite runs its own in-process mirror client, so the privileged
coverage and the dev workflow do not compete for the LaunchDaemon's ports. The
probe's classification is a pure function unit-tested both ways
(`TestPrivilegedPortCapabilityDecision`, no root, no VM). Status: unprivileged
run green (9 pass / 2 skip), and the root execution verified same night via
`just e2e-root` — both legs PASS as root (mirror served guest `:80` on Mac
localhost, 1101 bytes; Mac-held `:80` refused the guest bind synchronously),
resolving via `source=vznat-leases`. One fix was needed to get there:
`limactl` refuses to run as root, so the e2e helpers drop limactl calls to
`$SUDO_USER` under euid 0 — the harness-side twin of the daemon's own
leases-file lesson.

Findings:

1. **Root turns the `:22` skip into a real mirror** — the guest's sshd now
   appears on Mac `127.0.0.1:22` (`ssh localhost` reaches the guest when the
   Mac's Remote Login is off). Correct per the semantics, loopback-only, but
   surprising as a default. **Open question, deliberately not implemented: a
   default exclusion policy for guest infrastructure ports (`:22` and
   friends).** It is a policy call, not a bug — options are a built-in skip
   list, a `-exclude` flag, or leaving the semantics pure — and it only
   becomes visible under root, so it landed as a named follow-up rather than
   a rushed default.
2. The Local Network permission exemption for launchd daemons (TN3179) held
   in practice: the daemon resolved and used vzNAT-direct with no
   subnet-exemption dependency.

## Decisions log

drawbridge name (user-confirmed; loophole/ghostnet/mirage rejected for collisions — loophole.cloud tunneling CLI, GhostNet espionage network, MirageOS/Mirage JS) · cilium/ebpf v0.22 over libbpf-go (pure Go, no cgo; requires Go ≥1.25 — running current stable go 1.26.5 both sides) · fexit over kprobes where BTF allows (Phase 2) · same-port gateway scheme, no stash maps (see BPF section) · gateway addrs `127.0.0.2` and `fd77::2` on lo · dummy "Mac" backends on `127.0.0.3` · tooling via mise + just (user preference) · Apache-2.0 · `'M'`/`'D'` frames mirror `'E'`/`'S'` — the Mac always dials, the guest never does · park-ahead reverse-conn pool over a mux protocol (no per-byte framing; vsock swap stays localized) · Phase 3 outbound is TCP + IPv4 only (v6 gateway listener and UDP-over-stream framing deferred) · sync entries are session-owned, dropped on `'M'` disconnect · seccomp classifies sockets by type+domain, never `SO_PROTOCOL` (MPTCP) · reservations are mirror-owned pending entries released by adoption or TTL, not by a bind-error kernel hook · every uncertain arbitration answers CONTINUE (coordination, not enforcement) · repo pushed 2026-07-30 to `github.com/archcorsair/drawbridge` (private; module path confirmed) · OCI integration via wrapper runtime + spec listenerPath, not daemon-wide profile (agent-down must degrade, never brick `docker run`), not OCI hooks (cannot install filters), not crun plugin (crun-only, C ABI) · OCI protocol on a second socket, no protocol sniffing · `default-runtime=drawbridge` with skip-conditions (user-decided) · unconfined/privileged containers get a synthesized transparent filter, `dev.drawbridge.arbitrate=false` opts out (user-decided) · rootless engines out of scope, OCI socket 0600 (user-decided) · demo standardizes on `:8080`-class ports until the privileged-`drawbridged` story exists (user-decided) · a profile that doesn't provably allow bind is never mutated (deny must not become notify-CONTINUE) · notify-fd supervision is poll-first (RECV blocks forever on dead filters) · UDP muxes per-port framed streams over 'S'/'D' proto 17 (stream-per-flow rejected: socket-per-query workloads would pay ~1 ms per query), 21-byte v1 frame frozen, reserved header byte is the version escape · UDP mirrors exclude the guest autobind range (BPF snum flag is the precise upgrade path) · Mac UDP services are explicit `-udp` config only (udp pcblist has no LISTEN state; auto-discovery deferred) · flow tables expire (60 s/4096) on the side that dials the real backend · tracker events filter autobind-range UDP at the hub; subscriber overflow closes the subscription (drop = reconnect + snapshot, never silent divergence).
