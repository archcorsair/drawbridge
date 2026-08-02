# OCI integration — Phase 4 for real containers

> Status: BUILT (2026-07-30, all four phases; results folded into plan.md's "OCI
> integration results"). Productionizes Phase 4's synchronous-EADDRINUSE bind
> arbitration for actual containers: `docker run --network host` inside the guest gets
> reserve-before-ack semantics transparently, with no cooperation from the containerized
> process. `bindprobe` remains as the harness stand-in; this doc records the design
> and its rejected alternatives.

## Decision summary

| Question | Decision |
|---|---|
| First engine target | **Docker Engine (`docker.io` + runc), rootful.** Podman/crun explicitly kept open by the contract (see below). |
| Integration mechanism | **Wrapper OCI runtime** (`drawbridge-runc`): a small Go binary registered in `/etc/docker/daemon.json` that, on `create`/`run`, rewrites the bundle's `config.json` — injecting `bind` → `SCMP_ACT_NOTIFY` and `linux.seccomp.listenerPath` — then `exec`s the real runc. All other subcommands pass through untouched. |
| Wire protocol | The agent grows a **second unix listener** (`/run/drawbridge-oci.sock`) speaking the **OCI runtime-spec seccomp-agent protocol** (JSON `ContainerProcessState` + `SCM_RIGHTS`, one message per connection). The existing 1-byte handshake on `/run/drawbridge-notify.sock` is unchanged; `bindprobe` and the harness keep using it. No protocol sniffing on a shared socket. |
| Host-network scoping | Two layers: the wrapper injects **only when the container has no private network namespace** (no `network` entry in `linux.namespaces`), and the agent adds a **netns backstop** — any notified bind whose task is not in the agent's netns is answered CONTINUE immediately. |
| Failure posture | The wrapper probes the agent socket before injecting; unreachable ⇒ it execs runc with the spec untouched. Degradation is always Phase 2/3 async mirroring, never a container that fails to start and never a broken bind. |
| BPF | **No BPF changes.** Nothing under `internal/bpf/` is touched; no `just gen`, no shared-struct edits, no regen cost. |

### Why the seccomp filter comes from the runtime, not from us

The OCI runtime spec has native seccomp-notify support: when a profile uses
`SCMP_ACT_NOTIFY` and sets `linux.seccomp.listenerPath`, **the runtime itself installs
the filter in the container's init before `execve` and sends the notify fd** to the
socket at `listenerPath` — `SCM_RIGHTS` plus a JSON `ContainerProcessState`
(`{ociVersion, fds[], pid, metadata, state{id, status, pid, bundle, annotations}}`;
the index of `"seccompFd"` in `fds` names the fd's position in the rights array).
The spec pins the framing: exactly one state per connection, fds only in the first
`sendmsg`, the runtime closes the connection after transmission, and **a send failure
is a runtime error** (the container fails to start). runc has shipped this since
1.1.0; the container entrypoint does not exec until the handoff completes, so the
agent is always supervising before the workload's first syscall.

This dissolves Phase 4 finding 3 (hand the fd over *before* installing the filter):
that ordering existed because `RunBindProbe` installs the filter on itself, so its own
Go runtime's syscalls could be trapped by a not-yet-existent supervisor. Under runc
the filter is installed in the container init, and the fd is pulled out by the
*parent* runc process (`pidfd_getfd`) — which is not under the filter — and forwarded.
The one residual deadlock class is `SCMP_ACT_NOTIFY` on a syscall runc's init needs
after install (runc rejects `write` for exactly this reason); `bind` is not one of
them.

## Engine target: resolving "crun plugin preferred" vs "Docker-transparent"

The vault note preferred a crun plugin; the roadmap's headline demo is
`docker run --net host nginx`. These pull apart only if the guest-side contract is
engine-specific. It isn't, under this design:

**The contract is: any OCI runtime that installs a `bind` → `SCMP_ACT_NOTIFY` filter
and delivers the notify fd to `/run/drawbridge-oci.sock` in spec framing gets
arbitration.** That is the standardized `listenerPath` mechanism — engine-neutral by
construction.

- **Docker Engine first** because the demo, the DX gap, and the OrbStack/Docker
  Desktop comparison are all Docker-shaped; Ubuntu 24.04 ships `docker.io` with
  runc ≥ 1.1.12 (listenerPath support landed in runc 1.1.0; needs kernel ≥ 5.7 and
  libseccomp ≥ 2.5 — guest is 6.8 / 2.5.5). Docker exposes neither OCI hooks dirs
  nor per-daemon spec editing, but it does support **registered runtimes**
  (`daemon.json` → `runtimes` + `default-runtime`), which is exactly the wrapper's
  entry point — the same pattern nvidia-container-runtime has used for years.
- **Podman later, at near-zero cost**: `podman --runtime /usr/local/bin/drawbridge-runc`
  works with the identical wrapper (podman also drives runc `create`), or a variant
  execs crun. crun additionally offers the `run.oci.seccomp.receiver` annotation and
  in-process notify plugins; a plugin, if ever wanted, can forward the fd to the same
  agent socket in the same framing. Nothing in this design precludes any of these.
- **Rejected as first target — crun plugin (.so)**: crun-only (does not cover the
  Docker demo at all), C with a plugin ABI (new toolchain surface in a repo that is
  otherwise pure Go + one BPF C file), and in-process with the runtime (a plugin crash
  is a runtime crash). Would win only if the target were Podman-first or if the spec
  listenerPath path proved unusable — it is proven usable.

### Rejected integration mechanisms

1. **Daemon-wide seccomp profile** (`daemon.json` `"seccomp-profile"` pointing at a
   vendored copy of Docker's default profile with `bind` → NOTIFY + `listenerPath`;
   moby passes these fields through since 23.0). Genuinely simpler — zero new
   binaries — and it remains the quick manual-testing path (Phase C uses a one-off
   profile via `--security-opt seccomp=` to validate the chain before the wrapper
   exists). Rejected as the shipping mechanism because: (a) *every* container start
   gains a hard dependency on the agent socket (spec: send failure = start failure) —
   agent down would brick `docker run` entirely, with no place to put a fallback;
   (b) it forks Docker's default profile, which drifts across Docker versions,
   whereas the wrapper merges into whatever spec the daemon actually computed;
   (c) it cannot scope to host-network containers; (d) any per-container
   `--security-opt seccomp=` silently loses arbitration. Would win if maintaining a
   runc-CLI-compatible shim proved fragile in practice — it is cheap to switch: the
   agent-side listener (the expensive, protocol-bearing piece) is identical for both.
2. **OCI hooks (createRuntime/prestart)**: hooks run in the runtime namespace as
   separate processes — they cannot install a seccomp filter into the container
   process, and they run after the spec is final. Mechanically incapable; also Docker
   doesn't expose hook dirs. (The feature keeps the colloquial name "OCI hook"; the
   artifact is a wrapper runtime.)
3. **containerd shim / runtime plugin config**: reachable from Docker but deeper in
   the stack for no gain over a registered runtime path, and harder to make podman-
   symmetric.
4. **Teaching the agent's existing notify socket both protocols** (sniff first byte):
   saves one socket; costs a protocol ambiguity forever (the spec message begins with
   JSON `{`, the probe's with 0x00 — sniffable today, but a wrong guess breaks a
   handshake that blocks container start). Two sockets, two parsers, shared
   supervisor core is strictly easier to reason about and to reverse.

## End-to-end flow (target state)

```
docker run --network host nginx
  └─ dockerd → containerd → shim → /usr/local/bin/drawbridge-runc create --bundle B id
       ├─ read B/config.json
       ├─ no network ns entry?  agent socket reachable?  bind provably allowed?
       │    └─ yes: rewrite linux.seccomp: bind → SCMP_ACT_NOTIFY,
       │            listenerPath=/run/drawbridge-oci.sock, listenerMetadata={…}
       └─ execve(real runc, unchanged argv)
            └─ runc init installs the filter, parent runc sends
               ContainerProcessState + notify fd → agent OCI listener
                 └─ agent: parse, pick "seccompFd", superviseNotify(fd)   [existing]
nginx binds 0.0.0.0:80
  └─ kernel parks the bind, notifies the agent
       ├─ netns == agent's netns?  stream socket?  mirrorable addr?  port != 0?
       └─ ReservePort over 'R' (500 ms) → Mac binds mirror-before-ack   [existing]
            ├─ "inuse"  → SendErrno(EADDRINUSE)  — synchronous, Linux errno 98
            └─ "ok"/"unknown" → SendContinue — bind proceeds; tracker event
               adopts the pending mirror (or ReserveTTL releases it)    [existing]
```

`docker exec` processes inherit the container's seccomp config from the saved state,
so runc installs the filter (and delivers a fresh notify fd) for them too — exec'd
shells get arbitration for free. One notify fd is supervised per container init and
per exec; supervision ends when the filter's last task exits.

## Design details

### Wrapper runtime (`drawbridge-runc`)

- Pure Go, `//go:build linux`, cross-compiled like the agent. Argv contract: parse
  just enough of the runc CLI to find the subcommand and `--bundle`/`-b` (default:
  cwd). On `create` and `run`: mutate `config.json` in place (write temp + rename),
  then `syscall.Exec` the real runc (path: `$DRAWBRIDGE_RUNC`, else first of
  `/usr/sbin/runc`, `/usr/bin/runc`, `$PATH`). Every other subcommand (`start`,
  `kill`, `delete`, `exec`, `state`, `ps`, …): exec straight through. Never swallow
  runc's exit code or stdio — the shim owns them.
- **Injection preconditions** (all must hold, else exec runc untouched):
  1. `linux.namespaces` has no `"network"` entry (host-network container). An entry
     with a `path` (joining another netns) also skips — the agent backstop covers
     exotic cases.
  2. `/run/drawbridge-oci.sock` accepts a connection (dial, ~100 ms timeout, close).
     Agent down ⇒ stock behavior. (TOCTOU — agent dies between probe and runc's
     send — fails that container's start with a clear runc error; acceptable, rare,
     and retryable.)
  3. `bind` is **provably allowed** by the existing profile: either
     `linux.seccomp == nil` (unconfined/privileged), or `defaultAction` is
     `SCMP_ACT_ALLOW`/`SCMP_ACT_LOG` with no `bind` rule, or `bind` appears in a
     rule with `action: SCMP_ACT_ALLOW` and no `args`. If a profile restricts bind
     in any way we can't trivially prove out, do not touch it — never weaken a
     user's profile from deny to notify-CONTINUE (= allow).
  4. No opt-out annotation (`dev.drawbridge.arbitrate: "false"`).
- **Mutation**: if `linux.seccomp == nil`, synthesize
  `{defaultAction: SCMP_ACT_ALLOW, syscalls: [{names:["bind"], action:"SCMP_ACT_NOTIFY"}]}`
  (no `architectures` — libseccomp defaults to native). Otherwise remove `"bind"`
  from every existing rule's `names` (dropping rules left empty), append the NOTIFY
  rule, and set `listenerPath` + `listenerMetadata` (JSON:
  `{"v":1,"source":"drawbridge-runc","hostNetwork":true}` — logging aid only; the
  agent trusts its own netns check, not metadata). Docker's default profile
  (defaultAction ERRNO + big ALLOW list containing bare `bind`) satisfies
  precondition 3 and mutates cleanly.
- The mutation logic lives in `internal/ociruntime` with **no build tag**, so its
  unit tests run on the Mac (`go test ./internal/...`) against fixture configs:
  docker-default, unconfined, restrictive-bind (must refuse), bridged (must skip),
  args-on-bind (must refuse), annotation opt-out.

### Agent: OCI listener + hardening

- `ServeOCISeccomp(ln *net.UnixListener)` in new `internal/agent/ociseccomp.go`:
  accept → `ReadMsgUnix` (large buf + oob; fds arrive in the first message per
  spec) → drain to EOF appending JSON → parse `ContainerProcessState` → index of
  `"seccompFd"` in `fds` selects the notify fd (close any others) → log
  `state.id`/metadata → `go a.superviseNotify(fd)` (existing, unchanged core) →
  close conn. Malformed message: log, close everything, never crash — worst case is
  that container's start erroring, stock containers unaffected.
- Socket: `/run/drawbridge-oci.sock`, mode 0600 (runc runs as root; unlike the
  probe socket there is no non-root sender — rootless engines are out of scope).
  New flag `-oci-sock` in `cmd/drawbridge-agent/main_linux.go`, wired like
  `-notify-sock`.
- **Netns backstop** in `answerBind` (`internal/agent/notify.go`): before
  classification, compare `readlink /proc/<nf.PID>/ns/net` against
  `/proc/self/ns/net` (helper `seccomp.SameNetNS(pid)` in `internal/seccomp`);
  different or error ⇒ CONTINUE. This keeps the "supervisor must always answer /
  uncertain ⇒ CONTINUE" invariant and makes arbitration correct even if something
  other than the wrapper ever feeds the socket a bridged container's fd. (No change
  to socket classification — still `SO_TYPE` + domain, never `SO_PROTOCOL`.)
- **Supervisor lifecycle hardening**: `superviseNotify` currently treats every
  `ENOENT` from `NOTIF_RECV` as "blocked task went away" and loops. When the
  *filter's last task exits* (every `docker stop`), the kernel may satisfy the recv
  with ENOENT repeatedly — with container churn that risks a spinning goroutine per
  dead container plus a leaked fd. Phase A must pin the actual behavior empirically
  (in-guest test: probe exits → observe the supervisor goroutine), and if the spin
  is real, poll the fd for `EPOLLHUP` (filter dead ⇒ return) before re-recv. Do not
  reason about this from memory — verify in the guest.

### Provisioning (no VM rebuild)

Per AGENTS.md, template edits generally force `limactl delete -f drawbridge` — a
full rebuild on every iteration. So the engine install is an **idempotent in-guest
script** (`scripts/provision-docker.sh`, run via `limactl shell` from a `just`
recipe), not a `lima/drawbridge-dev.yaml` edit:

1. `apt-get install -y docker.io` if `docker` is absent (guest egress already exists
   — the template's provision uses apt and go.dev today).
2. Copy `bin/drawbridge-runc-linux-arm64` → `/usr/local/bin/drawbridge-runc`
   (a copy, not the virtiofs mount path, so Docker's default runtime never depends
   on the Mac-side mount or an unbuilt binary; `just oci-up` recopies after builds —
   no docker restart needed, the shim execs it per container).
3. Write `/etc/docker/daemon.json`:
   `{"runtimes":{"drawbridge":{"path":"/usr/local/bin/drawbridge-runc"}},"default-runtime":"drawbridge"}`
   (merge-preserving if the file exists), `systemctl restart docker` only when
   changed.
4. Build the offline e2e image: `docker image inspect drawbridge/bindtest ||
   tar -C <staging> -cf - . | docker import - drawbridge/bindtest` where staging
   holds the cross-compiled agent binary. **No registry pull in any test** — image
   creation is `docker import` of a local tar.

`default-runtime=drawbridge` makes the demo transparent (`docker run --network host
nginx`, no flags). Because the wrapper no-ops for bridged containers and probes the
agent socket first, stock docker behavior is preserved even with the agent down —
the only added failure mode is a host-network container start racing an agent crash.

### Container-side test binary

New agent subcommand `bindtry` (`cmd/drawbridge-agent/main_linux.go`): plain
`net.Listen` + JSON `{errno, error}` line + optional `-hold` — **no seccomp
machinery, no socket handoff, no imports from `internal/seccomp`**. It is the
"uncooperative process": the filter must come from runc or the test proves nothing.
Reusing the agent binary avoids a new artifact; the e2e image runs
`/drawbridge-agent bindtry -addr 127.0.0.1:<port>`.

## Affected files

| Path | Change |
|---|---|
| `internal/agent/ociseccomp.go` | new — OCI seccomp-agent protocol listener |
| `internal/agent/notify.go` | netns backstop in `answerBind`; supervisor HUP hardening |
| `internal/seccomp/netns.go` | new — `SameNetNS(pid)` |
| `cmd/drawbridge-agent/main_linux.go` | `-oci-sock` flag + listener; `bindtry` subcommand |
| `internal/ociruntime/mutate.go` (+`_test.go`) | new — spec mutation lib, no build tag, Mac-testable |
| `cmd/drawbridge-runc/main.go` | new — wrapper runtime (linux) |
| `internal/harness/seccomp_test.go` (+ helper in harness TestMain) | OCI-framing handoff test; netns CONTINUE test; supervisor-exit test |
| `internal/e2e/e2e_test.go` | container collide / mirror / bridged-scoping tests |
| `scripts/provision-docker.sh` | new — idempotent engine + wrapper + image provisioning |
| `justfile` | `build` adds drawbridge-runc cross-compile; new `vm-docker`, `oci-up` |
| `docs/plan.md`, `docs/HANDOFF.md` | results + status updates (per phase) |
| `internal/bpf/**` | **untouched — no `just gen`, no shared-key-struct changes** |

Frames: the `'R'` reserve path is reused byte-for-byte unchanged; no transport
changes (vsock swap unaffected). Reverse-stream `'D'` protocol untouched.

## Phases

Each lands independently and leaves every existing suite green.

### Phase A — agent speaks the OCI seccomp-agent protocol

Build: `internal/agent/ociseccomp.go`, `seccomp.SameNetNS`, netns backstop in
`answerBind`, `-oci-sock` flag, supervisor lifecycle hardening (empirically pinned).
Harness additions (in-guest): a helper mode that installs the bind filter and has the
*test* deliver the fd to the OCI socket in exact spec framing (JSON + SCM_RIGHTS,
close after send) — deny, continue, and repeat-notification cases against the fake
Mac on `127.0.0.4`; a netns case (`unshare -n` helper must get CONTINUE even for a
"Mac-held" port); a supervisor-termination case (helper exits ⇒ goroutine ends, fd
closed, no spin).

Verify: `just test-guest` (all Phase 1–4 assertions plus the new ones); `just
agent-up` then `just e2e` (existing three flows must stay green — proves the second
listener didn't disturb the first).

### Phase B — wrapper runtime binary

Build: `internal/ociruntime` mutation lib + fixture tests (docker-default profile,
unconfined, restrictive, bridged, args-on-bind, opt-out annotation);
`cmd/drawbridge-runc` (CLI passthrough + exec); `just build` emits
`bin/drawbridge-runc-linux-arm64`.

Verify: `go test ./internal/...` on the Mac (mutation lib is tag-free by design);
`just build`. No guest behavior changes yet — nothing installs the wrapper.

### Phase C — guest engine provisioning + in-guest smoke

Build: `scripts/provision-docker.sh` (docker.io install, wrapper copy, daemon.json,
offline `drawbridge/bindtest` image), `just vm-docker` and `just oci-up`, `bindtry`
subcommand. Before wiring the wrapper as default runtime, validate the chain once
with a hand-written profile — `docker run --security-opt seccomp=/tmp/notify.json
--network host …` — which exercises runc → agent handoff with zero drawbridge
binaries in the loop (this is the rejected-mechanism-1 as a diagnostic, and stays
documented as one).

Verify (in-guest, agent up): `just vm-docker`; then
`limactl shell drawbridge -- sudo docker run --rm --network host drawbridge/bindtest
/drawbridge-agent bindtry -addr 127.0.0.1:<free>` prints `{"errno":0}` and
`just agent-log` shows `notify: bind 127.0.0.1:<free> … -> ok|unknown`; a bridged
`docker run --rm drawbridge/bindtest …` shows *no* agent log line (wrapper skipped
it). `docker run --rm hello-world`-class stock behavior confirmed with the agent
stopped (`just agent-down`) — wrapper degrades. Then `just agent-up` and
`just test-guest` + `just e2e` re-run green.

### Phase D — Mac-side e2e + docs

Build, in `internal/e2e/e2e_test.go` (all gated on docker being provisioned — skip
with an actionable message otherwise, mirroring `requireE2E`):

1. `TestContainerBindGetsSynchronousEADDRINUSE` — Mac holds `127.0.0.1:P`; guest
   runs the host-network `bindtest` container against `P`; expect errno **98**
   (Linux `EADDRINUSE` crosses as a number — never darwin's 48).
2. `TestHostNetContainerListenerMirrored` — container `bindtry -hold` on a free
   port; Mac connects via the mirror (reserve adopted by the tracker event, the
   Phase 2 path end-to-end from a real container).
3. `TestBridgedContainerNotArbitrated` — a *bridged* container binds the Mac-held
   port and succeeds locally (errno 0) — the scoping guarantee.

Docs: plan.md results section, HANDOFF.md status, AGENTS.md command list gains
`vm-docker`/`oci-up`.

Verify: `just e2e` (needs `just agent-up` — suites do not rebuild the agent — and
`just vm-docker` once). `just bench` is **not** required: the dial pool and
forwarder are untouched.

## Resolved questions (user-decided 2026-07-30)

1. **Default-runtime for all containers** — `default-runtime=drawbridge` in
   daemon.json; the transparent demo is the point. The wrapper's skip conditions
   protect bridged/stock containers, and reverting is a one-line edit.
2. **Unconfined/privileged containers DO get the filter** — a synthesized
   ALLOW-default + bind-NOTIFY filter is semantically transparent;
   `dev.drawbridge.arbitrate=false` is the escape hatch.
3. **Rootless engines are out of scope** — rootful docker.io only. The 0600 agent
   socket and root-only filter-install assumptions are invariants, not TODOs.
4. **Demo standardizes on `:8080`-class ports** — the `:80` story waits for the
   privileged-`drawbridged`/launchd work already tracked in HANDOFF.
5. Module path confirmed: `github.com/archcorsair/drawbridge` (repo pushed
   2026-07-30; no longer a placeholder).

## Appendix — externally verified facts (2026-07-30)

- OCI runtime-spec `linux.seccomp.listenerPath`/`listenerMetadata`: runtime sends
  exactly one `ContainerProcessState` per connection (`AF_UNIX`/`SOCK_STREAM`), fds
  in the first `sendmsg`, closes after transmission, and MUST error if the send
  fails. (runtime-spec `config-linux.md`.)
- runc: seccomp-notify + listenerPath shipped in **1.1.0** (PR #2682); the notify fd
  is pulled from runc init via `pidfd_getfd` by the parent and forwarded before the
  entrypoint execs; `SCMP_ACT_NOTIFY` is rejected on `write` (runtime deadlock),
  fine on `bind`. Requires kernel ≥ 5.7, libseccomp ≥ 2.5 — guest (Ubuntu 24.04:
  kernel 6.8, libseccomp 2.5.5, runc ≥ 1.1.12) satisfies both.
- Docker/moby passes `listenerPath`/`listenerMetadata` through from custom seccomp
  profile JSON since **23.0** (moby PR #42604) — which is what makes the Phase C
  hand-written-profile diagnostic (and rejected mechanism 1) mechanically viable on
  noble's docker.io.
- Docker Engine exposes no OCI hooks dirs; runtime registration via `daemon.json`
  `runtimes` + `default-runtime` is the supported extension point (the
  nvidia-container-runtime wrapper-exec pattern).
- Podman on noble (4.9.x) + crun (≥ 1.14): `--runtime <path>` per invocation, plus
  crun's `run.oci.seccomp.receiver` annotation and notify-plugin API as later
  alternatives feeding the same agent socket.
