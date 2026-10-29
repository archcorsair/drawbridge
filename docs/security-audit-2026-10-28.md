# drawbridge code review (2026-10-28)

Whole-repo review of `main` at `149b71c` (the PR #1 merge). Nothing in the
repo was modified; this file is the only output. Every finding below names a
file and line at that commit, was produced by one reviewer, and was then
re-derived from the code by a second agent working against it. High findings
got a third, reproduction-focused check. Severity uses the scale of
[docs/security-audit-2026-10-18.md](docs/security-audit-2026-10-18.md):
**High** breaks ordinary user workloads or crosses a boundary the docs say is
closed; **Medium** is a real weakness with bounded or precondition-gated
impact; **Low** is hardening, defense in depth or an edge case; **Info** is
cosmetic or by design.

## Verdict

The code is in good shape where it has been tested hardest: the privilege
boundaries, the auth handshake, the seccomp always-answer discipline, and
everything the e2e suite exercises. The defects cluster in three places the
tests do not reach:

1. **macOS socket semantics on the bind-arbitration path.** The Mac decides
   "is this port taken" only from the result of its own `127.0.0.1:P` bind, and
   on XNU that bind succeeds over a wildcard holder. A guest bind that should
   fail with `EADDRINUSE` is allowed, and the Mac service's loopback traffic is
   taken over (H1). This was reproduced on this Mac.
2. **The VM's identity is re-derived at every step instead of carried.** `up`
   echoes a spelling that `install` parses as a different VM (H2), the
   upgrade remedy everywhere is a bare `sudo drawbridge install` that
   re-targets the default Lima VM (H3), re-install drops the existing pins
   (M15), `install` silently ignores a positional VM (M11), and root doctor
   diagnoses the default VM rather than the installed one (M22).
3. **Provisioning lifecycle: interruption, teardown, upgrade and VM restarts.**
   The OCI registration can point at a missing binary (M7, M8), silently
   disappears on a colima restart (M12), is never refreshed by the documented
   upgrade (M13), and a rootless podman restart never runs (M9). The original
   slices reviewed HEAD against HEAD; the gap round that walked upgrades and
   VM restarts is what found M12 and M13.

PR #1 closed audit findings 1, 2, 4 (partly), 5, 12 (partly) and 17, but its
supervision cap introduced a new way to get `ENOSYS` in containers (M3). It
also raised the guest kernel floor to 5.14 without updating the preflight
(L5), and missed the root daemon's own mirror accept loop (L20).

| Severity | Distinct findings | Raw (before dedup) |
|---|---|---|
| High | 3 | 5 |
| Medium | 31 | 43 |
| Low | 80 | 93 |
| Info | 11 | 11 |
| **Total** | **125** | **152** (+3 refuted) |

## What was run

| Check | Where | Result |
|---|---|---|
| `go vet ./...` (darwin) | this Mac, Go 1.26.5 | clean |
| `GOOS=linux go vet ./...` | this Mac | clean |
| `go test -count=1 ./...` | this Mac | all 26 packages with tests pass (linux-only and VM-gated tests skip on the Mac) |
| `go test -race -count=1 ./...` | this Mac | all pass, no races reported |
| `just test-guest`, `just e2e`, `just bench`, smoke-sudo | not run | they need the dev VM, and `just e2e` fights the installed root daemon (AGENTS.md); this review stayed read-only on the Mac |

Reviewers ran throwaway programs and overlay tests outside the repo to confirm
Mac-side hypotheses. Nothing touched a VM, ran as root or used the network.
Findings that hinge on guest-kernel, systemd or third-party behavior that could
not be exercised here are marked *(plausible)*.

## Method

- **15 review slices**: eBPF; agent core; seccomp/OCI; Mac data plane;
  transport and resolution; `up`; the rest of the CLI plus install;
  vmprovider; doctor checks; doctor gather plus introspection; TUI; tooling,
  CI and tests; the PR #1 diff as a fresh PR; the Mac/guest wire protocol
  end to end; and every AGENTS.md invariant against its enforcing code.
- **Adversarial verification**: for each slice, a separate agent re-derived
  every finding from the code and tried to refute it (guards elsewhere,
  unreachable inputs, misread semantics, documented intent, duplicates of the
  prior audit). 3 of 155 were refuted, all as documented design (see the end
  of this report). 16 severities were lowered and none raised.
- **Deep verification** of every finding still rated High: an independent
  agent built the exact user sequence and, where possible, ran it. One High
  (M9) was downgraded to Medium there.
- **Completeness critic, then a gap round**: two extra slices, *OCI engine
  matrix and persistence* and *upgrade transitions*, which no original slice
  covered.
- **Prior-audit status**: a separate agent re-checked all 28 findings of the
  2026-10-18 audit at HEAD (table near the end).
- **Lead spot checks**: the three Highs and about a dozen Medium and Low
  findings were re-read against the source by the lead reviewer, and H1 was
  reproduced independently (below). Every one held.

The *Source* column and the `(slice-n)` tags name the reviewer's finding IDs,
which index the workflow journal if more detail is wanted. Findings that
several slices reached independently are noted; that happened for H1 and for
ten of the Mediums, and it is the strongest evidence that they are real.

---

## High

### H1. A Mac port held on a wildcard address is not detected as taken: the guest bind succeeds and the mirror takes over the Mac service's loopback traffic

`internal/mirror/mirror.go:662` (`handleReserve`) and `internal/mirror/mirror.go:480` (`openLocked`); also `cmd/drawbridged/main.go:394`.
Found independently by three slices (macdp-1, wire-1, inv-1); deep-verified.

Both the `'R'` reservation and the async mirror decide "the Mac holds this
port" only from whether their own `net.Listen("tcp", "127.0.0.1:P")` fails with
`EADDRINUSE`. Neither consults the Mac LISTEN set that macsync already polls
every 75 ms. Go sets `SO_REUSEADDR` on every TCP listener, and on XNU that
makes the bind look up the exact address only, so `127.0.0.1:P` binds while
another socket holds `0.0.0.0:P` or `[::]:P`. The more specific listener then
wins `127.0.0.1` connects.

Lead reproduction on this Mac (Darwin 27.0.0, unprivileged, scratch program
outside the repo):

```
holder tcp   [::]:64837      -> mirror 127.0.0.1:64837 BIND OK; 127.0.0.1 client reached "M"
holder tcp4  0.0.0.0:64839   -> mirror 127.0.0.1:64839 BIND OK; 127.0.0.1 client reached "M"
holder tcp4  127.0.0.1:64841 -> mirror 127.0.0.1:64841: bind: address already in use
```

Wildcard holders are the common case on a Mac: Node and Go `listen(port)`,
Docker Desktop and OrbStack publishes, and macOS itself (`ControlCenter`, the
AirPlay receiver, holds `*:5000` and `*:7000` on this machine right now).

Sequence (`up --oci` plus the installed root daemon):

1. macsync syncs the Mac's `*:5000` into the guest; the agent opens its gateway
   listener on guest `127.0.0.2:5000`.
2. A `--network host` container runs `flask run`, which binds `127.0.0.1:5000`
   (Flask, Django, Rails and Jupyter all default to loopback). Linux sees no
   conflict with `127.0.0.2:5000`.
3. The seccomp notification asks the Mac; the reservation binds Mac
   `127.0.0.1:5000`, succeeds, and answers `ok`. The container's bind succeeds.
4. Mac clients of `127.0.0.1:5000` now reach the container, not AirPlay or the
   dev server. `newExclude` matches on port only (`main.go:394`), so the Mac's
   real `:5000` is also withdrawn from the guest. Without `--oci` the async
   mirror does the same takeover with no log line.

Verifier's correction, kept here: a guest *wildcard* bind most likely still
fails natively, because Linux treats `0.0.0.0:P` as conflicting with the
agent's `127.0.0.2:P` listener. The failing case is a guest loopback bind,
which is the default for most dev servers. Every e2e `EADDRINUSE` leg holds
the Mac port on `127.0.0.1` (`internal/e2e/e2e_test.go:581`,
`internal/e2e/oci_test.go:98,165`), so nothing tests this.

**Fix direction.** Before answering `ok` or opening a mirror, check the macsync
LISTEN set for any holder of `P` on `0.0.0.0` or `::` (arguably `::1` too) and
answer `inuse` or record `bind-failed`. Alternatively, clear `SO_REUSEADDR` on
the mirror and reservation listeners through `net.ListenConfig.Control`; the
reviewers confirmed that this returns `EADDRINUSE` against all three wildcard
holders, at some cost in TIME_WAIT rebinding. Add an e2e leg with a wildcard
Mac holder.

### H2. `drawbridge up colima` prints an install line that installs a daemon for a different VM

`cmd/drawbridge/guest.go:308`; printed at `cmd/drawbridge/up.go:799`; parsed at `internal/vmprovider/vmprovider.go:141`.
vmprovider-1; deep-verified with the real built CLI and daemon.

`pickInstance` matches a bare name across every provider (`guest.go:358-364`),
builds the canonical Ref, and then overwrites `ref.Spec` with the user's bare
spelling. `up` prints `Next: sudo drawbridge install -vm <Spec>`, and `install`
and `drawbridged` re-parse that text with `ParseRef`, where a bare name always
means Lima. So `colima` becomes `lima:colima`, `default` becomes
`lima:default` (because `ColimaInstance("default") == "colima"`), and a podman
machine `spike` becomes `lima:spike`.

`drawbridge up colima` is the README's own colima example. `up` writes
`transport-secret-colima-colima`. The pasted install renders
`-secret-file …/transport-secret-lima-colima`, a file that never appears, and
`drawbridged` treats a missing explicit secret as fatal, so launchd
crash-loops it (audit #16's mechanism). For podman, install renders a Lima
daemon with no endpoint pin. Nothing is mirrored either way, and install's own
warning says `drawbridge up colima` will write the missing file, but that
command writes a different one.

**Fix direction.** Echo `qualify(match)` unless the match is a Lima instance,
and add a vmprovider-level invariant, with a test, that `ParseRef(r.Spec)`
gives back the same provider and instance as `r`.

### H3. The upgrade remedy everywhere is a bare `sudo drawbridge install`, which re-targets the root daemon at the default Lima VM

`internal/doctor/checks.go:1500` and `:1508` (also `:1327`, `:1530`, `:1535`); `.goreleaser.yaml:223` (cask caveat); `README.md:277`; `internal/tui/dashboard.go:325`; `internal/agent/transport.go:143`.
gap-upgrade-1 (gap round, not deep-verified; lead re-read the path).

The cask caveat shown on every `brew upgrade`, doctor check 9's version-skew
remedy, README:277 and the TUI's skew chip all say `sudo drawbridge install`
with no `-vm`. `install`'s `-vm` defaults to `install.DefaultVM`
(`"drawbridge"`, `internal/install/plist.go:136`), and nothing fills an omitted
flag from the installed plist (`InstalledVM()` is used only for the
"replacing" notice, `cmd/drawbridge/main.go:328`). Install boots out the
working daemon and writes a plist for `lima:drawbridge` with that VM's secret
path.

A colima or podman user (or any Lima VM not literally named `drawbridge`) who
follows the upgrade instructions ends up with a crash-looping daemon pointed
at a VM that does not exist. Mirroring, sync and synchronous `EADDRINUSE` all
stop on a setup that worked, and doctor then prints the same command again.
`up`'s own handoff line (`up.go:799`) and `docs/releases/v0.2.0.md:98` spell
`-vm` correctly; the other sites do not. M15 compounds this: even with the
right `-vm`, a re-install drops the existing `-vm-mac`, `-vm-subnet`, `-udp`
and `-skip`.

**Fix direction.** Default every flag not given explicitly from the installed
plist (`flag.Visit` tells which were set) and say so. Render every remedy as
`sudo drawbridge install -vm <installed -vm>`; doctor already reads the plist.
Fix the cask caveat, README and TUI string to match.

---

## Medium

### Bind arbitration, data plane and wire protocol

#### M1. Guest listeners on `::1` only (or v6-only `::`) are mirrored, but every connection to the mirror is dropped
`internal/agent/transport.go:233`; also `internal/mirror/mirror.go:352`. Four slices (ebpf-2, agent-core-1, macdp-2, wire-3).

The tracker reports `::1` and v6-only `::` listeners, and the Mac mirrors them
on `127.0.0.1:P`. But the agent's `'S'` handler always dials `127.0.0.1:P`, so
every Mac connection is accepted and then closed. Nothing logs it, and doctor
and the TUI show the mirror as active. Triggers include
`python3 -m http.server --bind ::1`, Go `net.Listen("tcp6", …)`, nginx
`listen [::]:P` (ipv6only by default) with no v4 listen, and Node or Vite
`localhost` binds where the guest resolves `localhost` to `::1` first. The
eBPF gateway likewise treats a v6-only `::` listener as serving `127.0.0.1`.
**Fix:** choose the dial address from the hub's listener set for that port, or
for TCP fall back to `[::1]` on `ECONNREFUSED` (UDP needs the lookup).
Alternatively, decline to mirror `::1`-only listeners and log the decline. Add
a harness leg.

#### M2. A UDP relay flow goes deaf after one ICMP port-unreachable while its peer keeps sending
`internal/udpframe/relay.go:88`. Three slices (agent-core-2, macdp-3, wire-2).

The per-flow reader exits on `ECONNREFUSED` from its connected UDP socket, but
the flow stays in the map. Later datagrams are still forwarded, and every
reply is left unread. This lasts as long as the client sends at least once per
60 s `FlowIdleTimeout`. The real path is Mac UDP services offered with `-udp`
(a Mac dnsmasq on 53, say) that restart or start after the guest's first
datagram, with a guest client that reuses its source port (c-ares, QUIC,
WireGuard, game clients). Inbound mirrors mostly self-heal, because a guest
`del` closes the stream. **Fix:** on any reader error other than
`net.ErrClosed`, delete the flow if the map still points at it and close the
socket; or treat `ECONNREFUSED` as transient. The same shape exists in
`internal/proxy/udp.go:85-97` (harness path only).

#### M3. PR #1's supervision cap closes real OCI listeners, turning a container's `bind()` into `ENOSYS` for life; any guest process can fill it
`internal/agent/notify.go:105`, `internal/agent/notifycap.go:18`. Three slices (seccomp-oci-1, pr1-1, inv-4); relates to audit #4.

The 4096-slot cap is one counter shared by the `0666` probe socket and the
`0600` OCI socket, and it counts fds, not senders. On refusal,
`acceptNotifyFd` closes the fd. For an OCI handoff that fd is the only
reference to the container's listener (runc has closed its own), so the
kernel answers every later `bind()` in that filter with `ENOSYS`. Any
unprivileged guest process can install its own `NEW_LISTENER` filters (per
thread, no `TSYNC` needed) and send 4096 genuine listeners through the `0666`
socket; they all pass `IsListener`. After that, every new `--network host`
container and every `docker exec` into one gets `ENOSYS`, with one throttled
log line as the only trace. The documented failure posture is stock behavior
or a degrade to CONTINUE. The fd-store adoption branch cannot hit the cap with
the shipped unit (`FileDescriptorStoreMax=4096` equals the cap), so only the
two socket paths are affected. **Fix:** never close an OCI-delivered listener
on a cap refusal. Reserve capacity for the OCI socket, give the probe socket
its own per-uid budget (`SO_PEERCRED` is already read), and revisit whether
production needs the `0666` socket at all, as audit #4 suggested.

#### M4. The Mac-sync wire is keyed per address on the Mac and per port on the agent, so one `del` withdraws a port the Mac still serves
`internal/macsync/sync.go:452`; `internal/agent/macsync.go:129-151`. Three slices (macdp-4, agent-core-4, wire-4).

The Mac tracks `{proto, port, addr}` and sends `add`/`del` per address. The
agent registers per `{proto, port}`, ignores the second `add`, and removes the
whole port on any `del`. With two Mac sockets on one port at different
normalized addresses (`0.0.0.0:5432` from Docker Desktop plus `127.0.0.1:5432`
from a `kubectl port-forward`), closing one makes the guest lose 5432 while
the Mac still serves it and still lists it as advertised. Nothing re-sends the
`add` until the `'M'` session reconnects. **Fix:** refcount per address on the
agent, or collapse to per-port on the Mac before diffing.

#### M5. Tracker ring-buffer overflow drops listener events silently, and nothing reconciles the hub with `guest_ports`
`internal/bpf/c/tracker.c:186`. Two slices (ebpf-1, inv-5).

A failed `bpf_ringbuf_reserve` drops the ADD or DEL with no counter.
Autobind UDP churn is filtered only in the hub, after the ring buffer, so it
still consumes ring slots. A lost ADD means a listener is never mirrored. A
lost DEL leaves a dead mirror on Mac `127.0.0.1:P`, which also excludes the
Mac's own `P` from sync. Reconnect does not heal it, because the snapshot is
the hub's set. The verifier notes that the trigger needs high churn (more than
8192 records inside one consumer lag), so this is a heavy-load failure. It
runs against the spirit of the "never drops silently" invariant. **Fix:** skip
`emit()` for autobind in BPF while still counting `guest_ports`, count drops
in an array map, and rebuild the hub's set from `guest_ports` when the counter
moves.

#### M6. If the Mac's secret file disappears while the daemon runs, every dial silently goes unauthenticated
`internal/transportauth/mac.go:108`. transport-resolve-1.

`MacConfig.Secret` re-reads the file on every dial, and `LoadOptional` folds
"absent" into `nil`. With `nil`, `ClientHello` sends `auth=0` and
`AwaitAgentProof` skips the proof. Only boot treats a missing explicit
`-secret-file` as fatal. Scenario: the user follows the documented rotation
(`rm <file> && drawbridge up`, also doctor's remedy at
`internal/doctor/auth.go:273`) while the VM is stopped, and `up` fails before
it rewrites the file. The root daemon falls back to `tcp://127.0.0.1:4777`,
which is free because the VM's forward is gone. Any local user can bind it,
and root accepts that process as its agent: it binds loopback mirrors on that
process's say, privileged ports included. This contradicts AGENTS.md's
"configured-but-unreadable fails closed" and "a side with a secret refuses
unauthenticated peers". `status`, doctor and the TUI do show auth mode `none`;
the dial path and the log do not. **Fix:** once a secret was configured or
loaded, absence is a refusal (`CauseSecretUnreadable`), never a downgrade.

### CLI, provisioning and lifecycle

#### M7. `down` deletes the runc wrapper while `daemon.json` still makes it Docker's default runtime
`cmd/drawbridge/down.go:90`. Four slices (cli-up-3, cli-rest-1, inv-2, oci-matrix-2).

When `provision.json` does not record the registration as drawbridge's (dev
flow `just vm-docker`, a pre-existing registration, an `up --oci` interrupted
before its state write, or the "remove provision.json" remedy), `revertOCI`
correctly leaves `daemon.json` alone, but step 3 still deletes
`/usr/local/bin/drawbridge-runc` unconditionally. The running dockerd already
has `default-runtime=drawbridge` loaded, so the next `docker run` fails
immediately, and `down` reported a clean removal. **Fix:** before deleting
either wrapper, check `daemon.json` (or `docker info` `DefaultRuntime`) and
podman's runtime path. Keep the binary and say why when anything still names
it.

#### M8. `daemon.json` is written before the wrapper exists, and a re-run never heals an interrupted first run
`cmd/drawbridge/up.go:597`. Two slices (cli-up-2, oci-matrix-6).

`provisionOCIDocker` writes `default-runtime=drawbridge` (`up.go:596-598`), and
the wrapper is installed later by the script in a separate shell round trip
(`provision-docker.sh:82-85`). The comment at `up.go:573-576` claims the
opposite order. Interrupt in between and the default runtime is a binary that
does not exist. The re-run installs the wrapper but restarts docker only when
*this* run changed `daemon.json`. If the interruption landed before the state
write, the re-run records the merged file as the original, and a later `down`
keeps `daemon.json` while deleting the wrapper (M7). **Fix:** install the
wrapper first, write `daemon.json` last, record state before the mutation, and
restart when the running config differs from the file.

#### M9. Rootless podman API-service restart never runs: an unquoted `SC=%s` becomes an env-prefix assignment
`cmd/drawbridge/ocipodman.go:187`. Two slices (cli-up-1, inv-3); deep-verified, downgraded from High.

The script renders `SC=systemctl --user -M core@.host` unquoted. A POSIX shell
parses that as `SC=systemctl` prefixed to a command named `--user`, which
fails. `SC` stays empty, `$SC cat podman.service` runs plain `cat`, and the
result is reported as `drawbridge-podman=absent`. The verifier confirmed this
under sh, bash and dash. On a rootless machine (podman's default) with an
active `podman.service` (Podman Desktop, compose, or the Mac-side `podman`
CLI, which is a remote client of that service), containers keep the cached
real crun and bypass the wrapper. After `down`, the cached wrapper path has
been deleted, so creates fail until someone restarts the service by hand. No
warning is printed. **Fix:** quote the value, or pass the manager as separate
words; add a test that runs the rendered script under `sh`.

#### M10. `up --oci` on a Lima or Colima guest running rootless podman never sets `-oci-sock-owner`
`cmd/drawbridge/up.go:120`. cli-up-4.

The socket-owner decision keys on the provider (podman machine), not on the
guest's engine and mode. With Lima's `template://podman` (rootless), the OCI
socket stays `root:0600`, crun runs as the user and cannot connect, and
nothing is arbitrated while `up` reports success. That is the posture AGENTS.md
calls fatal: "an agent that continued would look healthy and arbitrate
nothing". **Fix:** decide on `pf.Engine == EnginePodman && !pf.Rootful`, or
refuse `--oci` with a named reason.

#### M11. `install`, `doctor`, `tui`, `status` and `uninstall` silently ignore a positional argument and every flag after it
`cmd/drawbridge/main.go:165`. cli-rest-2.

`_ = fs.Parse(args)` never checks `fs.Args()`, and Go's flag package stops at
the first non-flag. So `sudo drawbridge install colima:default` (the grammar
`up` and `down` accept) installs for `lima:drawbridge`, and
`sudo drawbridge install myvm -print`, meant as a preview, performs a real
install. `drawbridge doctor podman:spike -json` diagnoses the implicit VM and
prints text. `up` and `down` already use `parsePositional` for exactly this.
**Fix:** reject leftover arguments, or accept the positional VM the way
`up`/`down` do.

#### M12. Colima regenerates `daemon.json` on every `colima start`, silently dropping the `--oci` registration
`cmd/drawbridge/up.go:597`. oci-matrix-1 (gap round); the colima behavior comes from colima's source, not a live restart.

`provisionOCIDocker` writes the merge once, and nothing re-applies it. After a
Mac reboot or `colima stop && colima start`, dockerd runs plain runc while the
agent, secret and wrapper all persist. Mirroring keeps working, but
synchronous `EADDRINUSE` for containers is gone, and doctor still reports
`provisioned --oci` as ok (see M27). docs/verify-colima.md never restarts the
VM after `up --oci`, which is why this was not seen live. **Fix:** re-apply the
registration from the agent at start (it is root in the guest), or have
doctor detect the drift and warn with the `up --oci` remedy.

#### M13. The documented upgrade never refreshes the OCI wrapper, so PR #1's listenerPath fix never reaches guests provisioned with `--oci`
`cmd/drawbridge/up.go:108`. gap-upgrade-2; relates to audit #5.

`up` gates the wrapper push on `--oci`, while the cask caveat, README:147 and
doctor tell users to upgrade with a bare `drawbridge up <vm>`. A guest
provisioned on v0.2.0 gets the new agent with the old wrapper, which still
overwrites an existing `listenerPath`. Those notifications reach the new
agent, `IsBind` is false, and it answers CONTINUE, which is audit #5's
deny-becomes-allow, after an upgrade meant to fix it. No release contains
PR #1 yet, so this affects the next one. **Fix:** refresh the wrapper whenever
the guest was provisioned with `--oci` (`provision.json` present or the
wrapper path exists), and have doctor compare wrapper digests with the bundle.

#### M14. The agent restart is gated on "this run wrote the binary", so a failed or interrupted `up` leaves the old agent running for good
`cmd/drawbridge/up.go:163`. gap-upgrade-3.

If `up` pushes the new binary and then fails (a malformed secret, Ctrl-C, a
provider-shell hiccup during `daemon-reload`), the re-run finds the digest
matching and the unit unchanged, so nothing restarts the old process. `up`
and doctor check 3 both say "re-run `drawbridge up`", which changes nothing.
The verifier notes that the v0.2.0 to HEAD upgrade escapes this, because PR #1
changed the unit; the loop applies to later upgrades without a unit change.
**Fix:** restart based on what is running (`/run/drawbridge-agent.version` or
the running `exe` digest against the bundle), not on what this run wrote.

#### M15. A re-install for upgrade silently drops the existing `-vm-mac`, `-vm-subnet`, `-udp` and `-skip`
`internal/install/install.go:55`. gap-upgrade-4; relates to audit #25.

The plist is rebuilt from flags alone. A user who pinned `-vm-mac` as AGENTS.md
and the README recommend, and who re-runs the release-notes command with only
`-vm`, is back to name-only lease matching (audit #25's squatting exposure).
They also lose `-udp 53` and any custom skip list, and on a Mac whose vmnet is
not `192.168.64.0/24`, they lose the subnet override that resolution depends
on. The generic "no -vm-mac given" warning prints, but nothing says a pin was
removed. **Fix:** the same as H3: default unset flags from the installed plist
and say so, with an explicit way to clear a value.

#### M16. Rootless Docker is reported as `engine=docker`; `--oci` registers the wrapper with a rootful dockerd nobody uses, and starts it *(plausible)*
`cmd/drawbridge/guest.go:608`. oci-matrix-3 (gap round).

On Lima's `template://docker`, the user's CLI talks to the rootless daemon.
`up --oci` merges into the system `/etc/docker/daemon.json`, starts a rootful
dockerd (plus docker0 and iptables) uninvited, and reports success. The user's
containers keep plain runc. Non-mirroring of rootless containers is the
documented out-of-scope; the `--oci`-specific defects are the false success
and the uninvited daemon. **Fix:** detect rootless (`docker context show`,
`DOCKER_HOST`, a user-level `docker.service`, `rootlesskit`) and refuse
`--oci` with a named reason.

#### M17. `--oci` on a docker guest checks neither that runc is where the wrapper looks nor runc's version floor
`cmd/drawbridge/guest.go:750`. oci-matrix-5 (gap round).

podman's branch checks crun for both. For docker: (a) a guest whose only runc
is `/usr/local/bin/runc` passes, and then every `docker run` fails with
"drawbridge-runc: no real runc found" (confirmed from the code). (b) An old
runc (Debian 11's 1.0.0~rc93) passes the preflight, and the injected
`SCMP_ACT_NOTIFY` is probably rejected (not verified). Both are rare on the
documented platforms. **Fix:** probe `command -v runc` and `runc --version`
like crun, and refuse below the floor or off the probed paths.

#### M18. Attachability accepts any Lima/Colima `vz` instance, including one with no vzNAT network *(plausible)*
`internal/vmprovider/vmprovider.go:93`. vmprovider-2.

drawbridge's own create hint (`colima start --vm-type vz …`, no
`--network-address`) produces such a VM. The attach succeeds and the agent
binds loopback only. The root daemon finds no lease and falls back to Mac
`127.0.0.1:4777`, which is Lima's own automatic forward (the default gRPC
tunnel drops TCP half-close, per AGENTS.md). `up` does print the
"no host-reachable guest IP (vzNAT missing?)" note, so it is not silent.
**Fix:** treat `vz` with no vzNAT MAC as not attachable (or attachable with an
explicit note), and add `--network-address`/vzNAT to the create hints.

### doctor, introspection and TUI

#### M19. Daemon log-tail auth evidence is not scoped to the target VM and outlives uninstall
`internal/doctor/auth.go:378`. doctor-checks-1.

A root daemon for one VM logs refusals, and `drawbridge doctor -vm <another>`
reports `auth-wrong-peer` fail (exit 1) for a VM nothing serves. After
`uninstall` the frozen tail of `/Library/Logs/…` keeps producing the same
FAIL. **Fix:** use the log tail only when the installed daemon is loaded and
its VM canonicalizes to the target (or filter lines by the VM they name), and
date the lines so the staleness rule applies.

#### M20. Check 5 treats any broader covering route as the vmnet subnet's route
`internal/doctor/checks.go:1057`. doctor-checks-2.

A full-tunnel VPN (`0/1` plus `128.0/1`, as OpenVPN def1 and wg-quick install)
or a `/16` hides both the deleted-route and the crutch-static pathologies that
check 5 exists to catch; it reports `[ok] vzNAT route` instead. **Fix:**
classify only the most specific covering route, as the kernel does, and treat
a broader one as absent.

#### M21. `sudo drawbridge doctor` can never report the root-fail half of the discriminator
`internal/doctor/checks.go:1250`, `internal/doctor/gather.go:379`. Two slices (doctor-checks-3, doctor-4).

Under euid 0, a failed lease dial makes the resolver fall back, and the failed
candidate is not exposed, so check 6 says "not probed" rather than "root
cannot reach the guest either". The both-fail row (content filter or network
fault), which doctor.md calls conclusive, never appears. Check 4 does warn
about the fallback. **Fix:** expose the first failed lease candidate on
`limaaddr.Resolution`, or derive it from the lease db in gather, and dial it.

#### M22. Root doctor diagnoses the default VM, not the one the root daemon serves, and the printed remedy carries no `-vm`
`internal/doctor/gather.go:594`; remedy at `internal/doctor/checks.go:1318`. Two slices (doctor-5, doctor-checks-4).

A colima user's unprivileged doctor prints `sudo drawbridge doctor`, and the
root run diagnoses `lima:drawbridge`. That matches the doc text ("explicit
-vm, else the daemon's default VM") but defeats its intent ("mirrors the root
daemon"). **Fix:** under euid 0 default to `install.InstalledVM()`, and render
the remedy with `-vm <target>`.

#### M23. Check 9's runtime alarms never change its status, so doctor stays green while macsync syncs nothing
`internal/doctor/checks.go:1520`. doctor-checks-5.

On macOS 27.0b4 a terminal-launched `drawbridged` sees an empty pcblist
(AGENTS.md's "treat an empty enumeration as the gate, not the truth"). Doctor
builds the "advertised nothing" line but renders `[ok] Mac daemon` and exits 0,
and the default renderer hides evidence on ok findings. Row-7 "refused reverse
dial" alarms are hidden the same way. **Fix:** raise check 9 to warn on a fresh
alarm or the adv-0 state.

#### M24. Gather's `-timeout` does not bound resolution: doctor hangs against a wedged guest
`internal/doctor/gather.go:344`. doctor-1.

`wg.Wait` blocks on `guestIP`'s unbounded `limactl shell`, though the help
says doctor "terminates against a wedged VM rather than hanging". In the TUI,
each `R`/`p` press leaks a parked Gather goroutine and its `limactl`
children. **Fix:** thread the context through every exec Gather triggers
(`exec.CommandContext`, a ctx-aware provider `Shell`), or race `wg.Wait`
against `ctx.Done()`.

#### M25. `introspect.Listen` chmods and chowns the parent directory of an explicit `-introspect` path
`internal/introspect/server.go:74` (and `:96`). doctor-2.

`os.Chmod(dir, dirMode)` runs unconditionally on an existing directory, and
under root so does `os.Chown(dir, 0, 0)`; both follow symlinks.
`sudo drawbridged -introspect /tmp/x.sock` turns `/private/tmp` from 1777 into
0755 `root:wheel`, which drops the sticky bit and world-write, and breaks every
non-root process that writes to `/tmp`. Unprivileged,
`-introspect ~/x.sock` makes the home directory 0700. **Fix:** assert modes
only on a directory Listen created, or require a dedicated directory.

#### M26. With the help overlay open over the doctor view, doctor keys answer first
`internal/tui/model.go:249`. tui-1.

`esc`, which the card says closes it, cancels a running probe or leaves the
doctor view while the card stays up. On short terminals the card's bottom
groups cannot be scrolled from the doctor view. **Fix:** route keys to a
help-only handler while `overlayHelp` is open.

#### M27. doctor's OCI classification never checks that the registration is in effect
`internal/doctor/checks.go:491`. oci-matrix-4 (gap round).

The docker branch has no registration check at all, so M12's colima restart
stays green. On podman, the "runtime is NOT the wrapper" and missing-drop-in
states are `StatusOK`, shown only under `-v`, which contradicts doctor.md. One
machine's `down` removing the shared drop-in therefore goes unreported on the
others. **Fix:** "provisioned `--oci` but not in effect" is a warn with the
`up --oci` remedy: for docker, read `DefaultRuntime` and check the wrapper
exists; for podman, cover `RuntimePath != WrapperPath` and a missing drop-in.

### Tooling, CI and tests

#### M28. Release binaries, including the root daemon and the root guest agent, are built with Go 1.25.0
`.github/workflows/release.yml:42`. tooling-2.

`setup-go` with `go-version-file: go.mod` takes `go 1.25.0` as an exact
version (there is no `toolchain` line), and `GOTOOLCHAIN=auto` does not
upgrade, because 1.25.0 satisfies the go line. So releases ship the original
1.25 stdlib with none of its patch releases, a toolchain CI never tests (CI
uses `1.25.x`/`1.26.x`; mise pins 1.26.5). **Fix:** pin
`go-version: 1.26.x` (or add a `toolchain` directive) in release.yml, and run
`govulncheck` in CI.

#### M29. smoke-sudo-oci's arbitration leg can pass with the wrapper broken
`scripts/smoke-sudo/main.go:540`. tooling-1.

The leg greps the journal for `-> inuse` with no time bound, and the
bindprobe step about 30 s earlier already logged one. The container's nginx
bind on `0.0.0.0:48081` is also refused natively by the agent's `127.0.0.2`
gateway listener. So a rootless machine whose OCI socket is unreachable still
reports "agent logged -> inuse", and this is the only podman `--oci`
acceptance. **Fix:** match the container's own bind line, bound the journal
window with a cursor taken just before `podman run`, and have nginx listen on
`127.0.0.1:<port>`.

#### M30. smoke-sudo "restores" the previous daemon with only `-vm`
`scripts/smoke-sudo/main.go:337`. tooling-3.

The restore drops `-vm-mac`, `-udp`, `-skip`, `-vm-subnet` and `-secret-file`,
may install a different `drawbridged` binary, and still reports
`restored=true`. **Fix:** snapshot the plist and binary and replay them
verbatim, then compare the restored plist and report any difference.

#### M31. The dev Lima template mounts only the original author's checkout path
`lima/drawbridge-dev.yaml:17`. tooling-5.

The only mount is `~/ghq/github.com/archcorsair/drawbridge`, while every
in-guest recipe uses `{{justfile_directory()}}` (`justfile:24,67,74,83`). Any
other clone location breaks `just gen`, `test-guest`, `vm-docker` and
`agent-up`, and `just e2e` then misreports the cause as "agent transport not
reachable". This includes this checkout, at `[reviewer's path redacted]`.
**Fix:** mount the checkout path (the template can be rendered by `vm-up`), or
mount `~` read-only plus the checkout writable.

---

## Low

Grouped by area. *(plausible)* means the mechanism is confirmed but depends on
runtime, kernel or third-party behavior not exercised here.

### Guest kernel hooks and tracker

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| L1 | `internal/agent/agent.go:111` | /proc/net seed reads every file before any Put, so a listener that closes in that window leaves a permanent guest_ports entry and Mac mirror (explicit ports too) | Seed each row immediately, or after the Put re-check the socket's existence (rescan the key) and roll back. | ebpf-3 |
| L2 | `internal/bpf/c/loopback_gw.c:165` | recvmsg/getpeername un-rewrite turns every 127.0.0.2 peer into 127.0.0.1 for all host-netns sockets, breaking guest software that really uses 127.0.0.2 *(plausible)* | Un-rewrite only flows that could have been rewritten: gate on lb4_served(&mac_ports, proto, ntohs(user_port)), since the peer port is the same port under the same-port scheme. | ebpf-4 |
| L3 | `internal/bpf/c/loopback_gw.c:135` | Guest connect/sendto to 0.0.0.0:P or [::]:P skips the gateway, though Linux delivers it to loopback *(plausible)* | In handle_v4, treat user_ip4 == 0 like 127.0.0.1: guest_ports check first, then rewrite to the gateway when mac_ports serves the port. | ebpf-5 |
| L4 | `internal/harness/harness_test.go:110` | No test anywhere covers the v6-API gateway paths (connect6 v4-mapped rewrite, getpeername6/recvmsg6 un-rewrite, sendmsg4 via dual-stack sockets), which carry all JVM loopback traffic | Add harness legs: a tcp6 dual-stack client (net.Dial("tcp", "[::ffff:127.0.0.1]:P") on an AF_INET6 socket) to a Mac-mapped port with a raw getpeername assertion. | ebpf-6 |
| L5 | `internal/bpf/loader.go:33` | Gateway load now needs SO_NETNS_COOKIE (kernel 5.14) but up's preflight, doctor and README still gate at 5.7, so 5.8 to 5.13 guests pass every check and the agent crash-loops (audit #1) | Either raise minKernel to 5.14 in both cmd/drawbridge/guest.go and internal/doctor/checks.go (as a hard failure, not only for --oci, with a message naming SO_NETNS_COOKIE) and update README.md:112, or remove the 5.14 dependency. | pr1-3, gap-upgrade-5 |
| L6 | `internal/harness/notifyfd_test.go:113` | The fd-store send and adopt paths have no automated test, and ExtraFdsClosed claims cases it never exercises | Add a linux unit test that points NOTIFY_SOCKET at a unixgram socket in a temp dir and asserts the FDSTORE and FDSTOREREMOVE datagrams and their SCM_RIGHTS. | pr1-7 |

### Guest agent, seccomp and OCI wrapper

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| L7 | `internal/agent/transport_test.go:165` | TestFramedDialConnParksSilent cannot catch the loss of the pre-dispatch deadline clear it claims to pin | Keep the conn parked past HandshakeTimeout before popping, or make the handshake timeout an Agent seam set to about 50 ms in the test. | agent-core-3 |
| L8 | `internal/agent/listen.go:79` | pickVZNAT's 'bridges hold the first host' rule misses non-.1 gateways, so on VMs with no vzNAT NIC auto mode can bind the transport on a bridge and allowlist a container | Exclude interfaces by kind rather than by address shape: skip bridge, veth, vxlan and other virtual links via /sys/class/net/<if>/bridge, the uevent DEVTYPE, or the absence of /sys/class/net/<if>/device. | agent-core-5 |
| L9 | `cmd/drawbridge-agent/main_linux.go:159` | The control socket is chmodded after listen() and the chmod error is ignored, so the audit #17 fix leaves a window (audit #17) | Create the socket with umask 0077 set around Listen (syscall.Umask), or inside a 0700 directory. | agent-core-6 |
| L10 | `internal/agent/dialpool.go:56` | A park-to-waiter handoff that races pop's timeout strands the 'D' conn in an unread channel | Do the send while still holding mu: the buffered channel makes it non-blocking, and it makes pop's remove-then-drain atomic with respect to park. | agent-core-7, wire-5 |
| L11 | `internal/ociruntime/mutate.go:58` | Synthesized profile for unconfined/privileged containers omits `architectures`, so compat-ABI (i386/x32) processes are killed by libseccomp's bad-arch action *(plausible)* | Synthesize `architectures` as the native arch plus its compat sub-architectures (amd64: X86_64, X86, X32; arm64: AARCH64, ARM), passed in by GOARCH so MutateConfig stays pure. | seccomp-oci-2 |
| L12 | `internal/seccomp/seccomp.go:178` | EINTR from NOTIF_SEND / NOTIF_ID_VALID is treated as final: the notification is never answered and the target's bind() blocks forever *(plausible)* | Retry on EINTR in send, IDValid and IsListener. | seccomp-oci-3 |
| L13 | `internal/ociruntime/mutate.go:68` | Injected listener occupies the container's one-listener-per-filter-chain slot: nested seccomp agents inside arbitrated host-network containers fail with EBUSY | Document the restriction next to the opt-out annotation (the slot is kernel-enforced, one listener per filter chain). | seccomp-oci-4, inv-11 |
| L14 | `internal/agent/notify.go:36` | Probe-socket handoff read has no deadline: idle connections to the 0666 socket pin an agent fd and goroutine each, without limit (audit #4) | SetReadDeadline (about 1-2 s) on the conn before ReadMsgUnix, and a per-uid limit on concurrent handoff connections (SO_PEERCRED is already read). | seccomp-oci-5 |
| L15 | `internal/agent/notify_linux_test.go:55` | Per-ABI bind fix (1412ca1) is pinned only at the table level: reverting answerBind to the native-number compare passes every test | Add an answerBind case (pipe fd, PID 0) with Arch=AUDIT_ARCH_I386 (amd64) or AUDIT_ARCH_ARM (arm64) and the compat bind nr. | seccomp-oci-6 |
| L16 | `internal/agent/notify.go:158` | A notification the dying agent had received but not yet answered is never re-delivered: with the fd store keeping the listener alive, that bind() hangs forever (audit #2) *(plausible)* | On SIGTERM, set a stopping flag that supervisors check before calling Recv, and wait (bounded, about 2x reserveTimeout) for in-flight answerBind calls before returning from main. | pr1-2, gap-upgrade-6 |
| L17 | `internal/acceptloop/acceptloop.go:64` | acceptloop still ends a listener silently on any non-Temporary accept error; every caller drops Serve's error with no log, which is the finding-12 failure mode for other errnos (audit #12) | In each caller, treat a Serve return that is not net.ErrClosed as fatal (log the error and os.Exit(1), so Restart=on-failure brings up a fresh agent that re-adopts the stored fds). | pr1-4 |
| L18 | `internal/seccomp/seccomp_amd64.go:16` | Per-ABI bind table misses i386 socketcall(SYS_BIND), the form mainstream i386 glibc uses, so 32-bit x86 containers get CONTINUE plus a misleading 'not drawbridge's filter' log *(plausible)* | For (AUDIT_ARCH_I386, 102) with Args[0]==SYS_BIND (2), read the three u32 arguments from target memory at Args[1], then continue with those values as for a direct bind. | pr1-5 |
| L19 | `internal/acceptloop/acceptloop.go:70` | Proxy Close now waits out an uninterruptible backoff sleep of up to 1 s while RemoveMacPort and Agent.Close hold a.mu | Make the backoff wait interruptible: Serve takes a stop channel or context (or checks a closed flag), and the proxy and agent listeners close it alongside the listener. | pr1-8 |

### Mac daemon, transport and resolution

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| L20 | `internal/mirror/mirror.go:497` | The root daemon's mirror accept loop still exits on the first Accept error; PR #1's acceptloop fix missed it (audit #12) | Drive acceptLoop with acceptloop.Serve(ln.Accept, handler, log.Printf). | macdp-5, wire-6 |
| L21 | `internal/mirror/mirror.go:252` | The 'E', 'R' and 'M' reconnect loops log every failure at about 1 Hz with no backoff, which breaks the premise the log-rotation design rests on | Use capped exponential backoff with jitter in all three session loops and in poolLoop (for example 1 s up to 30 s, reset after a session that delivered its snapshot). | macdp-6 |
| L22 | `internal/mirror/mirror.go:454` | bind-failed and skipped entries in the introspection data never go away, so the TUI and doctor report stale failures for ports nothing listens on | Call forget(key) in del when there is no entry or refs reaches 0. | macdp-7 |
| L23 | `internal/macsync/sync.go:346` | A v6-only [::] Mac listener is synced as 0.0.0.0, but the reverse dial always targets 127.0.0.1 and is refused | Treat `::` as v4-any only when the pcb's inp_vflag has INP_IPV4 (0x1). | macdp-8 |
| L24 | `internal/mirror/udp.go:27` | A non-literal -mirror-ip such as localhost makes UDP mirrors bind on every interface while TCP mirrors stay on loopback | Parse MirrorIP once into a netip.Addr when the client is built, and use that for both TCP and UDP. | macdp-9 |
| L25 | `internal/proxy/udpstream.go:75` | udpStreamProxy dials the Mac pool while holding p.mu, so Close() (called under the agent-wide a.mu) can block for about 3 s per synced UDP port | Dial outside p.mu, with a single-flight dialing flag. | macdp-10 |
| L26 | `internal/limaaddr/limaaddr.go:234` | ParseSubnet checks the unmasked address but returns the masked prefix, so install can render a -vm-subnet the daemon rejects at boot | Validate the masked prefix: m := p.Masked(), then require m.Addr().IsPrivate() and the last address of m to be private too, or at least a minimum Bits() (for example /8 inside 10/8, /12 inside 172.16/12, /16 inside 192.168/16). | transport-resolve-2, inv-10 |
| L27 | `internal/limaaddr/leases.go:221` | The MAC pin trusts hw_address, which bootpd likely takes from the client-written DHCP chaddr field, so it may not be 'the one field a guest cannot choose' (audit #25) *(plausible)* | Check live whether bootpd records chaddr or the frame source MAC, using a guest that sends a DHCPREQUEST with a forged chaddr. | transport-resolve-3 |
| L28 | `internal/limaaddr/limaaddr.go:317` | guestIP runs limactl with no timeout, and drawbridged's resolver holds its mutex across the call *(plausible)* | Use exec.CommandContext with a short timeout (a few seconds) plus cmd.WaitDelay in guestIP. | transport-resolve-4 |
| L29 | `internal/podmanaddr/podmanaddr.go:81` | podmanaddr's probe cannot tell a dead agent from a live one when gvproxy still holds the port; its timeout diagnosis is effectively unreachable *(plausible)* | After the TCP connect, read for a short window: gvproxy closing at once means no agent behind it. | transport-resolve-5 |
| L30 | `internal/limaaddr/leases.go:342` | The root daemon's name-only lease warning tells colima users to run a limactl command that cannot find their instance | Interpolate t.LimaHome the way limactlShow does ('LIMA_HOME=<dir> limactl list --format json <instance>'), or point to `drawbridge install`'s own hint. | transport-resolve-6 |
| L31 | `internal/vmrecord/vmrecord.go:126` | vmrecord.Write truncates the file in place instead of writing atomically; an interrupted write blocks up and install and loses the recorded port | Write to a temp file in the same directory (0600), fsync it, and rename it over the record. | transport-resolve-7 |
| L32 | `internal/transportauth/transportauth.go:35` | Secret's redaction only covers Stringer verbs; %#v and %d print the raw key bytes, and the test checks only String() | Add GoString() returning the same redacted text, plus a Format(fmt.State, rune) method that redacts for every verb. | transport-resolve-8 |
| L33 | `internal/macsync/sync.go:472` | 'M' publishes a new port to the guest before adding it to the advertised set, so an early activation is refused | Publish the union of the old and new sets before sending the adds, then publish the final set after the dels. | wire-7 |
| L34 | `internal/mirror/mirror.go:303` | 'E' row-6 diagnosis ('guest has a secret, this daemon needs one') also fires for an agent that is simply down behind a forwarder, and floods the 32-entry refusal ring | Throttle the Record through Auth.Throttle like every other refusal site. | wire-8 |
| L35 | `internal/mirror/mirror.go:294` | Mac side never enforces the agent's 15 s 'E' liveness ping; 'E', 'R', 'D' and 'M' detect a silently dead path only through TCP keepalive or retransmission timeouts *(plausible)* | Set a read deadline (about 45 s, matching the agent) before each 'E' Decode, so the existing ping becomes the liveness signal. | wire-9 |
| L36 | `cmd/drawbridged/main_test.go:166` | TestRootDoesNotReadThePodmanRecord never executes the euid-0 branch it is named for | Inject euid (resolveAuto(ref, target, euid int)) and assert that euid 0 returns the refusal note without touching HOME, for example with a HOME that contains a record that must not be read. | inv-8 |

### CLI, provisioning, install and providers

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| L37 | `cmd/drawbridge/ocipodman.go:99` | Podman API restart is gated on the drop-in bytes changing, but the drop-in is shared across machines, so a machine whose wrapper is newly installed keeps its API service on the real crun *(plausible)* | Restart (or at least report) when the wrapper was newly installed (changedWrapper with no previous file) as well as when the drop-in changed. | cli-up-5 |
| L38 | `cmd/drawbridge/up.go:482` | Root installs and executes /tmp-staged content with no digest re-check: second site of the /tmp staging weakness, with a code-execution consequence (audit #8) | In the same root script, copy the staged file to dst.drawbridge-new and verify its sha256 against the digest the Mac computed before the `mv`. | cli-up-6 |
| L39 | `internal/guestbin/provision.go:236` | Surgical Revert rewrites (reformats) daemon.json and makes `down` restart docker even when it has nothing to undo | Track whether the surgical path actually deleted or restored a key, and skip the write and the docker restart when it did neither. | cli-up-7, oci-matrix-8 |
| L40 | `cmd/drawbridge/ocipodman.go:247` | Podman restart-failure remedy always names `systemctl --user`, which is the wrong manager on a rootful machine | Print the command for the manager actually targeted (`sudo systemctl …` for rootful, `systemctl --user …` for rootless), from the same `rootful` value used to build SC. | cli-up-8 |
| L41 | `cmd/drawbridge/down.go:163` | revertOCI treats any state version other than 2 (including a missing/0 version) as a docker state, so `down` reformats daemon.json, reports it 'restored' and restarts docker | Switch on the version explicitly: 1 is docker, 2 is podman, above MaxStateVersion is newerStateError, and 0 or negative is an error naming the file. | cli-rest-3, inv-6 |
| L42 | `cmd/drawbridge/render.go:118` | Default `status` hides the installed launchd daemon whenever any other daemon answers its introspection socket | When st.Installed()//st.Loaded and no usable snapshot's PID equals st.PID (or !st.Running()), append renderStatus's launchd block, or at least one line naming the installed job's state and the log path, after the calm blocks. | cli-rest-5 |
| L43 | `cmd/drawbridge/main.go:87` | Usage text says `--oci is not available on podman machines yet` and describes down/--oci as daemon.json-only, but podman --oci is implemented and documented | Rewrite the up/--oci and down entries to cover both engines (the docker daemon.json merge and the podman crun drop-in shared via ~/.config/containers), and add -probe to the doctor synopsis. | cli-rest-6 |
| L44 | `internal/vmprovider/podman.go:389` | Podman machine config dir is hardcoded to ~/.config and ignores $XDG_CONFIG_HOME, which podman honours *(plausible)* | On the user side, honour $XDG_CONFIG_HOME in PodmanMachineDir. | vmprovider-3 |
| L45 | `internal/vmprovider/forwarding.go:209` | Lima rule model makes every specific-guestIP rule skip wildcard listeners, not just ignore rules, and ignores proto and hostPort, so it under-reports what Lima forwards *(plausible)* | Apply the specific-guestIP-vs-wildcard skip only to ignore rules, matching the hostagent's asymmetry. | vmprovider-4 |
| L46 | `internal/vmprovider/vmprovider.go:330` | Detect lists every colima instance twice when $LIMA_HOME points at colima's _lima, and the first suggestion carries the wrong lease name | In Detect, compare cleaned/EvalSymlinks'd LimaHome() and ColimaHome() and drop the Lima driver when they are the same directory, since those instances are colima's. | vmprovider-5 |
| L47 | `internal/vmprovider/vmprovider.go:221` | Podman's empty LeaseName ('no lease exists') means 'default to lima-<name>' in limaaddr, so the sentinel fails open, and e2e resolveAgent passes podman refs through ungated | Make the empty-lease sentinel fail closed (an explicit no-lease marker on limaaddr.Target, or refuse a podman-tagged target), and dispatch podman in e2e resolveAgent as bench does. | vmprovider-6 |
| L48 | `internal/vmprovider/lima_test.go:117` | The root-refusal tests that pin ErrRootScoped and ErrPodmanRootScoped never run anywhere | Route both seams through a package-level `geteuid = os.Geteuid` variable. | vmprovider-7 |
| L49 | `README.md:280` | The first `drawbridge up` onto this release restarts an agent that never stored its fds, so running containers get ENOSYS even though the README says restarts are covered | Add a release note and a README/oci-hook.md sentence: the first restart onto the fd-store release still drops existing containers' listeners. | pr1-6 |
| L50 | `internal/guestbin/assets/provision-docker.sh:101` | up --oci and down start a stopped or disabled docker.service: `systemctl start`/`restart` where only a reload of a running engine was meant | Restart the engine only when it is active (`systemctl is-active`), never start a stopped or disabled one. | oci-matrix-7 |
| L51 | `cmd/drawbridge/ocipodman.go:129` | On podman, the -oci-sock-owner carried forward on a plain `up` comes from provision.json, not from the machine's current mode, so it is lost after a rootful-to-rootless switch *(plausible)* | When a v2 state exists and --oci is not passed, take the owner from the current preflight (pf.User on a rootless machine) instead of the recorded value, and rewrite the state with the new mode. | gap-upgrade-7 |
| L52 | `internal/guestbin/dropin.go:195` | The shared podman drop-in is tracked by a per-machine digest: another machine's rewrite makes `down` claim 'edited since up', and a machine whose drop-in another machine's `down` deleted still passes doctor | Recognise any drop-in this build would render as ours (compare with the DropinBytes output, not only the recorded digest), and word the refusal as 'rewritten by another drawbridge up'. | gap-upgrade-8 |
| L53 | `cmd/drawbridge/ocipodman.go:145` | readPodmanState treats a newer state version as 'not podman' instead of refusing as its comment says, so an older CLI's `up` silently drops -oci-sock-owner | Return newerStateError when v > MaxStateVersion, before the v != 2 early return. | gap-upgrade-9 |

### doctor, introspection and TUI

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| L54 | `internal/doctor/checks.go:819` | Podman check 4 is ok whatever the resolver found: an empty endpoint or a failed probe note is ignored, and under euid 0 the verdict is unconditionally ok | In the podman branch, an empty endpoint or a failed probe note is a fail carrying the resolver's Note, also under euid 0. | doctor-checks-6 |
| L55 | `internal/doctor/auth.go:355` | Ring row-6 evidence (auth-mac-missing-secret) and the daemon's own auth state are dropped when doctor's file comparison matches, giving a false 'mutual auth on every conn' | When the pair matches, emit auth-mac-missing-secret (fail) if the matched snapshot reports mode none or secretState absent/malformed, or if there is a fresh row-6 ring entry. | doctor-checks-7 |
| L56 | `internal/doctor/auth.go:346` | The primary auth verdict ignores Mac.Malformed: a malformed Mac file gets an auth-mismatch remedy that `up` refuses, and unstat-able files read as absent | In primaryAuthFinding, check Mac.Malformed first. | doctor-checks-8 |
| L57 | `internal/doctor/auth.go:390` | auth-wrong-peer names doctor's own resolution source, not the source of the daemon that was refused | Pass matched.State.Resolution.Source (and the endpoint) when a matched snapshot exists. | doctor-checks-9 |
| L58 | `internal/doctor/checks.go:830` | For a non-root run, a vznat-leases resolution counts as ok, and check 6 marks the probe ok for the guest's own address even when that address failed (audit #25) | In localNetworkInput, set ProbeOK from the resolver only when the resolver's endpoint host equals ProbeAddr's host; otherwise dial ProbeAddr. | doctor-checks-10 |
| L59 | `internal/doctor/checks.go:1540` | Check 9 reports ok for a daemon that serves a different VM, and never says the target VM is unserved | Pass the target ref, or matched==nil, into DaemonInput. | doctor-checks-12 |
| L60 | `internal/doctor/checks.go:507` | The runc version floor is skipped whenever crun exists, but the Docker wrapper always execs runc | Check the runtime the wrapper actually execs: on non-podman targets, apply the runc floor regardless of crun, and apply the crun floor only on podman. | doctor-checks-13 |
| L61 | `internal/doctor/checks.go:1361` | Check 7 treats every activated network extension (VPN packet tunnels) as a Little Snitch-class content filter and tells the user to deactivate it | Report known content-filter bundles (or entries whose name or bundle indicates a filter) with the LS signatures. | doctor-checks-14 |
| L62 | `internal/introspect/server.go:139` | Snapshot assembly runs outside the write deadline and waits on drawbridged's resolver mutex, which is held across a limactl exec and probe dials: a healthy daemon reads as an 'unreadable snapshot' and slots can stay pinned | In drawbridged, resolve without holding r.mu and swap the result in under the lock, or publish the resolution through an atomic.Pointer, so readers never wait on I/O. | doctor-3 |
| L63 | `internal/introspect/server.go:171` | Listen unlinks a live introspection socket, and Close unlinks whatever socket is at the path: two daemons on one path silently hide each other | In removeStale, dial the existing socket first and refuse if it answers; unlink on Close only if the inode at the path is still ours. | doctor-6 |
| L64 | `internal/introspect/paths.go:71` | The user-daemon socket for podman's default machine exceeds sun_path for any username of 8+ characters, and the suggested workaround makes the socket undiscoverable | Keep the per-VM file name bounded: abbreviate or hash the instance when the full path would overflow (e.g. `introspect-<provider>-<sha8>.sock`); consumers already match on the payload's vm.ref. | doctor-7 |
| L65 | `internal/doctor/gather.go:170` | The guest script curls gvproxy's API at 192.168.127.1 on every provider, so Lima and colima runs send an HTTP GET off-box and spend up to 3 s of the 10 s shell budget | Run the gvproxy block only for podman targets: render the script per provider, or put a provider word on stdin ahead of the script. | doctor-8 |
| L66 | `internal/doctor/gather.go:501` | halfCloseInput drops a malformed Mac secret and runs -probe unauthenticated, the downgrade the fail-closed test claims to forbid | Pass the derived path whenever one exists, Malformed included, so runProbeWithWindow's fail-closed Secret() produces the Err. | doctor-9 |
| L67 | `internal/doctor/probe.go:223` | Context expiry or cancellation is recorded as network evidence: the probe's ctx-driven close reads as the agent's EOF, and an expired-ctx dial reads as the Local Network timeout | After any read or dial error, check ctx.Err() and record 'doctor's budget ran out' as Err rather than EOF or timeout. | doctor-10 |
| L68 | `internal/tui/model.go:234` | One scrollState is passed between regions across overlay changes: help inherits the pane's or table's offset and follow and hands its own back, and a selection made inside the switcher drops the refusals pane's follow | Recompute m.scroll = m.freshScroll() after every overlay transition: open and close help, and close the switcher after a selection, computed after m.overlay is set. | tui-2 |
| L69 | `internal/tui/dashboard.go:586` | Under NO_COLOR or TERM=dumb the mirror-table cursor disappears: its only marker is reverse video, which termenv drops under the Ascii profile | Give the cursor row a glyph that survives without color, for example a `▸`/`◂` marker in the two-column gutter alongside the pulse mark or replacing it, with reverse video kept as emphasis. | tui-3 |
| L70 | `internal/tui/model.go:317` | The mirror cursor is kept in view only when it moves: opening the detail strip with enter, or any other drop in the row budget, pushes the selected row off screen and removes the overflow tail | After any change that can alter the budget (RowDetail toggle, WindowSizeMsg, applySnapshots while mirrorMoved), re-run m.scroll.reveal(cursor, cursor, len(entries), m.scrollVisible()). | tui-4 |
| L71 | `internal/tui/model.go:601` | When D7 retires the selected daemon, or a late -vm match moves the selection, the per-daemon row cursor, detail strip and scroll carry over to the new daemon | Route both resolveSelection paths through a shared reset of the per-daemon view state (cursor, strip, scroll, switcher cursor), without setting pinned on the fallback path, or move those fields into a helper that selectPath also uses. | tui-5 |
| L72 | `internal/tui/model.go:524` | A daemon that starts answering with a newer schema or a malformed payload is shown for 30 s as 'stopped answering', with its stale last-known summary and a second switcher row | In applySnapshots, treat a path that answered skewed or malformed in this fetch as answered: drop it from m.snaps right away (or mark it as replaced, not missed), so the skew card or unreadable row takes its slot. | tui-6 |
| L73 | `internal/tui/doctorview.go:593` | wrapText hard-splits by rune count after measuring display width, so a space-free token containing wide characters panics with an out-of-range slice and crashes the TUI from the doctor failure card | Split by display width, for example with ansi.Truncate or lipgloss MaxWidth for the head and the remainder computed by width, or clamp the index to len(r) and advance by runes until the width fits. | tui-7 |

### Tooling, CI and tests

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| L74 | `justfile:97` | `just e2e` prints a bare `ok` when every leg skipped, but the docs and the release protocol treat its output as a tally | Run e2e with -v, or with `-json` piped through a small summarizer that prints pass/skip/fail counts. | tooling-4 |
| L75 | `scripts/smoke-sudo/main.go:630` | smoke-sudo can hang forever in the --oci dup leg, and an interrupt skips every cleanup and the daemon restore | Run the foreground container under a timeout: `timeout 30 podman run ...` in the stdin script, or `podman run --stop-timeout` plus a Go-side context with a deadline. | tooling-6 |
| L76 | `internal/e2e/e2e_test.go:661` | waitBindArbitrationLive and startDrawbridged cannot tell a live 'R' session from a missing one, so they do not gate what they claim | Gate on the reservation's own side effect: hold the free-port probe and require `m.Mirrors("tcp", port)` while it is held, or grep for `-> ok`. | tooling-7 |
| L77 | `internal/e2e/e2e_test.go:232` | e2e resolveAgent sends podman refs through the Lima lease resolver and falls back to the Lima dev VM's forward | Reuse the bench's dispatch in e2e: `if vmRef.Provider == vmprovider.ProviderPodman { return podmanaddr.Resolve(vmRef) }`, failing when the endpoint is empty. | tooling-8 |
| L78 | `internal/e2e/skip_test.go:126` | The skip-list positive leg has no attribution guard, on the false premise that forwarders never republish loopback binds | Call `requireAttributableMirror(t, "127.0.0.1", skipPort)` in both skip legs and correct the comment. | tooling-9 |
| L79 | `justfile:83` | agent-up, the e2e suite and the bench hardcode the arm64 guest binary, so x86_64 guests break although the template ships an x86_64 image | Resolve the arch once (`limactl shell vm -- uname -m`, mapped as in provision-docker.sh) in agent-up, and reuse vmprovider's GuestArch in guestAgentBin and agentBin. | tooling-10 |
| L80 | `internal/bench/wedge_test.go:69` | TestWedgeRepro runs its mirror and syncer without transport auth, so it cannot run against a provisioned guest | Load macAuth as requireBench does and set `m.Auth = macAuth` and `Auth: macAuth` on the syncer. | tooling-11 |

## Info

| # | Where | Finding | Fix direction | Source |
|---|---|---|---|---|
| I1 | `internal/harness/ociseccomp_test.go:239` | TestNotifyFilterExitSemantics, cited as pinning 'NOTIF_RECV on a dead filter blocks forever', never calls NOTIF_RECV | Add a bounded Recv on the dead filter in a goroutine and assert it is still blocked after the timeout (or assert whatever the kernel does today), or drop the "pinned by" claim from AGENTS.md. | inv-7 |
| I2 | `internal/agent/control.go:15` | The control API is documented as driven by `drawbridge-agent testctl`, which does not exist | Either restore a testctl subcommand or say the socket is a debugging and harness surface with no in-tree client. | agent-core-8 |
| I3 | `internal/transportauth/transportauth_test.go:195` | TestVerifyConstantTimeAndLengthStrict says it pins hmac.Equal but would pass with bytes.Equal | Pin the implementation structurally instead of behaviorally, for example with a source-level check (a go/ast scan) that Verify calls crypto/hmac.Equal or crypto/subtle.ConstantTimeCompare. | transport-resolve-9 |
| I4 | `cmd/drawbridge/up.go:315` | Every podman machine records the same transport port (4778), so an endpoint pinned for one machine reaches whichever machine is running | When choosing a new port, skip ports named in any other vm-podman-*.json record in the drawbridge state directory. | cli-up-9 |
| I5 | `cmd/drawbridge/doctor.go:37` | doctor's -v flag help contradicts the renderer and docs/doctor.md §6: warn/fail/info evidence is not 'always printed' | Reword the help to match §6: ok and info are title-only, warn and fail show the remedy (or the first evidence line), skip shows one evidence line, and -v shows everything. | cli-rest-7 |
| I6 | `cmd/drawbridge/main.go:328` | Install's 'replacing the installed daemon' notice compares raw -vm spellings, so it warns about replacing a VM with itself | ParseRef both values and compare Provider+Instance, printing the notice only when the canonical target differs. | cli-rest-8 |
| I7 | `internal/vmprovider/podman.go:31` | ErrPodmanRootScoped's message starts with Lima's refusal and tells podman users the root daemon uses the DHCP lease db | Implement the podman refusal as its own error type whose Is(target) reports ErrRootScoped and whose Error() is podman's text only. | vmprovider-8 |
| I8 | `cmd/drawbridge/guest.go:751` | --oci refusal on a containerd-only guest tells the user that a Colima VM already has Docker Engine | Name the case: when containerd/nerdctl is present and docker is absent, say --oci supports Docker Engine and podman only, and that mirroring and host-process EADDRINUSE still work. | oci-matrix-9 |
| I9 | `internal/tui/model.go:34` | The production CLI swaps the doctor view's real gather for canned findings whenever DRAWBRIDGE_TUI_DEMO_DOCTOR is set, and nothing on screen marks the report as canned | When GatherDoctor is non-nil, render a visible `canned (demo)` tag in the doctor header and footer. | tui-8 |
| I10 | `internal/tui/keys.go:77` | The in-app help and docs/tui.md disagree with dispatch: esc's help omits the detail-strip step, j/k's help omits the mirror cursor, and §4.1's scroll-region precedence is the reverse of the code's | Update the esc, j and k help strings to match dispatch, and amend docs/tui.md §4.1's Scrolling precedence to say the doctor view outranks an open pane (or change scrollRegion to match the doc). | tui-9 |
| I11 | `.github/workflows/release.yml:3` | Workflow header comments describe the release as dormant and CI as main-only, contradicting the live triggers | Delete the stale DORMANT paragraph and the first ci.yml trigger paragraph, and state the live behavior: which tags publish, and whether prerelease tags touch the tap. | tooling-12 |

---

## Status of the 2026-10-18 audit at HEAD

Every one of the 28 findings was re-checked against `149b71c`. PR #1 fixed
1, 2, 5 and 17 outright and 4 and 12 in part. Nothing else has changed since
the audit; the cross-references point at new findings in this report that
extend an old one.

| # | Sev | Finding | Status | Notes |
|---|---|---|---|---|
| 1 | High | Gateway rewrite not netns-scoped | **Fixed** (95936e1) | `host_netns_cookie` gates all eight hooks; the load fails on an error or a 0 cookie. The kernel floor is now 5.14 and the preflight was not raised (L5). |
| 2 | High | Agent exit turns `bind()` into `ENOSYS` | **Fixed** (f2c1ebd) | fd store plus re-adopt. A full stop then start still gives `ENOSYS` (documented). The first restart onto this release still drops listeners (L49), and a bind in flight at restart hangs (L16). |
| 3 | Medium | Static proofs replayable by a `CAP_NET_RAW` host-network container | Still open | The proof is unchanged, and transport-auth.md §1 and §4 still claim there is no passive observer. |
| 4 | Medium | Thread and fd exhaustion through the 0666 notify socket | **Partly fixed** (93cd9f2) | IsListener gate, extra fds closed, 4096 cap. The socket is still 0666, the handoff read has no deadline (L14), and the cap is global and closes real listeners (M3). |
| 5 | Medium | Wrapper overwrites `listenerPath`; `answerBind` ignores `nr` | **Fixed** (550ce06, 1412ca1) | Guests provisioned with `--oci` keep the stale wrapper after the documented upgrade (M13). i386 `socketcall` is not covered (L18). |
| 6 | Medium | UDP reply path writes to any loopback destination | Still open | `internal/mirror` is untouched since the audit. |
| 7 | Medium | `/proc/net` seed under-counts and leaks | Still open | L1 adds a second seed race. |
| 8 | Medium | Secret staged world-readable in guest `/tmp` | Still open | L38 adds a second site: root installs `/tmp`-staged content without re-checking its digest. |
| 9 | Medium | `install` side effects before its refusals | Still open | |
| 10 | Medium | Stray Linux ELF `drawbridge-runc` at the repo root | Still open | `.gitignore` covers `/drawbridge` and `/drawbridged` but not `/drawbridge-runc`. |
| 11 | Medium | Committed BPF objects have no regeneration check | Still open | PR #1 regenerated `loopbackgw_bpfel.o`, and nothing cross-checks it against its source. |
| 12 | Medium | Accept loops die on the first error | **Partly fixed** (93cd9f2) | Five agent loops use `acceptloop.Serve`. The root daemon's own mirror loop was missed (L20), and a non-temporary error still ends a loop silently (L17). |
| 13 | Low | Root re-reads a user-owned secret without owner, mode or symlink checks | Still open | |
| 14 | Low | Unbounded `'E'`/`'R'` JSON decoders | Still open | Also the guest's `'M'` and reserve decoders, and the OCI socket's `io.ReadAll` with no limit or deadline (`internal/agent/ociseccomp.go:82`). |
| 15 | Low | `limactl` from `$PATH` under euid 0; `launchctl`/`netstat`/`arp` by bare name | Still open | |
| 16 | Low | Install-before-`up` crash-loops the daemon | Still open | Now reachable through H2 and H3 as well. |
| 17 | Low | Control socket mode relies on umask | **Fixed** (93cd9f2) | A bind-to-chmod window remains, and the chmod error is ignored (L9). |
| 18 | Low | Tracker refcount read-modify-write races | Still open | |
| 19 | Low | `is_gateway_addr` v6 prefix+suffix sniff | Still open | |
| 20 | Low | `/proc/<pid>/mem` read can block the supervisor | Still open | A stuck read now also holds a cap slot (M3). |
| 21 | Low | `Merge` never corrects a stale runtime path | Still open | |
| 22 | Low | Guest-controlled strings reach the Mac terminal unfiltered | Still open | |
| 23 | Low | Unbounded reads of guest output | Still open | |
| 24 | Low | Ad-hoc signing, quarantine strip, no `-trimpath`, no checksum signing | Still open | The signing gap is accepted in the README; `-trimpath` and checksum signing are not addressed. See also M28. |
| 25 | Low | Name-only lease match lets any vmnet VM win | Still open | L27: the MAC pin itself may be guest-written. M15 and M30: re-install and smoke-sudo silently drop the pin. |
| 26 | Info | Unauthenticated mode admits any host-netns process | By design | |
| 27 | Info | An authenticated Mac peer owns `'D'`, replaces `'R'`, flaps `'M'` | By design | |
| 28 | Info | Introspection reveals the home path; log 0644; `/Users/nxc` fixtures | By design | Unchanged. |

## Refuted during verification

Three findings were dropped. All three describe behavior the docs specify:

- **`down` exits 0 with a WARNING on stdout after a failed docker restart,
  then deletes the wrapper** (cli-rest-4). docs/ergonomics.md:833-837 says
  `down` "warns loudly with remediation when docker will not come back".
  M7 is the related real defect: deleting the wrapper while `daemon.json`
  still names it.
- **Doctor's tier-2 row 3 leads with `sudo drawbridge install`**
  (doctor-checks-11). This is specified by doctor.md §4 check 6's four-state
  table.
- **`sudo drawbridge doctor` reads the user's podman machine config as root**
  (inv-9). podman.md:1346-1348 and doctor.md:293 document this. However,
  AGENTS.md's wording ("never reads the user's per-VM record or machine
  config", with doctor under euid 0 following the same rule) is broader than
  what those docs say; reconciling the two would prevent the next reviewer
  from flagging it.

## Suggested order of work

No release contains PR #1 yet, so the first group should land before the next
tag; otherwise that release's headline fixes do not reach upgraded guests, and
some guests that work today will break.

1. **Before the next release.** L5 (raise the preflight and doctor kernel gate
   to 5.14, or drop the hard `SO_NETNS_COOKIE` dependency), M13 (refresh the
   wrapper on any `--oci`-provisioned guest), L49 (release-note the
   first-restart `ENOSYS`), M28 (build releases with a patched, CI-tested
   toolchain) and H3 (fix the upgrade remedy in the cask caveat and doctor).
2. **H1.** Consult the macsync LISTEN set in `handleReserve` and `openLocked`,
   and add an e2e leg with a wildcard Mac holder. This is the one finding
   that breaks a headline semantic for common setups.
3. **VM identity as one change.** H2, H3, M15, M11, M22 and I6: echo only
   canonical spellings, default `install`'s unset flags from the installed
   plist, and reject leftover positional arguments. One invariant test
   (`ParseRef(r.Spec)` round-trips) would have caught H2.
4. **Restore fail-closed posture.** M6 (an absent secret after boot is a
   refusal) and M3 (never close an OCI-delivered listener on a cap refusal;
   give the probe socket its own budget).
5. **OCI lifecycle.** M7, M8, M9, M10, M12, M14 and M27: write order, `down`
   safety, script quoting (a test that runs every rendered script under `sh`
   would catch M9's class), re-applying the registration after a VM restart,
   and doctor drift detection.
6. **Data plane.** M1, M2, M4, M5, then the cheap Lows: L20 (wrap the mirror
   accept loop in `acceptloop.Serve`) and L21 (reconnect backoff, already a
   recorded follow-up in HANDOFF).
7. **doctor accuracy.** M19 to M24 and M27. Each is a case where doctor reports
   ok or not-probed for a state it was built to catch.
8. **Tooling and tests.** M29, M30, M31, then the test-gap Lows (L4, L6, L7,
   L15, L36, L48, L76, I1, I3): tests that pass whether or not the behavior
   they name is present.
