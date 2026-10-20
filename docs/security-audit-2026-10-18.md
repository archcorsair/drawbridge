# drawbridge security and soundness audit (2026-10-18)

Read-only audit of `main` at `afc1b24`. Nothing was modified, run as root, or
executed in a VM. Evidence is from reading source; `go build ./...` and
`go vet` were run on the Mac (clean). Five scoped reviews (Mac root daemon and
install, guest agent and seccomp and OCI wrapper, eBPF, CLI provisioning, supply
chain) were cross-checked, and every finding below was re-verified against the
code by the lead reviewer. "Confirmed" means the full code path was read;
"suspected" means the mechanism is confirmed but exploitability depends on a
kernel or distro behavior that was not tested live.

## Verdict

The privilege boundaries the design claims are real and well built: the install
path refuses non-root-owned ancestors, root's argv is allowlisted rather than
escaped, every transport conn is authenticated before a payload byte is read,
the reverse dial path is bounded to advertised ports, mirrors bind loopback only,
secrets never touch argv, env, or logs, and the seccomp supervisor degrades to
CONTINUE on every doubt. No finding gives an unprivileged Mac user root, and no
finding lets a bridged container reach the Mac.

What the audit found is concentrated in three places:

1. **Soundness bugs that break ordinary workloads** (gateway not netns-scoped;
   agent restart turning `bind()` into `ENOSYS` in running containers).
2. **A threat-model premise that does not hold**: `--network host` containers
   with Docker's default `CAP_NET_RAW` are a passive observer of the transport,
   and the static HMAC proof is replayable by one.
3. **Robustness of root-running processes against local DoS** (thread and fd
   exhaustion through the 0666 notify socket; accept loops that die on EMFILE;
   unbounded JSON decoders).

Nothing here is a reason to stop using the tool on a single-user dev Mac. The
first group should be fixed before the next release because users will hit it;
the second should at least be documented honestly; the third is hardening.

## Severity scale

- **High**: breaks ordinary user workloads, or crosses a boundary the docs say is
  closed.
- **Medium**: a real weakness with a bounded or precondition-gated impact.
- **Low**: hardening, defense in depth, or an edge case.
- **Info**: accepted by design or cosmetic; recorded so the acceptance is
  conscious.

## Findings

| # | Sev | Area | Finding | Status |
|---|-----|------|---------|--------|
| 1 | High | eBPF | Gateway rewrite is cgroup-global but not netns-scoped: bridged containers lose their own loopback on every Mac-held port | Confirmed |
| 2 | High | Agent | Agent exit or restart makes `bind()` return `ENOSYS` in every running arbitrated container | Confirmed (kernel semantics), not live-tested |
| 3 | Medium | Transport | Static proofs are replayable by a host-network container with `CAP_NET_RAW`; the "no passive observer" premise is false | Confirmed |
| 4 | Medium | Agent | Any guest process can exhaust the agent's OS threads and fds through the 0666 notify socket | Confirmed |
| 5 | Medium | OCI wrapper | Wrapper overwrites an existing `listenerPath`, hijacking a user's own seccomp agent; `answerBind` never checks the syscall number | Confirmed |
| 6 | Medium | Mac daemon | UDP mirror writes guest-supplied reply frames to any loopback destination from a root socket | Confirmed |
| 7 | Medium | eBPF | `/proc/net` seed writes refcount 1 with no `sk_keys`; pre-existing ephemeral listeners and reuseport groups leak or under-count | Confirmed |
| 8 | Medium | CLI | Transport secret is staged world-readable in guest `/tmp` and survives an aborted `up` | Confirmed |
| 9 | Medium | Install | `install` boots out the running daemon and chowns the target dir before the path check can refuse | Confirmed |
| 10 | Medium | Supply chain | Stray 3.7 MB Linux ELF `drawbridge-runc` is committed at the repo root | Confirmed |
| 11 | Medium | Supply chain | Committed BPF objects have no regeneration check in CI | Confirmed |
| 12 | Medium | Agent | Accept loops exit permanently on the first `Accept` error (EMFILE) | Confirmed |
| 13 | Low | Mac daemon | Root re-reads a user-owned secret with no owner, mode, or symlink check (same-uid file-length oracle; same-uid process can become the "agent") | Confirmed, partly design-accepted |
| 14 | Low | Mac daemon | `'E'` and `'R'` JSON decoders are unbounded | Confirmed |
| 15 | Low | Mac daemon | `limaaddr.guestIP` execs `limactl` from `$PATH` under euid 0; `install` and `doctor` exec `launchctl`, `netstat`, `arp` by bare name | Confirmed |
| 16 | Low | Mac daemon | Install-before-`up` crash-loops the daemon while the CLI says it will run unauthenticated | Confirmed |
| 17 | Low | Agent | Control socket mode relies on umask | Confirmed |
| 18 | Low | eBPF | Refcount read-modify-write races in `track_add` / `track_del`; update return ignored on a full map | Confirmed |
| 19 | Low | eBPF | `is_gateway_addr` v6 match is a prefix+suffix sniff matching any `fd77:…::2` | Confirmed |
| 20 | Low | Agent | `/proc/<pid>/mem` read can block the supervisor indefinitely | Suspected |
| 21 | Low | CLI | `Merge` never corrects a stale `runtimes.drawbridge.path` | Confirmed |
| 22 | Low | CLI | Guest-controlled strings reach the Mac terminal unfiltered | Confirmed |
| 23 | Low | CLI | Unbounded reads of guest output into Mac memory | Confirmed |
| 24 | Low | Supply chain | Mac binaries are ad-hoc signed; the cask strips quarantine; no `-trimpath`, no checksum signing | Confirmed |
| 25 | Low | Resolver | Name-only lease match lets any vmnet VM win resolution and hold it; auth refuses it but the resolver never demotes it | Confirmed |
| 26 | Info | Design | Unauthenticated mode (no secret on either side) admits any host-netns process on guest loopback | Confirmed, design-accepted |
| 27 | Info | Design | An authenticated Mac peer can own the `'D'` pool, replace `'R'`, and flap `'M'` | Confirmed, by design |
| 28 | Info | Misc | Introspection payload reveals the installer's home path to every staff user; daemon log is 0644; `/Users/nxc` in fixtures and docs | Confirmed |

### 1. Gateway rewrite is not netns-scoped (High, confirmed)

- [loader.go:50-54](../internal/bpf/loader.go) attaches `connect4/6`,
  `sendmsg4/6`, `recvmsg4/6`, `getpeername4/6` at `/sys/fs/cgroup`, so every
  container cgroup is covered.
- [loopback_gw.c:114-131](../internal/bpf/c/loopback_gw.c) decides on
  `dst == 127.0.0.1`, `guest_ports`, `mac_ports` only. No netns, cgroup, or uid
  check. The tracker has `in_host_netns` on every path
  ([tracker.c:202,226](../internal/bpf/c/tracker.c)); the gateway does not.
- Scenario: Mac runs Postgres on 5432. A bridged container runs its own
  Postgres on 127.0.0.1:5432 and an app that dials it. The container's listener
  is correctly absent from `guest_ports`; `mac_ports` has 5432; the connect is
  rewritten to 127.0.0.2:5432 inside the container's netns, where nothing
  listens. Result: `ECONNREFUSED` for intra-container loopback on every port the
  Mac holds. Same for compose sidecars and kind/k3d pods. UDP `sendto` is
  redirected the same way.
- Not a confidentiality issue (127.0.0.2 in the container netns reaches
  nothing), but it is the AGENTS.md invariant "anything hooked on kernel-global
  functions must be netns-scoped" applied to the tracker and not to the gateway.
- Fix direction: `volatile const __u64 host_netns_cookie` in `loopback_gw.c`,
  early return in `handle_v4/v6` when `bpf_get_netns_cookie(ctx)` differs
  (helper exists for `cgroup/sock_addr` since 5.8). Agent sets it from
  `getsockopt(SO_NETNS_COOKIE)` the way `host_netns_inum` is set today. Needs
  `just gen` + `just test-guest` and a harness leg with an `unshare -n`
  listener on a Mac-held port.

### 2. Agent exit turns `bind()` into `ENOSYS` in running containers (High, confirmed semantics)

- runc hands the only notify-fd reference to the agent and closes its own
  ([ociseccomp.go:106](../internal/agent/ociseccomp.go), docs/oci-hook.md).
  When the agent's copy closes (crash, `systemctl restart`, `just agent-up`,
  `drawbridge up` re-provision, the thread-limit abort in finding 4), the
  kernel's `seccomp_notify_release` clears `filter->notif`, and
  `seccomp_do_user_notification` returns `-ENOSYS` for every later `bind()` in
  that filter. `Restart=on-failure` brings the agent back but cannot re-attach
  to existing filters.
- Every `--network host` container started under the wrapper is affected for
  its whole life. The docs say the only added failure mode is a start racing an
  agent crash (docs/oci-hook.md:224); `ENOSYS` does not appear anywhere in docs.
- Fix direction: keep the notify fds alive across restarts with systemd's fd
  store (`FileDescriptorStoreMax=` in the unit plus
  `sd_pid_notify_with_fds`, re-adopting them on start), or document the
  limitation and make `drawbridge up` warn when it is about to restart the agent
  with arbitrated containers running.

### 3. Static proofs are replayable by a host-network container (Medium, confirmed)

- [transportauth.go:147-154](../internal/transportauth/transportauth.go): the
  proof is `HMAC(secret, label || frame)`, identical for every conn of the same
  type and direction. docs/transport-auth.md §4 justifies this with "there is
  no passive observer position in this topology short of root/kernel
  compromise".
- A `docker run --network host` container shares the host netns and, with
  Docker's default capability set, holds `CAP_NET_RAW`. An `AF_PACKET` socket on
  `lo` (forwarder path: sshd dials 127.0.0.1:4777) or on the vzNAT NIC (direct
  path) sees every Mac hello. [listen.go:181](../internal/agent/listen.go)
  admits loopback unconditionally, so the replay passes the source allowlist.
- What the replay buys is everything the Mac can do (finding 27): park 32 `'D'`
  conns and receive every guest connect to a Mac-mirrored port, replace the
  `'R'` conn and answer `inuse` to every arbitrated bind, kick the `'M'` session
  and poison `mac_ports` with any port (including 4777, redirecting sshd's own
  forwarder dial).
- Marginal gain is bounded: a process with `CAP_NET_RAW` in the host netns can
  already sniff every loopback flow in plaintext and inject raw packets. The
  replay turns that into a clean application-level control channel. The real
  defect is the premise: host-network containers are the adversary the whole
  seccomp and netns design defends against, and the transport-auth doc declares
  them a non-observer.
- Fix direction: a nonce on the long-lived types (`'D'`, `'M'`, `'R'`) via the
  reserved `auth=2` scheme closes the high-value replays without the per-`'S'`
  round trip the doc rejected; `'S'` can stay static (its payload is Mac-chosen).
  At minimum, rewrite §1/§4 of transport-auth.md to state that a host-network
  container with `CAP_NET_RAW` is a passive observer and what it can do.

### 4. Thread and fd exhaustion through the 0666 notify socket (Medium, confirmed)

- [main_linux.go:169](../cmd/drawbridge-agent/main_linux.go) makes
  `/run/drawbridge-notify.sock` 0666. [notify.go:33-55](../internal/agent/notify.go)
  accepts any fd and starts `superviseNotify`, which blocks in `unix.Poll(…, -1)`
  ([seccomp.go:206](../internal/seccomp/seccomp.go)): a raw blocking syscall that
  pins one OS thread per fd with no timeout.
- A pipe read end never reports `POLLIN` or `POLLHUP`. Ten thousand handoffs of
  one pipe (one short connection each) pin ten thousand threads and Go aborts the
  process with `program exceeds 10000-thread limit`. With finding 2 that is "any
  unprivileged guest process breaks `bind()` in every host-network container".
- Also: [notify.go:47-54](../internal/agent/notify.go) uses `fds[0]` only; extra
  fds in the first control message and every later one are never closed. The OCI
  path closes extras correctly ([ociseccomp.go:99-103](../internal/agent/ociseccomp.go)).
- Legitimate load has the same shape: each `docker exec` into an arbitrated
  container installs a filter with the same `listenerPath`, so each exec pins a
  thread for its lifetime.
- Who can reach the socket: any process in the guest. Containers only if
  `/run` is bind-mounted. On a single-user Lima VM the unprivileged user has
  passwordless sudo anyway, so this is robustness more than privilege.
- Fix direction: validate the fd is a seccomp listener before parking it
  (`SECCOMP_IOCTL_NOTIF_ID_VALID` with id 0 returns `ENOENT` on a real one,
  `ENOTTY` otherwise); close every fd beyond the first; cap supervised fds;
  one epoll loop instead of a blocking `Poll` per fd. Consider whether the
  probe socket needs to be 0666 at all now that production uses the 0600 OCI
  path.

### 5. Wrapper overwrites an existing `listenerPath` (Medium, confirmed)

- [mutate.go:92-121](../internal/ociruntime/mutate.go) (`seccompOf`) inspects
  only rules that name `bind`. A profile with `SCMP_ACT_NOTIFY` on other
  syscalls and its own `listenerPath` passes, and [mutate.go:69-70](../internal/ociruntime/mutate.go)
  replaces `listenerPath` and `listenerMetadata`. The user's notifications now go
  to drawbridge.
- [notify.go:97-154](../internal/agent/notify.go) `answerBind` never checks
  `nf.Nr`: every non-bind notification is read as a sockaddr and answered
  `CONTINUE` (or `EADDRINUSE` if the bytes parse). A notify-based deny policy
  silently becomes allow. This is the "never weaken a container's seccomp
  profile" invariant, violated for the (rare) user who already runs a seccomp
  agent.
- Fix: refuse injection when `sec["listenerPath"]` is non-empty or any rule has
  `SCMP_ACT_NOTIFY`; in `answerBind`, `nf.Nr != bind` ⇒ `CONTINUE` without
  reading target memory.

### 6. UDP mirror reply path writes to any loopback destination (Medium, confirmed)

- [udp.go:110-114](../internal/mirror/udp.go): `udpframe.ReadFrame` returns the
  peer AddrPort from the guest's frame header, and `m.uc.WriteToUDPAddrPort`
  sends to it from the root-owned socket bound to `127.0.0.1:<mirrored port>`.
  The Mac keeps no flow table, so nothing checks the peer ever sent anything.
- An authenticated (or replaying, finding 3) guest with any mirrored UDP port
  can inject arbitrary payloads into any loopback UDP socket on the Mac with
  source `127.0.0.1:<mirrored port>`. The reverse TCP/UDP path is bounded to
  advertised ports ([sync.go:551](../internal/macsync/sync.go)); this path is
  the one unbounded write primitive left.
- UDP mirroring requires the daemon's `-udp` list, so the surface is opt-in.
  Whether a 127.0.0.1-bound socket can emit to a non-loopback address on macOS
  was not tested; a `peer.Addr().IsLoopback()` check costs nothing.
- Fix: per-mirror table of peers seen inbound with expiry (the relay already
  has one, [relay.go](../internal/udpframe/relay.go)), drop frames for unseen
  peers.

### 7. `/proc/net` seed under-counts and leaks (Medium, confirmed)

- [agent.go:102-115](../internal/agent/agent.go) `seed()` puts
  `guest_ports[k]=1` for every `/proc/net/{tcp,udp}*` listener with no `sk_keys`
  entry. At teardown [tracker.c:226-234](../internal/bpf/c/tracker.c) falls
  back to `fill_key`, which fails once `skc_num` is zero, and the project's own
  finding (plan.md) is that ephemeral-port TCP listeners have their port
  cleared before `inet_csk_listen_stop` runs.
- Scenario: agent restarts while a Go server holds a `:0` listener. On close,
  the entry stays at 1 forever, no `DEL` event, the Mac mirror stays up until
  the next agent restart; a later Mac listener on that port is never gatewayed.
- Second effect: a seeded `SO_REUSEPORT` group of N workers gets count 1, so the
  first worker close deletes the key and emits `DEL` while N-1 still listen.
- Fix: track which keys came from `seed`, re-scan `/proc/net` periodically and
  reconcile seeded-only keys that vanished; or count rows per key when seeding.

### 8. Secret staged world-readable in guest `/tmp` (Medium, confirmed)

- [guest.go:190-201](../cmd/drawbridge/guest.go) `writeFile` stages the
  64-hex secret with `dd of=/tmp/drawbridge-stage-…` as the unprivileged ssh
  user ([guest.go:88-98](../cmd/drawbridge/guest.go)); `dd` creates the file
  under the user's umask (0644 on Ubuntu and FCOS) and only the destination
  gets `install -m 0600`. The deferred `rm -f` is best-effort
  ([guest.go:77-79](../cmd/drawbridge/guest.go)); an interrupted `up` leaves
  the copy in `/tmp` indefinitely.
- Any non-root guest process, or a container with `/tmp` bind-mounted, can read
  it in the window or after an abort. Tests pin `install -m 0600`
  (`secret_test.go:54`) but not the staging mode.
- The pre-create swap race is blocked by `fs.protected_regular` on both guest
  distros (suspected, not tested).
- Fix: `mkdir -m0700` a private staging dir first (one argv word, so it keeps
  the single-word rule), `dd` into it, and run the cleanup inside the same
  `sudo -n sh` script as the install so it is not a separate best-effort trip.

### 9. `install` orders its refusals after its side effects (Medium, confirmed)

- [install.go:69-74](../internal/install/install.go) boots out the loaded job,
  then [install.go:79](../internal/install/install.go) calls `ensureRootDir`,
  which does `MkdirAll` → `Chmod` → `Chown(0,0)` and only then
  `checkSecurePath` ([install.go:241-253](../internal/install/install.go)).
- On an Intel-Homebrew layout (`/usr/local` user-owned) the check correctly
  refuses, but by then the previously installed daemon is booted out and not
  re-bootstrapped (mirroring stops until reboot), and `/usr/local/libexec` has
  been chowned to root:wheel. If a non-root user had planted that path as a
  symlink, `Chmod`/`Chown` follow it before the walk refuses. No escalation
  (the parent fails `secureDirInfo`), but the "refuse without side effects"
  promise is not kept.
- Fix: run `checkSecurePath` on the parent and `Lstat` the leaf before
  mutating; move the bootout after every refusable precondition, or
  re-bootstrap the old plist on failure.

### 10. Stray Linux ELF committed at the repo root (Medium, confirmed)

- `drawbridge-runc` at the repo root is tracked (mode 100755, blob `c9bb916`),
  added in `e0e67d0`, a 3.7 MB static aarch64 Go executable. `.gitignore`
  ignores `/drawbridge` and `/drawbridged` but not `/drawbridge-runc`.
- A public repo now carries an opaque, unreproducible root-run binary with no
  provenance. It is not what goreleaser ships, but it is what every clone gets
  and what scanners flag.
- Fix: `git rm --cached drawbridge-runc`, add `/drawbridge-runc` to
  `.gitignore`. The blob stays in history.

### 11. Committed BPF objects have no regeneration check (Medium, confirmed)

- `internal/bpf/{loopbackgw,tracker}_bpfel.o` are tracked and embedded into the
  agent, which loads them as root in every guest. CI explicitly never runs
  `just gen` ([ci.yml:77-80](../.github/workflows/ci.yml)) and nothing compares
  the objects to the `.c` sources. Generation uses an unpinned `clang` from
  `apt` in the dev VM with `-g`, so the objects are not reproducible.
- Scenario: a PR, or a compromised maintainer machine, changes an `.o` without
  touching the `.c`; nothing notices.
- Fix: a Linux CI job that pins clang, runs `go generate ./internal/bpf/`, and
  fails on `git diff --exit-code internal/bpf/`; or at minimum fail when a
  `.o` changes in a commit whose `.c` does not.

### 12. Accept loops die on the first error (Medium, confirmed)

- [transport.go:58-66](../internal/agent/transport.go), [notify.go:23-31](../internal/agent/notify.go),
  [ociseccomp.go:47-55](../internal/agent/ociseccomp.go), [control.go:35-43](../internal/agent/control.go),
  [tcp.go:30-40](../internal/proxy/tcp.go): `Accept()` error ⇒ `return`.
  Go surfaces `EMFILE`/`ENFILE` from `Accept`, so any fd-pressure event (finding
  4, a loopback conn flood, a proto-17 peer with thousands of flows) kills the
  listener for the life of the process while systemd sees it as active.
- Fix: the standard temporary-error backoff loop (`net/http`'s `Serve` pattern).

### 13. Root reads a user-owned secret without checks (Low, confirmed, partly design-accepted)

- [transportauth.go:80-93](../internal/transportauth/transportauth.go) is a bare
  `os.ReadFile` (follows symlinks, no owner or mode check), re-read per dial by
  the root daemon. The file is user-owned 0600 in a 0700 dir
  ([up.go:408-418](../cmd/drawbridge/up.go)).
- Same-uid consequences: (a) a symlink to a root-only file yields
  `want 64 hex characters, got N` in the 0644 daemon log, a byte-length oracle;
  (b) a same-uid process can rewrite the secret, bind 127.0.0.1:4777 while the
  VM is down (the resolver falls back to the forwarder,
  [limaaddr.go:163-169](../internal/limaaddr/limaaddr.go)), and become root's
  "agent": root then binds any loopback port below 1024 on its word.
- docs/transport-auth.md §1 declares a same-user process a non-adversary. That
  covers secret confidentiality, not the sub-1024 bind capability. On a
  single-user dev Mac this is the user's own foot; on a shared Mac it is a
  conscious acceptance worth stating.
- Fix: `Lstat` and refuse symlinks, non-regular files, mode wider than 0600, or
  an owner other than the recorded install uid; log loudly when an installed
  daemon resolves to `ssh-forwarder`.

### 14 to 25. Low findings

- **14** [mirror.go:294,624](../internal/mirror/mirror.go): `json.NewDecoder(conn)`
  with no `io.LimitReader` on `'E'` and `'R'`; an authenticated guest can OOM the
  root daemon with one multi-GB value (KeepAlive restarts it). The guest side
  has the same shape on `'M'` and the OCI socket's `io.ReadAll`
  ([ociseccomp.go:84](../internal/agent/ociseccomp.go)).
- **15** [limaaddr.go:316-324](../internal/limaaddr/limaaddr.go): `exec.Command("limactl", …)`
  with no euid guard, called by the root daemon at every re-resolve. Under
  launchd the PATH is safe; under `sudo drawbridged` from a shell (macOS sudoers
  has no `secure_path`) root execs whatever `limactl` is first on the sudoer's
  PATH. Contradicts the AGENTS.md rule that root touches only `ParseRef`.
  Same pattern for `launchctl` ([install.go:344,352,382](../internal/install/install.go))
  and `netstat`/`arp`/`systemextensionsctl` in doctor. Fix: `os.Geteuid()==0`
  early return in `guestIP`; absolute paths for the system tools.
- **16** [main.go:234-247](../cmd/drawbridge/main.go) warns that the daemon
  "will run UNAUTHENTICATED until `drawbridge up`"; the plist always renders
  `-secret-file`, so the daemon hits `log.Fatalf`
  ([main.go:116-119](../cmd/drawbridged/main.go)) and launchd restarts it every
  10 s. Fail-closed is the right behavior; the message and `waitRunning`'s
  success report are wrong. No test pins either.
- **17** [main_linux.go:138-144](../cmd/drawbridge-agent/main_linux.go): the
  control socket has no explicit `Chmod` (the other two do). Under umask 022 it
  is 0755 root, so connect needs root; a looser umask hands `add-mac-port` with
  an arbitrary backend to any local user. One line.
- **18** [tracker.c:211-217](../internal/bpf/c/tracker.c): lookup-miss then
  `update(BPF_ANY)` with 1 lets two first-listeners on two CPUs both write 1;
  [tracker.c:241-243](../internal/bpf/c/tracker.c): sub-to-zero then delete
  lets an add in between be erased. Update return is ignored, so a full map
  (16384 keys, every bound UDP socket counts) emits `ADD` with no entry and then
  never emits `DEL`. Fix shape: `BPF_NOEXIST` then re-lookup and `fetch_add`;
  check the return before `emit`.
- **19** [tracker.c:159](../internal/bpf/c/tracker.c): `a[0]==0xFD && a[1]==0x77 && a[15]==2`
  matches every `fd77:xxxx:…::2`, a legitimate ULA. Compare all 16 bytes.
- **20** [seccomp.go:243-249](../internal/seccomp/seccomp.go): `ReadAt` on
  `/proc/<pid>/mem` at an attacker-chosen pointer; a FUSE- or
  userfaultfd-backed page can sleep the supervisor loop for that fd forever,
  pinning a thread and skipping `defer Close`. Contradicts "never block between
  receiving a notification and answering it". Suspected: needs FUSE or the
  `unprivileged_userfaultfd` sysctl. Fix: bounded read (goroutine plus
  timeout, timeout ⇒ CONTINUE).
- **21** [provision.go:125-128,161-167](../internal/guestbin/provision.go): when
  `runtimes.drawbridge` exists with a different path and `default-runtime` is
  already set, `AddedRuntime=false` and the function returns `existing`
  unchanged, so docker keeps exec'ing the old path and the state file records no
  change. The surgical revert also never restores a user's own overwritten
  entry.
- **22** `handoff`, `provisionOCIDocker`, `enableAgent`, and doctor's text
  renderer print guest-sourced strings with no control-character filter
  ([up.go:759-766,637-638,545-546](../cmd/drawbridge/up.go)). A compromised
  guest can emit OSC/ANSI sequences (title set, OSC 52 clipboard write on
  terminals that allow it). `doctor -json` is safe. Fix: strip `< 0x20` except
  `\n`/`\t` at the `guest.sh` boundary.
- **23** `vmprovider` returns `cmd.Output()` whole; `readFile` `cat`s guest
  files into memory; `Merge` stores daemon.json verbatim in provision.json. A
  hostile guest can make `up`/`down`/`doctor` allocate arbitrarily. The
  introspection client is bounded (1 MiB). Fix: `head -c` in the scripts or
  `io.LimitReader` at the provider seam.
- **24** [.goreleaser.yaml:164-168,194-207](../.goreleaser.yaml): ad-hoc
  signing only, cask strips `com.apple.quarantine` in postflight, so the whole
  integrity chain is GitHub TLS plus the sha256 in the cask. No `-trimpath`, no
  `signs:` block, no attestation. `sudo drawbridge install` then copies that
  binary to a root path with no digest check. Documented as out of scope
  (docs/ergonomics.md); worth one sentence in the README's threat model.
- **25** Default install does not pin `-vm-mac`; `leaseCandidatesFrom` sorts
  newest-expiry first and `ResolveTarget` takes the first TCP-accepting
  candidate. Auth refuses the wrong peer, but the resolver never demotes it, so
  any other vmnet VM on the Mac can deny service until the MAC is pinned.

### 26 to 28. Info

- **26** Unauthenticated mode: with no secret on either side,
  [handshake.go:121-126](../internal/transportauth/handshake.go) admits any
  loopback dialer, which includes every `--network host` container and every
  guest process. They can then do everything in 27. `drawbridge up` always
  provisions a secret, so this is the dev flow only (`just agent-up` without
  `up`), and the agent logs it loudly at boot. Deleting the guest secret as
  root reopens it. Recorded so the dev-flow posture is explicit.
- **27** An authenticated Mac peer owns the agent: it can park all 32 `'D'`
  conns and receive every guest connect to a Mac-mirrored port
  ([dialpool.go:45-63](../internal/agent/dialpool.go)), replace the `'R'` conn
  and answer `inuse` to every bind ([reserve.go:33-42](../internal/agent/reserve.go)),
  and kick the `'M'` session, tearing down every Mac-owned proxy
  ([macsync.go:52-56](../internal/agent/macsync.go)). Conversely an
  authenticated agent can make root bind any free loopback port on the Mac with
  no cap on mirror count. Both are the design's trust model; they matter only
  via findings 3 and 13.
- **28** The introspection payload includes `SecretPath` and the socket is
  0660 root:staff, so every console user learns the installer's username and
  VM. The daemon log is 0644. `/Users/nxc` appears in `internal/vmprovider/testdata/*.json`
  and several docs. No tokens, keys, or credentials anywhere in the tree or in
  any reachable history. `govulncheck` was not run (not installed; installing
  needs the network).

## Checked and found sound

- **Install**: constant root-owned paths; temp file, chown, chmod, rename in a
  directory `checkSecurePath` walked from `/`; plist values allowlisted
  (`ParseRef` grammar, MAC and subnet regexps, loopback-TCP-only agent pin,
  secret path with XML metacharacters and control characters rejected); the
  running root daemon never reads the user's podman record.
- **Transport auth**: every conn type awaits the agent proof before trusting a
  byte on both sides; `hmac.Equal`; deadlines cleared before parking; exactly
  36 bytes read pre-auth under a 5 s deadline; unknown auth byte and reserved
  bytes close pre-dispatch; refusal logs throttled per (cause, source) with map
  pruning; secret never in argv, env, logs, or the introspection payload;
  `Secret.String()` redacts; malformed fails closed at boot and per conn.
- **Agent bind scope**: `auto` binds 127.0.0.1 plus the discovered vzNAT
  address only, bridge gateways excluded; source allowlist drops strangers
  before any byte; wildcard needs an explicit flag.
- **Reverse path bounds**: `handleStream` dials only advertised ports, set
  primed before any pool loop; mirror bind address is loopback-only under root
  with no override; UDP frames bounded at 65507 with flags and port checked;
  relay flow table capped at 4096 with idle sweep.
- **Seccomp supervisor**: `IDValid` after every target-memory read and before
  the Mac RPC; netns gate with error ⇒ CONTINUE; `SO_TYPE`+domain
  classification; Tgid fallback for non-leader TIDs; sockaddr length bounded;
  poll-first loop with HUP as the only exit. The TOCTOU on sockaddr and fd
  (another thread rewrites after the read) is inherent to seccomp-notify and
  bounded to a 10 s Mac-side reservation of the attacker's own port.
- **OCI handoff**: 0600, chown-then-chmod, unresolvable owner fatal;
  `seccompFd` index validated; extra fds closed; malformed JSON closes all fds.
- **Wrapper decision function**: refuses any non-ALLOW bind action, any bind
  `args`, and deny-by-default profiles with no bind rule; strips `bind` so the
  notify rule is the sole match; skips private netns and the opt-out
  annotation; probes the agent before writing; atomic rename; `Pick` excludes a
  probe path that resolves to itself; env overrides are engine-owned.
- **Tracker**: `in_host_netns` on every add and del path before any state
  change; `port_key` byte-identical across both objects with explicit padding;
  `sk_keys` honored for tracker-added sockets; shared `guest_ports` via
  `MapReplacements`; no `bpf_printk`; GPL-compatible license; nothing pinned,
  so SIGKILL detaches everything; `AddMacPort` is proxy-first and
  `RemoveMacPort` map-first.
- **Gateway matching**: exact 127.0.0.1, `::ffff:127.0.0.1`, `::1`; TCP and
  UDP only; port 0 skipped; stateless un-rewrite with no per-flow maps; a
  squatter on 127.0.0.2:P only makes `AddMacPort` fail, never writes
  `mac_ports` without a live listener.
- **Provider shell**: every `Shell` argv is a constant single word, checked at
  runtime and by the fake guest; scripts ride stdin; Mac-side values in scripts
  are constants through `shquote`; no Mac-side `sudo` is ever spawned;
  `up`/`down`/`doctor` refuse euid 0 at the provider seam.
- **`down`**: no state file ⇒ no write; version dispatch before decode; exact
  restore only on digest match; drop-in removed only on digest match with the
  real crun fallback always rendered; `reset-failed` before every engine
  restart with explicit markers.
- **Supply chain**: every `uses:` SHA-pinned; minimal `permissions`; no
  `pull_request_target`; no event-data interpolation into `run:`; secrets
  scoped to the goreleaser step; release and guest binaries built in one job
  from one commit; `all:bin` embed; `go.mod` has no `replace`, no forks;
  `go mod verify` clean; bpf2go pinned via `tools.go`; no pipe-to-shell
  installers; the Mac never executes guest-produced content.

## Recommended order of work

1. **Finding 1** (gateway netns cookie): one BPF variable, one helper call, one
   harness leg. The only finding that breaks ordinary workloads today.
2. **Finding 2** (fd store or documented restart warning) together with
   **4** and **12** (fd validation, close extras, accept backoff): these three
   combine into "any guest process breaks bind in every host-net container".
3. **Finding 5** (refuse on existing `listenerPath`; `nf.Nr` check): small and
   it is a stated invariant.
4. **Findings 10 and 11** (remove the stray ELF; BPF regen check in CI):
   cheap, public-repo hygiene.
5. **Finding 3**: decide whether to add a nonce on `'D'`/`'M'`/`'R'` under
   `auth=2`, or rewrite the threat model. Either way the docs should stop
   claiming no passive observer exists.
6. **Findings 6, 7, 8, 9**: each is a contained change in one file.
7. The Lows as a hardening pass: 13, 14, 15, 17, 18, 19 are each a few lines.
