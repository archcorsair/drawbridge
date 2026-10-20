# Audit follow-up: high-priority fixes

Source: [docs/security-audit-2026-10-18.md](../security-audit-2026-10-18.md).
This plan covers the two High findings (1, 2) and the three Mediums that share
their failure chain or files (4, 12, 5). Everything else in the audit stays
where it is.

Rules for whoever works this:

- Read AGENTS.md first. Kernel-hook changes need `just gen` and
  `just test-guest` in the VM; nothing in `internal/bpf/c/` is done until both
  pass. If the VM cannot be run in your session, implement, run the Mac-side
  unit tests, and mark the in-guest leg "needs guest run" in the tracker rather
  than claiming it passed.
- One commit per item, Conventional Commits, no AI attribution lines.
- Keep every existing invariant in AGENTS.md. Several are directly in play:
  the seccomp supervisor must always answer and never block; poll-first notify
  supervision; never weaken a container's seccomp profile; anything hooked on
  kernel-global functions must be netns-scoped.
- Update the tracker at the bottom of this file as you go. The reviewer reads
  the tracker, then the diff.

## Item 1: netns-scope the gateway (audit finding 1, High)

**Problem.** `loopback_gw.c` is attached at the root cgroup
([loader.go:50-54](../../internal/bpf/loader.go)) and `handle_v4`/`handle_v6`
([loopback_gw.c:114-131, 179-207](../../internal/bpf/c/loopback_gw.c)) decide
on destination and the two port maps only. A bridged container's connect to its
own `127.0.0.1:P` is rewritten to `127.0.0.2:P` inside its netns whenever the
Mac holds P, so it gets `ECONNREFUSED`. The tracker already gates on
`host_netns_inum` ([tracker.c:202, 226](../../internal/bpf/c/tracker.c)); the
gateway does not.

**Change.**

1. In `loopback_gw.c`, add `volatile const __u64 host_netns_cookie;` and at the
   top of `handle_v4` and `handle_v6` return 1 (pass through) when
   `bpf_get_netns_cookie(ctx) != host_netns_cookie`. The helper is available
   to `cgroup/sock_addr` programs since kernel 5.8; the guest is 6.8. Apply
   the same gate to the `recvmsg`/`getpeername` un-rewrite hooks so the
   program set stays symmetric (an un-rewrite in a foreign netns is harmless
   but should not run).
2. In the Go loader (`internal/bpf/loader.go`), read the agent's own cookie
   with `getsockopt(SOL_SOCKET, SO_NETNS_COOKIE)` (`unix.GetsockoptUint64`,
   kernel 5.14+) on any socket and set it through `spec.Variables` exactly as
   `tracker_loader.go:43-49` sets `host_netns_inum`. A cookie of 0 is never
   valid; fail the load if the getsockopt fails rather than attaching an
   unscoped gateway.
3. `just gen`, commit the regenerated objects and bindings together with the
   `.c` change.

**Verify.**

- `just test-guest` green.
- New harness leg in `internal/harness`: inside `unshare -n` (or a
  `netns`-isolated helper the harness already has for the tracker netns test),
  bring up `lo`, listen on `127.0.0.1:P` where P is also synced as a Mac port
  through the agent's control socket, connect from the same netns and assert
  the connect succeeds and reaches the local listener. Without the fix this
  leg gets `ECONNREFUSED`.
- Existing gateway legs (host-netns connects to Mac-held ports still rewritten)
  stay green.
- Optional live check: `docker run --rm --network bridge <image>` with a
  service on a port the Mac holds, `curl 127.0.0.1:P` from inside succeeds.

## Item 2: notify fds must survive an agent restart (audit finding 2, High)

**Problem.** runc hands the agent the only reference to each container's
seccomp notify fd ([ociseccomp.go:106](../../internal/agent/ociseccomp.go)).
When the agent exits for any reason, the kernel clears `filter->notif` and
every later `bind()` in that container returns `ENOSYS` for the rest of the
container's life. `Restart=on-failure` cannot re-attach. This is undocumented;
docs/oci-hook.md says the only added failure mode is a start racing a crash.

**Decide first, record the decision in the tracker.** Two acceptable outcomes:

- **(a) systemd fd store.** Add `FileDescriptorStoreMax=4096` to
  `internal/guestbin/assets/drawbridge-agent.service`. On every supervised fd
  (both the OCI path and the probe-socket path), call `sd_pid_notify_with_fds`
  (implement the `NOTIFY_SOCKET` datagram directly with `SCM_RIGHTS`; no cgo,
  `FDSTORE=1\nFDNAME=notify-<id>`). On start, read `LISTEN_FDS`/`LISTEN_FDNAMES`
  and re-adopt every `notify-*` fd into `superviseNotify`. Remove from the
  store on HUP (`FDSTOREREMOVE=1\nFDNAME=…`). This is the real fix; it makes
  `drawbridge up` re-runs and crashes transparent to running containers. The
  transient `just agent-up` unit also needs `-p FileDescriptorStoreMax=4096`
  in the justfile.
- **(b) Document and warn.** If (a) turns out to be more than a day of work or
  cannot be verified in the guest, do this instead: a section in
  docs/oci-hook.md and README "Common issues" stating the `ENOSYS` behavior
  and the remedy (restart the affected containers); `drawbridge up` and `down`
  print a warning before restarting the agent when `docker ps --filter
  network=host` (or the podman equivalent) is non-empty; `drawbridge doctor`
  gains a check that reports arbitrated containers started before the agent's
  current start time.

**Verify (either outcome).**

- Mac-side unit tests for the fd-store message encoding and the
  `LISTEN_FDS` adoption (table tests, no systemd needed).
- In-guest: start a `--network host` container under the wrapper, confirm
  `bindtry` succeeds, `systemctl restart drawbridge-agent`, run `bindtry`
  again in the same container. With (a) it succeeds and the agent log shows
  the re-adopted fd. With (b) it returns `ENOSYS` and the docs say so. Record
  which you observed.

## Item 3: harden the notify socket and the accept loops (audit findings 4 and 12, Medium)

These are the cheap crash paths that trigger item 2.

**Problem.** `/run/drawbridge-notify.sock` is 0666
([main_linux.go:169](../../cmd/drawbridge-agent/main_linux.go)).
`recvNotifyFd` ([notify.go:33-55](../../internal/agent/notify.go)) parks any
fd in `superviseNotify`, which blocks in `unix.Poll(…, -1)` and pins an OS
thread per fd; a pipe read end never returns, so ten thousand handoffs abort
the process at Go's thread limit. Extra fds in the message are never closed.
Every accept loop (`transport.go:58-66`, `notify.go:23-31`,
`ociseccomp.go:47-55`, `control.go:35-43`, `proxy/tcp.go:30-40`) returns on
the first `Accept` error, so `EMFILE` kills the listener for the process
lifetime.

**Change.**

1. Before parking an fd, prove it is a seccomp listener:
   `ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &zero)` returns `ENOENT` on a real
   listener and `ENOTTY` on anything else. Anything else: close and log once
   (rate-limited per sender).
2. Close every fd beyond the one used, on both the probe-socket path and (as
   it already does) the OCI path. Parse all control messages, not only
   `scms[0]`.
3. Cap concurrently supervised fds (a counter; refuse and close above, say,
   4096, with one log line). Keep the per-fd goroutine model; replacing it
   with epoll is out of scope.
4. Chmod the control socket `/run/drawbridge-agent.sock` to 0600 explicitly
   (audit finding 17, one line, same file).
5. Give every accept loop the standard temporary-error backoff
   (`net/http.Server.Serve` pattern: on a `net.Error` with `Temporary()`, or
   `EMFILE`/`ENFILE`, sleep 5 ms doubling to 1 s and retry; return only on a
   closed listener).

**Verify.**

- Unit tests on the Mac for the fd-cap counter and the backoff helper.
- In-guest (`internal/harness`): hand a pipe read end to the notify socket
  and assert the agent closes it and keeps serving; hand a real listener and
  assert supervision still works (existing legs).
- `go vet`, `just test-guest`.

## Item 4: never hijack an existing seccomp agent (audit finding 5, Medium)

**Problem.** `seccompOf` ([mutate.go:92-121](../../internal/ociruntime/mutate.go))
only inspects rules naming `bind`, so a profile with `SCMP_ACT_NOTIFY` on
other syscalls and its own `listenerPath` is accepted, and `MutateConfig`
overwrites `listenerPath`/`listenerMetadata`. The user's notifications then
reach `answerBind`, which never checks `nf.Nr` and answers `CONTINUE` to
anything, turning a notify-deny policy into allow.

**Change.**

1. In `seccompOf`, refuse (return a reason, no injection) when
   `sec["listenerPath"]` is a non-empty string, or when any rule's action is
   `SCMP_ACT_NOTIFY`.
2. In `answerBind` ([notify.go:97](../../internal/agent/notify.go)), if
   `nf.Nr` is not the bind syscall number for the running arch
   (`seccomp_amd64.go`/`seccomp_arm64.go` already define it), send CONTINUE
   immediately without reading target memory, and log once.

**Verify.**

- Table tests in `internal/ociruntime/mutate_test.go`: profile with
  `listenerPath` set ⇒ not injected; profile with a `SCMP_ACT_NOTIFY` rule on
  `mount` ⇒ not injected; the existing allow-profile cases still inject.
- Unit test for the `nf.Nr` gate if `answerBind` can be exercised with a fake
  (it takes an fd; a `seccomp.Notif` with a wrong `Nr` and a pipe fd whose
  `SendContinue` fails is enough to assert the early return via the log).

## Out of scope here

Audit findings 3, 6 to 11, 13 to 28. Finding 3 (static proof replay) is a
design decision the user makes; findings 10 and 11 (stray ELF, BPF regen check)
are separate hygiene commits.

## Tracker

Update the Status column as you go. Allowed values: `todo`, `in progress`,
`done`, `done (needs guest run)`, `blocked: <why>`. Put the commit hash in the
last column once committed.

| Item | Finding | Status | Decision / notes | Commit |
|------|---------|--------|------------------|--------|
| 1 | Gateway netns cookie | todo | | |
| 2 | Notify fds survive restart | todo | (a) fd store or (b) document+warn: | |
| 3 | Notify socket + accept loops | todo | | |
| 4 | listenerPath refusal + nf.Nr gate | todo | | |

Verification log (append one line per run, with date and what was run):

- 
