# Evaluation of the 2026-10-28 third-party review

Evaluation of [security-audit-2026-10-28.md](security-audit-2026-10-28.md)
(125 findings at `149b71c`). Every finding, every row of its prior-audit table
and all three of its refutations were re-derived from source by independent
verifiers, and the guest-dependent ones were run in the Lima dev VM. Nothing
in the tree was changed to produce this; this file and the report are the only
additions. The report is copied verbatim except for one redaction: the
reviewer's own checkout path in M31.

## Verdict

The review is accurate. **No finding is refuted.** 116 are confirmed (20 of
them with corrections to mechanism, scope or fix), 7 are confirmed with a live
consequence still untested, and 2 (L27, L29) need hardware this evaluation was
not cleared to use. The report's own spot claims also hold: every one of its 148
`file:line` citations resolves at `149b71c`, and H1 was reproduced again, end to
end, through a real container.

Where it is wrong, it is wrong in the details, and four of those details matter:

1. **H1's alternative fix is unsound.** Clearing `SO_REUSEADDR` on the mirror
   makes every rebind fail for about 30 s after any connection the mirror side
   closed first (TIME_WAIT, MSL 15 s on macOS).
2. **H1's "wildcard guest bind is safe" correction is wrong** (NEW-A1, live).
   The guest bind still triggers a reservation and then fails natively. For the
   10 s reservation lifetime, Mac `127.0.0.1:P` is held by a dead mirror and the
   Mac's real port is withdrawn from the guest.
3. **M3 is cheaper than stated.** One listener re-sent 4096 times fills the cap,
   because nothing deduplicates by file. After the attacker exits, the agent
   keeps about 4096 idle OS threads for the rest of its life.
4. **The report under-counts H3.** It lists 9 bare `sudo drawbridge install`
   sites; there are at least 20 (code and docs). The worst is `status` on an
   installed-but-not-loaded job (`cmd/drawbridge/render.go:84`), which tells the
   user to re-target their daemon.

Severity changes: 9 accepted from verifiers (M5, M17, M25, M26, M30, M31 to
Low; L14 to Medium; L43, L80 to Info). One verifier proposal rejected: **M28
stays Medium** (see below). Final count: High 3, Medium 26, Low 83, Info 13
(report: 3, 31, 80, 11), plus 21 new findings (7 extend existing ones) and one reinstated refutation (R1).

## How this was verified

| Step | Who | What |
|---|---|---|
| Baseline | lead | `main` = `origin/main` = `149b71c`, clean. 148/148 report citations resolve. |
| Static verification | 7 independent verifiers, one per area | Re-derived every finding from source, tried to refute it (guards elsewhere, unreachable input, documented intent, duplicates), proved test-gap claims by mutating scratch copies of packages, never the repo. |
| Mac repros | verifiers | Unprivileged, loopback only: H1 (four holder types), L23 `inp_vflag`, L32 format verbs, L73 panic, M25 chmod, M9 rendered script under sh/bash/dash. |
| Guest lab | one agent owning the VM | `just build`, `vm-docker`, `test-guest` (43 top-level tests pass, 1 skip), `agent-up`; then the recipes below. VM returned to Stopped, tree clean. |
| Toolchain | govulncheck v1.9.0 | Source mode, `GOTOOLCHAIN=go1.25.0` and `go1.26.5`, darwin and linux/arm64. |
| Upstream source | verifiers | colima v0.10.3 (`daemon.json` overwrite), Lima v2.0.3/v2.2.0 (`port.go`, `shell.go`), setup-go at the pinned SHA, kernel v5.13/v5.14/v6.8 (`sock.c`, `filter.c`, `seccomp.c`, `route.c`, `udp.c`). |
| Lead | lead | Re-read H1, H2, H3, M3, M6 and M9 against source; reviewed every verdict. |

Guest: kernel 6.8.0-147, runc 1.3.4, docker 29.1.3, lima 2.2.0.

### Guest-lab results

| Item | Result | Evidence |
|---|---|---|
| H1 | Confirmed | Container bound `127.0.0.1:18080` beside a Mac `*:18080`; Mac `127.0.0.1` reached the container, `[::1]` still reached the Mac; guest `127.0.0.2:18080` withdrawn. |
| NEW-A1 | Confirmed | Container failed with Errno 98; Mac `127.0.0.1:18080` failed for 10 s; then `reservation :18080 expired unadopted`. The agent logged `-> ok` for the bind that failed. |
| M1 | Confirmed, stays Medium | `::1`-only listener mirrored, Mac gets `Empty reply from server`. Ubuntu 24.04 resolves `localhost` to `127.0.0.1` and Node binds there, so the High case is not the default. |
| M3 | Confirmed | uid 501 sent 4100 handoffs; next container's bind returned errno 38 (ENOSYS); journal logged the OCI refusal. 4106 agent threads remained after the attacker exited. |
| M5 | Mechanism confirmed, Low | ADD dropped with the agent stopped; reconnect did not heal. A listener opened inside a 120k-record burst with the agent running was still mirrored. |
| M7 | Confirmed | Wrapper moved aside: `fork/exec /usr/local/bin/drawbridge-runc: no such file or directory`. |
| L2, L3, L15, L50, I1 | Confirmed | See per-finding table. |
| L12 | Not observed | 77.5M SIGURG over 290 s and 12.7M binds: no stuck bind, no EINTR. Semantics stand on kernel source; occurrence is rare. |
| C/NEW-1 (runc EOF) | Refuted on runc 1.3.4 | Foreground `runc exec` bind supervised in 0.026 s. runc 1.3.2 and older untested. |
| AGENTS.md lima argv rule | **AGENTS.md is wrong** | On lima 2.2.0, `printf '[%s]\n' 'a b' c` prints `[a b]`, `[c]`. Lima quotes every argv element. The space-free rule stays safe (podman still needs it). |

### M28: why it stays Medium

govulncheck, source mode, reachable call paths only:

| Toolchain | darwin | linux/arm64 | Reached from |
|---|---|---|---|
| go1.25.0 (what `release.yml` builds with) | 35 | 36 | `drawbridged` (introspect), `drawbridge`, `drawbridge-agent` (net/http, crypto/tls, crypto/x509, net/url) |
| go1.26.5 (the mise pin used in development and CI) | 15 | 15 | same, minus the 1.25-only advisories; fixed in go1.26.6 to go1.26.10 |

These are reachability results, not demonstrated exploits; neither binary
serves HTTP or TLS to an untrusted network peer. But a root daemon and a root
guest agent shipping 35 known stdlib advisories is a real, cheap-to-fix
weakness. The report's fix ("add a `toolchain` directive") does not work: the
pinned setup-go reads only the `go` line. The mise pin is stale too (NEW-T1).

## Decisions

These are the lead's calls and need no input.

- **Accepted as real:** all 125 findings, with the corrections recorded in the
  per-finding table.
- **Reinstated:** the report's refutation of doctor-checks-11 is wrong on the
  spec. Remedy 1 in check 6's tier-2 row is at best a no-op, because tier-2
  evidence exists only when a root daemon already reaches the guest. Bare, it
  re-targets the daemon (H3). Recorded as **R1, Low**, fixed together with H3.
- **The other two refutations stand.** cli-rest-4 is specified behavior.
  inv-9's code follows podman.md and doctor.md; only AGENTS.md's wording is too
  broad (escalation E8).
- **Fix directions rejected or corrected:** H1 `SO_REUSEADDR` (unsound); L4's
  test (Go's `net.Dial` to `[::ffff:127.0.0.1]` opens AF_INET, so the test must
  build the AF_INET6 socket by hand); L21 exponential backoff (delays mirroring
  after a VM start; dedupe the log line instead); L30 (`ColimaHome()` resolves
  under `/var/root` in the root daemon); M20 "treat broader as absent" (breaks
  the tested `bridge100` case; use most-specific unscoped route); M17 (check
  `command -v runc` against the wrapper's own probe list); M3 "never close"
  alone (an unsupervised fd hangs binds; OCI handoffs must be supervised past
  the cap); L17 `os.Exit` (retry everything except `net.ErrClosed`).
- **M6 is a fix to existing policy, not a design change.** "Configured but
  unreadable fails closed" is already an AGENTS.md invariant; the runtime
  re-read violates it. The same downgrade exists guest-side (NEW-A2). No
  escalation needed.
- **L5's fix must be a feature probe, not a version compare.** `SO_NETNS_COOKIE`
  landed in v5.14 (e8b9eab99232) but was queued for some 5.12.y and 5.13.y
  stable kernels. Plain `up` currently checks no kernel version at all, and the
  agent has needed 5.8 since the tracker landed (NEW-B4).

## Escalations: design calls for the owner

Each touches an AGENTS.md invariant, a wire or CLI contract, a frozen doc
contract, or the threat model. Recommendation first.

| # | Covers | Question | Recommendation |
|---|---|---|---|
| E1 | H1, NEW-A1, L23 | How bind arbitration learns that the Mac holds a port on a wildcard. | Answer in the guest first: the agent returns `inuse` when the port is already in `mac_ports` (the synced Mac set), with no Mac round trip and no reservation, which also removes NEW-A1. Mac side, as a backstop for unsynced ports: `handleReserve`/`openLocked` take a fresh listener read that keeps `inp_vflag` (shared with L23) and count only `0.0.0.0` and dual-stack `::` holders. Keep `SO_REUSEADDR`. Add the wildcard-holder e2e leg. |
| E2 | M3, L14, audit #4, C/NEW-2 | Posture of the 0666 probe socket and the supervision cap. | OCI handoffs are never refused and get their own budget. The probe socket is root-only or test-build-only in production; if kept, add a per-uid budget, `kcmp(KCMP_FILE)` dedupe and a 1 to 2 s read deadline. |
| E3 | H3, M15, M11, M22, R1, I6 | Does `install` inherit unset flags from the installed plist? | Yes. Every unset flag defaults from the installed plist, and install prints each inherited value; an explicit flag (including `""`) overrides. Accept a positional VM like `up`/`down`; reject leftovers everywhere. Every remedy is rendered as `sudo drawbridge install -vm <installed>`. Root doctor defaults to `InstalledVM()`. |
| E4 | M7, M12, M27, L52 | OCI registration drift and the `down` contract. | Do not have the agent rewrite `daemon.json` (that breaks the single-writer invariant). doctor warns when `--oci` is provisioned but not in effect (docker: `DefaultRuntime` plus wrapper present; podman: runtime path and drop-in). `down` keeps a wrapper that any registration still names, and says why. |
| E5 | M6, NEW-A2, NEW-X1 | Root daemon fallback endpoint. | Fail closed as decided above, and additionally drop the `127.0.0.1:4777` fallback for targets that do not own that forward (colima, podman). Live evidence: this Mac's root daemon targets `colima:default`; with colima stopped it dials the Lima dev VM's agent, and only the secret mismatch refuses it. |
| E6 | M19, M23, M27, L54, L59, L61, L64, NEW-F3, I10 | Amend doctor.md / tui.md where the spec, not the code, is wrong. | Approve. Notably doctor.md §5 says log lines carry no timestamp (they do), §4 check 9 conflicts with §6, and tui.md §4.1's scroll precedence is the reverse of the code. I10 edits the frozen §4. |
| E7 | M28, NEW-T1, audit #11, #24 | Release and CI toolchain posture. | `release.yml` pins `go-version` to the current 1.26 patch; bump the mise pin to at least go1.26.10; add a govulncheck job and a BPF regeneration diff job (SHA-pinned actions only); add `-trimpath`. Checksum signing stays a separate decision. |
| E8 | NEW-G1, inv-9, I1 | AGENTS.md accuracy. | Approve: rewrite the lima half of the argv rule (lima quotes; the space-free rule stays for podman and as defense); narrow inv-9 to "the root daemon never reads either; root CLI runs never read the per-VM record"; keep the NOTIF_RECV statement (it holds on 6.8) but make `TestNotifyFilterExitSemantics` actually call Recv. The 27.0b4 empty-pcblist note stays: two unprivileged reads returned listeners on 27.2, but both ran under the Claude app's attribution, not a terminal, so they do not settle it. |
| E9 | M5, L2, L35, L11 | Lows whose fix changes a recorded design. | M5: add a BPF drop counter and hub rebuild (map change), or document. L2: reject gating the un-rewrite (it breaks stateless un-rewrite); document the 127.0.0.2 limitation. L35: accept the 45 s `'E'` read deadline (makes the ping part of the wire contract). L11: synthesize `architectures` from GOARCH. |
| E10 | audit #3 | Static proof replay (open since 2026-10-18). | Unchanged: nonce under `auth=2` on `'D'`/`'M'`/`'R'`, or rewrite transport-auth.md §1/§4 honestly. Still the owner's call. |
| E11 | L27, L29, M10, M12, M16, L37, L44, L51, M9 consequence, L11, L18 | Live tests beyond the dev VM. | Approve L27 first: if bootpd records the guest-written `chaddr`, the `-vm-mac` pin is not the identity anchor AGENTS.md says it is (Medium). The rest are confirmation only. L11 and L18 need an amd64 guest. |

## New findings (not in the report)

| ID | Sev | Finding | Where |
|---|---|---|---|
| NEW-A1 | Medium | Guest wildcard bind on a Mac-wildcard port still reserves Mac `127.0.0.1:P` for 10 s and withdraws P from the guest (live). Part of H1. | `internal/mirror/mirror.go:662-681`, `cmd/drawbridged/main.go:394` |
| NEW-T1 | Low | The mise pin go1.26.5 has 15 reachable stdlib advisories (fixed in go1.26.6 to go1.26.10). Part of M28. | `mise.toml` |
| NEW-X1 | Low | Root daemon falls back to Mac `127.0.0.1:4777` for a stopped colima target and dials whatever VM holds that forward (seen live on this Mac). | `internal/limaaddr/limaaddr.go:163` |
| NEW-A2 | Low | M6's runtime downgrade also exists in the guest agent; reachable when `down`'s best-effort agent stop fails and the secret is deleted under a running agent. | `internal/agent/transport.go:83`, `cmd/drawbridge/down.go:64-66` |
| NEW-B1 | Low | Second seed race: a close between `Put` and `Hub.apply("add")` leaves a stale hub entry and Mac mirror. Part of L1. | `internal/agent/agent.go` seed path |
| NEW-B2 | Low | `autoVZNAT` binds the first qualifying address and never re-evaluates, so a pre-lease bridge or overlay wins permanently. Part of L8. | `internal/agent/listen.go:402-413` |
| NEW-E1 | Low | `up --oci` on podman overwrites `provision.json` whatever version it holds, destroying a v1 docker record. | `cmd/drawbridge/ocipodman.go:88-94` |
| NEW-E2 | Low | Lima 2.2.0 `template://docker` masks the rootful units, so `up --oci` always fails there after writing `daemon.json` and `provision.json`. Part of M16. | `cmd/drawbridge/up.go` |
| NEW-F1 | Low | Check 5 fails (exit 1) with an impossible `bridge100` remedy when no vz VM is running. Seen live. | `internal/doctor/checks.go:918-929` |
| NEW-D1 | Low | H2 also corrupts the foreground hint (`drawbridged -vm <spelling>`). | `cmd/drawbridge/up.go:800` |
| NEW-D2 | Low | `-vm-subnet 10.0.0.0/7` passes install and the daemon and admits public 11/8. Part of L26. | `internal/limaaddr/limaaddr.go:234` |
| NEW-E3 | Test gap | `up_test.go:592` asserts M9's buggy line; the fake guest never executes the script. | `cmd/drawbridge/up_test.go:592` |
| NEW-C1 | Low (plausible) | OCI supervision waits for runtime EOF; runc 1.3.2 and older never close the conn. Not reproduced on runc 1.3.4. | `internal/agent/ociseccomp.go:82` |
| NEW-G1 | Info | AGENTS.md's lima argv premise is wrong on lima 2.2.0 (live). | AGENTS.md |
| NEW-F3 | Info | doctor.md §5 says log lines have no timestamp; they do. | `docs/doctor.md` §5 |
| NEW-B3, B4 | Info | `handle_v6` v4-mapped UDP branch is dead (kernel uses sendmsg4); the 5.7 floor is the seccomp floor reused as the guest floor. | `internal/bpf/c/loopback_gw.c`, `cmd/drawbridge/guest.go` |
| NEW-E4, E5, A3, I-log | Info | No `is-active` confirmation after the `--oci` restart; stale `up.go:7-10` header; row-6 "unambiguous" comment false behind the forwarder; agent logs `-> ok` for a bind that then fails natively. | various |

## Local state on this Mac (not findings)

- `/Library/Logs/drawbridge` is `0744`, not the `0755` install sets, so
  unprivileged doctor cannot read the daemon log here.
- The Mac's `transport-secret-lima-drawbridge` (2026-07-31) and the dev VM's
  `/etc/drawbridge/transport-secret` (2026-08-01) have different dates but the
  same sha256 (corrected 2026-10-28 during the P0-6 live leg).
- The installed daemon targets `colima:default` with
  `-secret-file …/transport-secret-colima-colima`. A bare
  `sudo drawbridge install` from any upgrade instruction would re-target it
  (H3).

## Recommended order of work

1. **Before the next release** (no release contains PR #1 yet): H3 and R1 sites
   including `render.go:84` (text-only half of E3), M13, L5 (feature probe),
   L49 release note, M9 (quote the value; it breaks every rootless podman
   machine), M28/NEW-T1 (E7).
2. **H1 + NEW-A1** once E1 is decided.
3. **VM identity:** H2 (with the `ParseRef(r.Spec)` round-trip invariant
   test), then the rest of E3: M15, M11, M22, I6, NEW-D1.
4. **Fail closed:** M6, NEW-A2 (decided); NEW-X1 per E5; M3/L14 per E2.
5. **OCI lifecycle:** M7, M8, M14, M10, M16/NEW-E2, NEW-E1, then M12/M27 per E4.
6. **Data plane:** M1, M2, M4, then L20, L22, L23, L10.
7. **doctor accuracy:** M19 to M24, M27, NEW-F1, with E6's spec edits.
8. **Tests that pass whether or not the behavior exists:** L4 (corrected), L6,
   L7, L15, L36, L48, L76, I1, I3, NEW-E3, M29.

## Per-finding verdicts

Verdict words: **CONFIRMED** (re-derived, mechanism and scope as reported);
**CORRECTED** (real, with a correction noted); **+LIVE** (confirmed in code, a
live consequence untested); **NEEDS-LIVE** (not settleable without hardware
outside the dev VM); **GUEST** marks findings also reproduced in the dev VM.
Esc refers to the escalation table.

| ID | Report | Final | Verdict | Esc | Note |
|---|---|---|---|---|---|
| H1 | High | High | CORRECTED GUEST | E1 | Reproduced on the Mac and end to end in the guest. SO_REUSEADDR fix unsound; wildcard guest bind is not safe (NEW-A1). |
| H2 | High | High | CONFIRMED | - | Install line for a different VM crash-loops the root daemon. Proven by unit run and built CLI output; README colima example hits it. |
| H3 | High | High | CONFIRMED | E3 | Upgrade remedy re-targets the root daemon to lima:drawbridge. Every listed site checks out; report missed several more. |
| M1 | Medium | Medium | CONFIRMED GUEST | - | Guest ::1-only and v6-only :: listeners are mirrored, but the agent dials 127.0.0.1, so clients get an empty reply. |
| M2 | Medium | Medium | CONFIRMED | - | UDP relay flow goes deaf after one ICMP port-unreachable. Precondition-gated opt-in -udp; a better fix variant exists. |
| M3 | Medium | Medium | CORRECTED GUEST | E2 | Reproduced in the guest (errno 38). One listener re-sent fills the cap; ~4096 OS threads persist after the attacker exits. |
| M4 | Medium | Medium | CONFIRMED | - | Mac-sync wire is keyed per address on the Mac and per port on the agent, so one del withdraws a port still served. |
| M5 | Medium | Low (was Medium) | CORRECTED GUEST | E9 | Ring-buffer overflow drops listener events silently. Mechanism exact; severity overstated, since it needs more than 8192 ring records. |
| M6 | Medium | Medium | CONFIRMED | E5 | Secret file vanishing at runtime silently downgrades every dial to unauthenticated. Fix sound; changes transport-auth.md section 5 and 6 semantics. |
| M7 | Medium | Medium | CONFIRMED GUEST | E4 | down deletes both wrappers while daemon.json still names one, leaving Docker's default runtime pointing at a deleted binary. |
| M8 | Medium | Medium | CORRECTED | - | Write-before-install and stale comment confirmed. Never heals is overstated for the wrapper, true for the state record. |
| M9 | Medium | Medium | CONFIRMED | E11 | Unquoted SC=%s: the rendered script fails under sh, bash or dash with a command-not-found error, and systemctl never runs. |
| M10 | Medium | Medium | CONFIRMED +LIVE | E11 | sockOwner is set only for the podman provider, so Lima and Colima guests running rootless podman never get it. |
| M11 | Medium | Medium | CONFIRMED | E3 | A positional VM and trailing flags are silently ignored, so sudo drawbridge install myvm -print becomes a real install. |
| M12 | Medium | Medium | CONFIRMED | E4 | Colima rewrites daemon.json from colima.yaml on every start, dropping the --oci registration. Confirmed from source. |
| M13 | Medium | Medium | CONFIRMED | - | Plain up never loads or pushes the wrapper, so upgraded --oci guests keep the stale listenerPath wrapper. |
| M14 | Medium | Medium | CONFIRMED | - | Agent restart is gated on this run writing the binary. A re-run after a mid-run failure restarts nothing. |
| M15 | Medium | Medium | CONFIRMED | E3 | A re-install silently drops -vm-mac, -vm-subnet, -udp and -skip. Confirmed. |
| M16 | Medium | Medium | CORRECTED | E11 | Lima 2.1 and earlier give a false success with rootful dockerd. Lima 2.2.0 masks docker.service, so up --oci fails midway. |
| M17 | Medium | Low (was Medium) | CONFIRMED +LIVE | - | Wrapper does not probe /usr/local/bin/runc or check a version floor. Part (a) confirmed; rare on documented guests. |
| M18 | Medium | Medium | CONFIRMED +LIVE | - | Attachability accepts any vz instance, even without vzNAT. Code confirmed; not silent, since up prints NoteNoGuestIP. |
| M19 | Medium | Medium | CONFIRMED | E6 | Daemon log-tail auth evidence is not scoped to the target VM and outlives uninstall, giving a false FAIL and a misleading remedy. |
| M20 | Medium | Medium | CORRECTED | - | Check 5 accepts any broader covering route as the vmnet route. Finding correct; the fix as written regresses a tested case. |
| M21 | Medium | Medium | CONFIRMED | - | sudo doctor can never report the root-fail half of the discriminator. The tier-1 fail branch is dead code. |
| M22 | Medium | Medium | CONFIRMED | E3 | Root doctor probes the default VM, not the root daemon's VM, and the remedy has no -vm. Misdiagnoses colima and podman users. |
| M23 | Medium | Medium | CONFIRMED | E6 | Check 9 runtime alarms never change its status, so an adv-0 daemon syncing nothing still renders ok with exit 0. |
| M24 | Medium | Medium | CONFIRMED | - | Gather -timeout does not bound resolution, so doctor hangs against a wedged guest. Local evidence supports it. |
| M25 | Medium | Low (was Medium) | CONFIRMED | - | introspect.Listen chmods and chowns the parent directory of an explicit -introspect path. Needs a flag nothing shipped passes. |
| M26 | Medium | Low (was Medium) | CONFIRMED | - | Help overlay over the doctor view lets doctor keys answer first. Key-routing UX bug in a read-only observer. |
| M27 | Medium | Medium | CONFIRMED | E4 | doctor OCI classification never checks the registration is in effect. The podman half contradicts the spec. |
| M28 | Medium | Medium | CONFIRMED | E7 | Release built with go1.25.0: 35-36 reachable stdlib advisories (govulncheck). The toolchain-directive fix does not work through setup-go. Verifier proposed Low; kept Medium. |
| M29 | Medium | Medium | CORRECTED | - | smoke-sudo-oci arbitration leg can pass with the wrapper broken. Only podman --oci acceptance gate, and it gates releases. |
| M30 | Medium | Low (was Medium) | CONFIRMED | - | smoke-sudo restores the previous daemon with only -vm. Developer-only tooling, recoverable by one reinstall; overlaps M15. |
| M31 | Medium | Low (was Medium) | CONFIRMED | - | Dev Lima template mounts only the author's checkout path. Developer ergonomics only; first failure is loud. |
| L1 | Low | Low | CORRECTED | - | /proc/net seed race leaves a permanent guest_ports entry and mirror. Two sub-windows; the proposed fix covers one. |
| L2 | Low | Low | CONFIRMED GUEST | E9 | recvmsg and getpeername un-rewrite turns 127.0.0.2 peers into 127.0.0.1. Confirmed; changes the documented stateless un-rewrite design. |
| L3 | Low | Low | CONFIRMED GUEST | - | connect and sendto to 0.0.0.0:P or [::]:P skip the gateway. The v4 case is confirmed. |
| L4 | Low | Low | CORRECTED | - | No test covers the v6-API gateway paths. The gap is real, but the suggested test would not exercise it. |
| L5 | Low | Low | CORRECTED | - | Gateway needs SO_NETNS_COOKIE (5.14), but preflight, doctor and README still gate at 5.7. No supported distro kernel sits in the window. |
| L6 | Low | Low | CONFIRMED | - | fd-store send and adopt paths have no automated test, and ExtraFdsClosed claims cases it never exercises. |
| L7 | Low | Low | CONFIRMED | - | TestFramedDialConnParksSilent cannot catch loss of the pre-dispatch deadline clear. Confirmed by code reading. |
| L8 | Low | Low | CORRECTED | - | pickVZNAT first-host rule misses non-.1 gateways. Broader than stated; auth still refuses a secretless peer. |
| L9 | Low | Low | CONFIRMED | - | Control socket chmod runs after listen, and the error is ignored. Hardening only; arguably Info. |
| L10 | Low | Low | CONFIRMED | - | Park-to-waiter handoff racing pop's timeout strands a D conn. Proved. |
| L11 | Low | Low | CONFIRMED | E9,E11 | Synthesized profile omits architectures, so compat-ABI processes are killed. Confirmed by source; untestable on arm64. |
| L12 | Low | Low | CORRECTED (not observed live) | - | EINTR from NOTIF_SEND or NOTIF_ID_VALID is final, so the bind is never answered. Semantics settled by kernel source. |
| L13 | Low | Low | CONFIRMED | - | Injected listener takes the container's one-listener-per-chain slot. Confirmed on kernel 6.8; the opt-out annotation works around it. |
| L14 | Low | Medium (was Low) | CONFIRMED | E2 | Probe-socket handoff read has no deadline. Confirmed; proposed Medium because it shares M3's precondition. |
| L15 | Low | Low | CONFIRMED GUEST | - | Per-ABI bind fix is pinned only at the table level. Confirmed statically; linux tests cannot run on the Mac. |
| L16 | Low | Low | CONFIRMED | - | Notification received but unanswered at agent exit is never re-delivered. Confirmed from v6.8 source; not exercised live. |
| L17 | Low | Low | CONFIRMED | - | acceptloop ends silently on non-Temporary errors, and callers drop Serve's error. Confirmed. |
| L18 | Low | Low | CONFIRMED | E11 | i386 socketcall(SYS_BIND) is missing from the per-ABI table. Confirmed by source; untestable on arm64. |
| L19 | Low | Low | CONFIRMED | - | Proxy Close waits out an uninterruptible backoff sleep while holding a.mu. Reachable only during fd exhaustion. |
| L20 | Low | Low | CORRECTED | - | Root daemon mirror accept loop exits on the first error. Go raises RLIMIT_NOFILE at start, so EMFILE needs heavy load. |
| L21 | Low | Low | CORRECTED | - | Reconnect loops log every failure at about 1 Hz. The stated fix is unsound; a better direction is given. |
| L22 | Low | Low | CONFIRMED | - | bind-failed and skipped observations never expire. Confirmed; the proposed fix is incomplete. |
| L23 | Low | Low | CONFIRMED | E1 | v6-only [::] Mac listener is synced as 0.0.0.0. Confirmed; fix verified live. |
| L24 | Low | Low | CORRECTED | - | Non-literal -mirror-ip makes UDP mirrors bind all interfaces. Unprivileged daemon only; arguably Info. |
| L25 | Low | Low | CORRECTED | - | udpStreamProxy dials while holding p.mu. Lives in guest agent code, not the Mac daemon. |
| L26 | Low | Low | CORRECTED | - | ParseSubnet validates the unmasked address but returns the masked prefix. Reaches further: -vm-subnet 10.0.0.0/7 is accepted. |
| L27 | Low | Low | NEEDS-LIVE | E11 | MAC pin may trust a guest-written chaddr. If true, the AGENTS.md trust claim fails and severity rises to Medium. |
| L28 | Low | Low | CORRECTED | - | guestIP runs limactl with no timeout while the resolver holds its mutex. Scope is narrower than the wording. |
| L29 | Low | Low | NEEDS-LIVE | E11 | podmanaddr cannot tell a dead agent from a live one behind gvproxy. Code-level half confirmed; behavior needs a live check. |
| L30 | Low | Low | CONFIRMED | - | Name-only lease warning gives colima users a limactl command that cannot find their instance. Proposed fix direction is wrong under launchd. |
| L31 | Low | Low | CONFIRMED | - | vmrecord.Write truncates in place. Confirmed; the window is tiny. |
| L32 | Low | Low | CONFIRMED | - | Secret redaction covers Stringer verbs only. Confirmed. |
| L33 | Low | Low | CONFIRMED | - | 'M' publishes adds before updating the advertised set. Confirmed; the window is microseconds. |
| L34 | Low | Low | CONFIRMED | - | Row-6 diagnosis fires for an agent that is simply down behind a forwarder. Fix sound but incomplete. |
| L35 | Low | Low | CONFIRMED | E9 | Mac never enforces the agent's 15 s 'E' ping. Enforcing a read deadline makes the ping part of the 'E' wire contract. |
| L36 | Low | Low | CONFIRMED | - | TestRootDoesNotReadThePodmanRecord never runs its euid-0 branch. It pins an AGENTS.md rule. |
| L37 | Low | Low | CONFIRMED +LIVE | E11 | Restart is gated on drop-in bytes changing, so a second podman machine's new wrapper never bounces its API service. |
| L38 | Low | Low | CONFIRMED | - | Root installs /tmp-staged bytes with no digest recheck. Exploit needs a second guest uid, which protected_regular mostly blocks. |
| L39 | Low | Low | CONFIRMED | - | Surgical Revert with nothing to undo reformats, reports restored, and restarts docker. Confirmed by harness. |
| L40 | Low | Low | CONFIRMED | - | Podman restart-failure remedy hardcodes systemctl --user, which is wrong for rootful machines. Info is defensible. |
| L41 | Low | Low | CONFIRMED | - | Version 0 falls through to the docker revert. Confirmed by harness. |
| L42 | Low | Low | CONFIRMED | - | Default status hides the installed launchd daemon when another daemon answers. Confirmed. |
| L43 | Low | Info (was Low) | CONFIRMED | - | Usage text says --oci is not available on podman machines. Stale help text, cosmetic; proposed Info. |
| L44 | Low | Low | CONFIRMED +LIVE | E11 | Podman machine dir hardcodes ~/.config. Podman on macOS honoring XDG_CONFIG_HOME needs a live check. |
| L45 | Low | Low | CONFIRMED | - | Lima rule model diverges from hostagent. Confirmed against Lima v2.0.3 source; affects only the coexistence warning. |
| L46 | Low | Low | CONFIRMED | - | Detect lists colima instances twice when LIMA_HOME points at colima's _lima. Rare configuration. |
| L47 | Low | Low | CORRECTED | - | Podman's empty LeaseName fails open in limaaddr. Only the e2e harness reaches it; defense in depth. |
| L48 | Low | Low | CONFIRMED | - | Root-refusal tests for ErrRootScoped and ErrPodmanRootScoped never run. |
| L49 | Low | Low | CONFIRMED | - | First up onto the fd-store release restarts an agent that never stored its fds. Arguably Info, as a documentation gap. |
| L50 | Low | Low | CONFIRMED GUEST | - | up --oci and down start a stopped or disabled docker. --no-docker-start is never passed. |
| L51 | Low | Low | CONFIRMED +LIVE | E11 | Plain up takes the owner from recorded state, which is empty after a rootful-era up --oci. Mode switch needs a live check. |
| L52 | Low | Low | CORRECTED | E4 | Digest mismatch needs differing drop-in bytes (crun path or drawbridge version). Doctor half confirmed. |
| L53 | Low | Low | CONFIRMED | - | v != 2 returns not-have before the newer-version refusal. Unreachable until a v3 exists; Info is defensible. |
| L54 | Low | Low | CONFIRMED | E6 | Podman check 4 is ok whatever the resolver found. Confirmed at checks.go:806-822. |
| L55 | Low | Low | CONFIRMED | - | Default auth case returns ok. Ring row-6 and the daemon's own auth state are ignored when the files match. |
| L56 | Low | Low | CONFIRMED | - | Primary auth verdict ignores Mac.Malformed. A present malformed file gives two fails; the correct remedy is also printed. |
| L57 | Low | Low | CONFIRMED | - | auth-wrong-peer names doctor's own resolution source instead of the daemon's. |
| L58 | Low | Low | CONFIRMED | - | vznat-leases counts as ok, and check 6 marks the guest's own address ok when it failed. Needs a differing lease IP that answers on :4777. |
| L59 | Low | Low | CONFIRMED | E6 | Check 9 is ok for a daemon serving a different VM. DaemonInput carries no target. Adds a check-9 state. |
| L60 | Low | Low | CONFIRMED | - | runc floor is skipped whenever crun exists. The docker wrapper always wraps runc. |
| L61 | Low | Low | CONFIRMED | E6 | Check 7 treats every activated network extension as Little Snitch class. Confirmed live on this Mac. |
| L62 | Low | Low | CONFIRMED | - | Snapshot assembly waits on the resolver mutex, which is held across I/O. Worse for the foreground daemon; diagnostic plane only. |
| L63 | Low | Low | CONFIRMED | - | Listen unlinks a live socket, and Close unlinks whatever is at the path. Two same-flavor daemons can collide. |
| L64 | Low | Low | CONFIRMED | E6 | Podman default machine user socket path overflows sun_path at 8 or more username characters. Changes D3's documented naming. |
| L65 | Low | Low | CONFIRMED | - | Guest script curls 192.168.127.1 on every provider. On Lima or colima it follows the default route through the Mac's NAT. |
| L66 | Low | Low | CONFIRMED | - | halfCloseInput drops a malformed Mac secret and probes unauthenticated. The tested fail-closed path is not the one the probe uses. |
| L67 | Low | Low | CONFIRMED | - | Context expiry is recorded as network evidence, producing a PostEOF skip or a pre-window agent-ended result. |
| L68 | Low | Low | CONFIRMED | - | One scrollState is shared across overlay transitions. |
| L69 | Low | Low | CONFIRMED | - | Mirror-table cursor vanishes under NO_COLOR or TERM=dumb. Breaks the section 3.6 accessibility promise for selection. |
| L70 | Low | Low | CONFIRMED | - | Mirror cursor is revealed only on movement. |
| L71 | Low | Low | CONFIRMED | - | D7 retire and late -vm match carry per-daemon view state over. |
| L72 | Low | Low | CONFIRMED | - | A daemon answering skewed or malformed shows as stopped answering for 30 s, plus a second row. |
| L73 | Low | Low | CONFIRMED | - | wrapText panics on a space-free wide-character token. Needs a gather error carrying such a token. |
| L74 | Low | Low | CONFIRMED | - | just e2e prints a bare ok when every leg skipped. |
| L75 | Low | Low | CONFIRMED | - | smoke-sudo can hang in the --oci dup leg, and an interrupt skips cleanup. |
| L76 | Low | Low | CONFIRMED | - | waitBindArbitrationLive and startDrawbridged cannot tell a live 'R' session from a missing one. A live mutation needs a guest. |
| L77 | Low | Low | CONFIRMED | - | e2e resolveAgent sends podman refs through the Lima lease resolver. Info is arguable given the documented workaround. |
| L78 | Low | Low | CONFIRMED | - | Skip-list positive leg has no attribution guard. A live false pass needs a forwarding provider. |
| L79 | Low | Low | CONFIRMED | - | agent-up, e2e and bench hardcode the arm64 guest binary. |
| L80 | Low | Info (was Low) | CONFIRMED | - | TestWedgeRepro runs without transport auth. Debug repro behind DRAWBRIDGE_WEDGE that still works in the dev flow. |
| I1 | Info | Info | CONFIRMED GUEST | E8 | TestNotifyFilterExitSemantics never calls NOTIF_RECV, so it does not pin the blocking behavior it cites. |
| I2 | Info | Info | CONFIRMED | - | Control API is documented as driven by drawbridge-agent testctl, which does not exist. |
| I3 | Info | Info | CONFIRMED | - | TestVerifyConstantTimeAndLengthStrict would pass with bytes.Equal. |
| I4 | Info | Info | CORRECTED | - | Every podman machine records the same transport port 4778, so a pinned endpoint can reach the wrong machine. |
| I5 | Info | Info | CONFIRMED | - | doctor -v help contradicts the renderer and docs/doctor.md section 6. |
| I6 | Info | Info | CONFIRMED | E3 | Install's replacing notice compares raw -vm spellings and warns about replacing a VM with itself. |
| I7 | Info | Info | CONFIRMED | - | ErrPodmanRootScoped text starts with Lima's refusal and points podman users at the lease db. |
| I8 | Info | Info | CONFIRMED | - | --oci refusal on a containerd-only Colima guest says a Colima VM already has Docker Engine. |
| I9 | Info | Info | CONFIRMED | - | Canned doctor via DRAWBRIDGE_TUI_DEMO_DOCTOR is unmarked on screen. Anyone who can set the variable already owns the session. |
| I10 | Info | Info | CONFIRMED | E6 | In-app help and tui.md section 4.1 disagree with dispatch. Amending 4.1 edits the frozen section 4 contract. |
| I11 | Info | Info | CONFIRMED | - | Workflow header comments are stale and contradict the live triggers. |

## Status of the 2026-10-18 audit

The report's table is correct for all 28 items. Corrections: #12's mirror loop
(L20) was never listed by the 10-18 audit, so PR #1 did not miss it; it is a
new site. #2 and #4 carry the residuals named in L16, L49, L6, M3 and L14.

| # | Report status | Evaluation | Note |
|---|---|---|---|
| 1 | Fixed (95936e1) | Agree | Hooks gated by host_netns_cookie; loader refuses on error or zero cookie. Kernel floor 5.14 not raised in preflight (L5). |
| 2 | Fixed (f2c1ebd) | Agree, with residuals | Residuals: L16 in-flight notification, L49 first upgrade, full stop still gives ENOSYS (documented), no automated test (L6). |
| 3 | Still open | CONFIRMED | proof() is HMAC without a nonce; transport-auth.md still claims no passive observer. |
| 4 | Partly fixed (93cd9f2) | CONFIRMED | Still open: 0666 socket, no handoff read deadline (L14), global cap closes real listeners (M3). |
| 5 | Fixed (550ce06, 1412ca1) | CONFIRMED | Residuals: i386 socketcall (L18) and stale wrapper on upgrade (M13). |
| 6 | Still open | CONFIRMED | udp.go writes to any loopback destination; no peer table; mirror untouched since the audit. |
| 7 | Still open | Agree | seed() unchanged since a44ab8a; L1 is a distinct second race. |
| 8 | Still open | Agree | writeFile still stages the secret in /tmp as the login user (guest.go:190-201). L38 adds a second site. |
| 9 | Still open | Agree | install boots out first; ensureRootDir runs before checkSecurePath (install.go:68-73, :241-252). |
| 10 | Still open | Agree | drawbridge-runc is a tracked ELF; .gitignore lists only /drawbridge and /drawbridged. |
| 11 | Still open | Agree | ci.yml never runs just gen; no job compares committed _bpfel.o files with the C source. |
| 12 | Partly fixed (93cd9f2) | CONFIRMED, with L20 correction | Five loops moved to acceptloop.Serve; root mirror loop missed (L20); L17 holds. |
| 13 | Still open | Agree | transportauth Load is a bare os.ReadFile with no owner, mode or symlink check. |
| 14 | Still open | CONFIRMED | Unbounded decoders at mirror.go:294 and :624, guest 'M' and 'R' decoders, and OCI socket io.ReadAll. |
| 15 | Still open | Agree | Bare limactl under euid 0 (limaaddr.go:316-317); bare launchctl, netstat, arp and systemextensionsctl. |
| 16 | Still open | Agree; now also reachable via H2 and H3 | Install-before-up crash loop: plist renders -secret-file and the daemon fatals (drawbridged/main.go:116-119). |
| 17 | Fixed (93cd9f2) | Agree | os.Chmod 0600 added in 93cd9f2; the residual window needs a non-default umask (L9). |
| 18 | Still open | Agree | tracker.c unchanged since the audit; lookup-miss and update race intact at :211-217 and :241-243. |
| 19 | Still open | Agree | tracker.c:159 prefix and suffix sniff unchanged. |
| 20 | Still open | CONFIRMED | ReadBindAddr unchanged since 1bb95c7; a stuck read also holds a cap slot. |
| 21 | Still open | Agree | Harness reproduces: stale runtimes.drawbridge.path survives; Merge returns the input unchanged. |
| 22 | Still open | Agree | No control-character filtering in doctor, render or tui; guest strings reach Evidence. |
| 23 | Still open | Agree | vmprovider/lima.go:129 and podman.go:210 use cmd.Output() with no limit. |
| 24 | Still open | Agree | No -trimpath, no signs section, cask still strips quarantine; signing gap accepted in README. |
| 25 | Still open | Agree | Default install pins nothing; first TCP-accepting candidate wins; M15 drops the pin on re-install. |
| 26 | By design | By design, unchanged (agree) | handshake.go admits sec == nil with AuthNone; agent logs UNAUTHENTICATED at boot. |
| 27 | By design | By design, unchanged (agree) | dialpool hand-off, reserve replace-on-new-conn and 'M' unchanged since the audit. |
| 28 | By design | By design, unchanged (agree) | Introspection path, log mode 0644 and fixture paths unchanged. This Mac's log dir is 0744. |
