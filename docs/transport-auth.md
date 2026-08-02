# Phase 4.5 — per-install transport authentication

Status: designed 2026-07-31, implements ergonomics.md §9 Q8 option (a) as
ratified (user, 2026-07-31), plus Q8 (c). **§12's two user-owned questions
ratified at recommendation (user, 2026-07-31): per-VM secret scope;
fail-open-loudly on both-absent.** The remaining §12 items stand at the
architect's recommendation. Lands before v0.1.0 — the wire
change is free exactly once (§6: embedded agents are lockstep with the CLI;
`just agent-up` builds both sides from one tree; no released artifact to
stay compatible with). This document is the executable plan: wire layout,
secret lifecycle, failure modes, files, phases, verification.

## 1. Goal and threat model

**Today:** whoever answers the transport probe first becomes the daemon's
trusted peer. Demonstrated live (2026-07-31): `drawbridged -vm
colima:colima` fell back to the loopback forwarder and silently attached to
the *dev VM's* agent — wrong peer, full trust. Symmetrically, the agent
trusts any dialer the source allowlist admits: the allowlist narrows *who
can dial*; nothing establishes *who dialed*.

**After this phase:** every transport connection carries a mutual proof of
a per-VM shared secret provisioned by `drawbridge up`. A peer without the
secret is **refused** — closed connection and a diagnosis in the log, never
a warning-and-continue. Independently (Q8 c), `macsync.handleStream` only
dials Mac-side ports the syncer actually advertised, so even an
authenticated-but-buggy peer is capped at the ports the Mac deliberately
offered.

**Threats in scope** (local machine only — loopback + host-only vzNAT, no
network MITM):

- T1 — wrong-agent attach: the daemon's resolution lands on a different
  VM's agent (the demonstrated failure) or on any process squatting the
  loopback forwarder port. Closed: the peer cannot produce the agent-side
  proof for *this* VM's secret.
- T2 — fake-daemon dial: a process that can reach the agent's transport
  (guest-loopback processes; anything on the Mac dialing via the forwarder
  or vzNAT) opens `'M'`/`'S'`/`'D'`/`'R'` conns and poisons `mac_ports`,
  splices to guest loopback services, or activates reverse streams.
  Closed: the agent refuses conns without the Mac-side proof.
- T3 — peer-confusion blast radius: any future bug that hands the syncer a
  wrong-but-authenticated peer. Bounded (not closed) by Q8 (c): reverse
  dials are limited to advertised ports.

**Explicitly out of scope, with reasoning** (§10 records the alternatives):

- A same-user Mac process is not an adversary: it can read the secret file.
- A *different*-user Mac process that squats `127.0.0.1:4777` before the
  provider's forwarder binds it can still act as a live relay (dial the
  real agent itself over vzNAT and pass bytes through). Static proofs do
  not bind the channel, so a relay is transparent. Challenge-response does
  not fix this either — only transcript-bound crypto (TLS-PSK/Noise) does,
  which is disproportionate for a loopback-local v0.1.0 threat and can be
  added later inside the same escape hatch (frame `auth` byte, §3). The
  residual risk is recorded, not hand-waved: the relay must win a boot-time
  port race against the forwarder, applies only on the forwarder fallback
  path (vznat-direct is preferred and its endpoint is not squattable
  cross-user), and the fallback is already loudly flagged by
  `Resolution.Note`.
- Replay across sessions: the proofs are deliberately static (§4). There
  is no passive observer position in this topology — loopback and
  host-only vmnet have no wire to tap short of root/kernel compromise, at
  which point the secret file itself is readable. A proof can only be
  "captured" by a fake peer the Mac dials (T1's squatter), and §4 shows
  what that buys: nothing reachable.

## 2. Decisions (the five open questions, answered)

| # | Question | Decision |
|---|----------|----------|
| 1 | Wire shape | Proof rides immediately after the 4-byte type frame, same first `Write` on the Mac side. Frame byte 1 (first reserved byte) is **spent** and permanently becomes the auth-scheme byte: `0` = none, `1` = static-HMAC-v1. Bytes 2–3 remain the reserved-zero version escape hatch. §3. |
| 2 | Static vs challenge-response | Static, direction- and type-bound HMAC-SHA256 proofs, constant-time compare. Challenge-response rejected: guest-first challenge on `'D'` would violate parked-conn silence, Mac-first nonces cost a round trip on every `'S'` conn, and the only attack it additionally stops (proof harvest + reuse) requires an attacker position the source allowlist and file permissions already exclude. §4. |
| 3 | Per-conn vs per-session | Per-conn. Conns are the only unit the wire has; the resolver can move the endpoint between conns (`ReResolve`), so "the session verified it" does not cover the next `'S'` dial. Per-conn cost is one HMAC (µs) and 32–64 bytes. §3. |
| 4 | Absent-on-both-sides | Fail-open **when neither side has a secret configured**, loudly logged. `up` always provisions, so every end-user install is authenticated; unauthenticated mode is reachable only by never running `up` (the dev flow). Any side that *has* a secret enforces mutually — there is no configuration in which a secretful side accepts a secretless peer. §6. |
| 5 | Rotation on `up` re-run | Preserve. The Mac-side file is authoritative: `up` generates it only when absent and always converges the guest to it. Rotation = delete the Mac file, re-run `up`; both sides re-read the file per connection, so rotation heals live without daemon or agent restarts. §5. |

One deviation from the brief's phrasing, flagged deliberately: the secret is
**per-VM**, not per-Mac. A single Mac-wide secret provisioned into every VM
would *not* close the demonstrated failure — both the colima VM and the dev
VM would hold it, and the wrong-peer attach would authenticate cleanly. The
identity this phase establishes is "the agent `up` provisioned for
*this* instance", so the secret must be scoped to the instance.
(`per-install` in Q8's text reads naturally either way; the goal — "answered
the probe first no longer confers trust" *between the user's own VMs* —
forces per-VM.)

## 3. Wire protocol

### 3.1 Before (today)

Every conn is dialed by the Mac. First bytes on the wire, per direction:

```
Mac → agent:  {type u8, 0, 0, 0}              one Write; then type-specific:
              'S': + {proto u8, port u16 BE, 0}   (same Write, 8 bytes total)
              'M'/'R': JSON lines follow
              'E'/'D': nothing further ('D' parks)
agent → Mac:  'E': JSON events    'R': JSON requests
              'D': nothing until the 4-byte activation header
                   {proto u8, port u16 BE, reserved u8}
```

Agent closes on any nonzero reserved byte, pre-dispatch
(`internal/agent/transport.go:69`). The Mac side does **not** currently
check the activation header's reserved byte (`macsync.parkOne`) — fixed in
this phase (§7 row 9).

### 3.2 After

```
frame:  {type u8, auth u8, 0, 0}     auth: 0 = none, 1 = static-HMAC-v1
                                     bytes 2–3: reserved, MUST be 0 (the
                                     remaining version escape hatch)

proof_mac   = HMAC-SHA256(secret, "drawbridge-transport-v1:mac"   || frame)   32 bytes
proof_agent = HMAC-SHA256(secret, "drawbridge-transport-v1:agent" || frame)   32 bytes
```

Mac side, one `Write` (the one-syscall rule is kept — first segment is the
whole hello):

```
auth=1:  'E'/'M'/'D'/'R':  [type,1,0,0] + proof_mac                (36 bytes)
         'S':              [ S ,1,0,0] + proof_mac + {proto,port,0} (40 bytes)
auth=0:  exactly today's bytes, unchanged
```

Agent side, auth=1, after verifying `proof_mac` (constant-time,
`crypto/hmac.Equal`) and before any dispatch side effect:

```
agent → Mac:  proof_agent                                          (32 bytes)
```

then dispatch exactly as today (`'D'` parks, `'E'` streams events, …). The
Mac verifies `proof_agent` before it forwards **any** payload byte or
trusts any received byte: `'S'` gates the client→guest splice, `'E'` gates
the JSON decoder, `'M'` gates the snapshot send, `'R'` gates the request
loop, `'D'` gates parking (the Mac-side `parkOne` reads the 32-byte proof,
verifies, *then* blocks on the activation header). Handshake reads on both
sides carry a 5s deadline; today's frame read gets the same deadline while
we are here (a stalled dialer currently pins a goroutine forever).

Proof binding: including `frame` in the MAC means a proof is bound to its
direction, its conn type, and the auth byte — a proof captured from an
`'S'` hello is not valid on `'M'`, and neither direction's proof yields the
other's. The raw secret never crosses the wire in either direction.

### 3.3 Invariant compliance (checked line by line)

- **Parked `'D'` conns silent until the guest's 4-byte header** — *held,
  unchanged.* The entire handshake happens in the pre-park dispatch phase:
  the Mac's proof rides in the same first Write as the type frame (all 36
  bytes consumed by `handleTransportConn` before `pool.park`), and
  `proof_agent` is written by the agent *before* parking. After park, the
  Mac writes nothing (as today) and the dial pool's 1-byte watchdog
  (`internal/agent/dialpool.go:65`) arms exactly where it always did. On
  the Mac side, `parkOne` consumes exactly 32 proof bytes and then waits
  for the activation header; the watchdog contract "any earlier byte is a
  dead conn" still refers to bytes after the handshake, which is the same
  boundary as today shifted by one verified exchange. No banner, no bytes
  on the reverse-stream protocol itself.
- **4-byte conn-type announcement, never a lone byte** — *held.* The frame
  grows company (proof in the same segment), it never shrinks. First
  segment Mac→agent is ≥ 36 bytes beginning `{'D',0x01,0,0}` — the
  method-prefix ambiguity that stalled DPI middleboxes needs a lone
  ASCII-method byte awaiting a request line; four bytes with a `0x01`
  in position 1 followed by 32 binary HMAC bytes is disambiguated at
  least as hard as today's `{'D',0,0,0}`. First bytes agent→Mac on a
  handshaking conn are the 32-byte proof — same argument. The activation
  header itself is untouched.
- **Frames transport-agnostic** — *held.* The handshake is bytes inside
  the stream after `transport.Dial`; nothing references TCP. The vsock
  swap stays localized to `internal/transport`.
- **Reserved bytes are the version escape hatch** — *spent deliberately,
  half of it.* Byte 1 now permanently means auth scheme; the agent closes
  on any value other than 0 or 1, and on nonzero bytes 2–3, so an
  incompatible future peer still fails closed pre-dispatch. This is the
  planned one-time spend the pre-v0.1.0 window allows; AGENTS.md gets the
  updated wording (§11). A future channel-bound scheme (TLS-PSK/Noise) is
  `auth=2`, no second wire break.
- **`'S'`/`'D'` activation headers and the v1 UDP frame** — untouched, to
  the byte.
- **Never weaken "wrong peer" into a warning** — refusal is a closed conn
  on both sides, always (§7).

## 4. Why static proofs (and what replay means here)

Who can ever *see* a proof? Only a peer one side willingly dialed or
accepted. Enumerate:

- A rogue **VM on the vmnet subnet** can squat the DHCP name (pre-pin) or
  answer probes, receive `proof_mac` — and do nothing with it: it cannot
  reach the real agent (source allowlist admits guest loopback and the
  Mac's `.1` only; another VM is neither), and `proof_mac` is useless
  against the daemon, which demands `proof_agent`.
- A rogue **guest process** can dial the agent's loopback listener but
  holds no secret; it is refused before dispatch. It never sees any proof
  (the agent answers only after a valid `proof_mac`).
- A rogue **Mac process, different user**, squatting the forwarder port:
  receives `proof_mac`, can dial the real agent — the live-relay residual
  documented in §1, which challenge-response also would not stop.
- A rogue **Mac process, same user**: reads the secret file; no wire
  scheme changes anything.

So a nonce exchange would buy exactly one thing — a *stored* `proof_mac`
becoming useless — in a topology where every position that can store one
either cannot use it or already has the file. Against that, the costs are
concrete: a guest-first challenge is an early guest byte on `'D'` (a direct
invariant conflict), a Mac-first nonce adds a round trip before the agent
can even evaluate the hello on every latency-critical `'S'` conn, and both
add state to the one code path that is deliberately stateless. Static
proofs keep the hello a single write and the verify a single HMAC.
Constant-time comparison (`hmac.Equal`) on both sides — the compare is on
a network-observable path.

Latency accounting (bench re-baselines in the last phase):

- Outbound (guest→Mac, `'D'`): zero added latency on the flow path — the
  handshake happens at park time, off the critical path; activation is
  byte-identical.
- Inbound (Mac client→guest, `'S'`): the Mac's hello grows to 40 bytes
  (same single write); the added wait is `proof_agent` arriving before
  client bytes are forwarded, and the agent sends it *before* dialing the
  guest backend, so the extra wait overlaps the backend dial. Expected
  cost: sub-ms on vznat-direct; visible only in first-byte, not throughput.
- `'E'`/`'M'`/`'R'`: long-lived; one extra exchange at session start,
  irrelevant.

## 5. Secret lifecycle

**Format.** 32 bytes from `crypto/rand`, stored as 64 lowercase hex chars +
`\n`. Anything else in the file — wrong length, bad hex, empty — is
*malformed*, and malformed always fails closed (refuse to start / refuse
the conn), mirroring the `-vm-mac` "malformed pin fails closed" rule.
Absent is a distinct state (§6).

**Guest side.** `/etc/drawbridge/transport-secret`, `0600 root:root`,
written by `up` via the existing `writeFile` primitive (data on stdin —
never argv, never a shell word). Constant lives in `internal/guestbin`
(`SecretPath = StateDir + "/transport-secret"`). `drawbridge down` already
removes `StateDir` wholesale (`cmd/drawbridge/down.go:98`) — the guest half
dies with it, no new teardown code. The agent takes `-secret-file` (default
`/etc/drawbridge/transport-secret`; a *path* is argv-safe — the secret
itself never is).

**Mac side.** `~/Library/Application Support/drawbridge/` (dir `0700`),
file `transport-secret-<provider>-<instance>` (`0600`), e.g.
`transport-secret-lima-drawbridge`, `transport-secret-colima-colima`. The
filename derives from the **canonical** `vmprovider.Ref`
(`ref.Provider + "-" + ref.Instance`), never the user's spelling —
`colima:default` and `colima:colima` must land on the same file (pin with a
test). Instance names already pass `ParseRef`'s allowlist grammar, so the
filename needs no sanitizing.

One file serves both daemon flavors:

- Unprivileged foreground `drawbridged`: derives the default path from
  `os.UserHomeDir()` + the parsed `-vm` ref. Same derivation `up` used to
  write it — same file by construction.
- Root LaunchDaemon: `sudo drawbridge install` resolves the invoking
  user's home via `SUDO_USER` (`os/user.Lookup`) and renders an explicit
  `-secret-file <abs path>` into `ProgramArguments`. The value is a path,
  not a secret — ps-visible is fine. Plist validation stays
  validate-never-escape: absolute path, no control characters, none of
  `& < > " '` (the space in `Application Support` is legal — plist argv
  elements are separate `<string>`s, no shell involved). Root reading a
  user-owned `0600` file is intended: the user *is* the trust root of this
  whole system; the file grants transport identity, not code execution.
- `sudo drawbridged` ad-hoc foreground (the <1024 dev case): the
  `SUDO_USER` derivation applies there too.
- Explicitly passed `-secret-file` that does not exist: **fatal** (an
  explicit flag states intent; silently degrading to unauthenticated would
  be the forbidden weakening). Derived default path absent: unauthenticated
  mode with a log line (§6).

**Both sides re-read the file per connection** (agent: per accepted conn;
Mac: per dial). The file is ~65 bytes; a read is noise next to a TCP dial,
and it makes rotation live: delete Mac file → `drawbridge up` → new secret
on both sides → in-flight *new* conns use it immediately, no restarts.
Established conns keep running (they were mutually verified at open).

**`up` re-run semantics** (deterministic, stated): Mac file exists → reuse;
absent → generate. Then converge the guest: compare via a root digest
(`sudoSh("sha256sum " + SecretPath)` — the guest file is `0600` root, so
the existing non-root `g.sha256` cannot read it; comparing digests exposes
only a digest of 32 random bytes, which is inert) and `writeFile` mode
`0600` only when it differs — re-runs stay cheap and journal-quiet.
`down` keeps the Mac file, deliberately: `down` is guest-scoped, a
recreated VM plus `up` re-adopts the same identity (and a root daemon's
plist keeps pointing at a file that exists). The doc string on the ensure
step says so.

**Never in argv, env, or logs** — the secret and the proofs. Log paths,
modes, and enabled/disabled; log a digest prefix only in `doctor` (Phase
5), where comparison is the point. This becomes an AGENTS.md invariant
(§11).

## 6. Mode matrix (per side: configured = file present at its path)

| Mac secret | Agent secret | Outcome |
|---|---|---|
| yes | yes, same | Mutual auth on every conn. `drawbridged` logs once at startup: `transport auth: enabled (<path>)`. |
| yes | yes, different | Agent refuses `proof_mac` (row 2, §7); Mac refuses `proof_agent` if it ever gets one (row 5). Wrong-peer/stale-secret diagnosis both ends. |
| yes | no | Agent sees `auth=1`, cannot complete the exchange, closes + logs (row 3). Mac times out awaiting `proof_agent` (row 4). |
| no | yes | Mac sends `auth=0`; agent refuses (row 1). Mac's session dies immediately after the frame and its error names both possible causes and its own mode (row 6). |
| no | no | Today's wire, byte-identical. `drawbridged` logs once: `transport auth: no secret configured (looked for <path>) — transport is UNAUTHENTICATED; any process that reaches it is trusted. Run `drawbridge up` to provision one.` Agent logs the mirror-image line at startup. |

Rationale for fail-open-on-both-absent: the dev flow (`just agent-up`, no
`up`) must stay one command, and the e2e/bench harness constructs
`mirror.Client`/`macsync.Syncer` directly. Fail-closed-always would force
secret plumbing through the justfile, the harness, and every test that
spins an agent — coordination cost with no security payoff, because `up`
always provisions (there is no `--no-secret` flag, deliberately) and
`install`'s plist always renders `-secret-file`, so no *provisioned*
install can be unauthenticated. What the feature claims changes shape:
"drawbridge-provisioned transports are mutually authenticated" — and
`doctor` (Phase 5) flags the unauthenticated state on sight. There is no
downgrade path a peer can trigger: each side decides its mode from its own
file, never from the wire.

Mixed dev states stay one-command: after an `up` on the dev VM,
`just agent-up`'s transient agent reads the same
`/etc/drawbridge/transport-secret` (flag default), and the e2e harness
loads the Mac half via the same derivation `drawbridged` uses
(`DRAWBRIDGE_SECRET_FILE` env override first — the sibling of
`DRAWBRIDGE_AGENT` — then the default path for the target VM, absent = 
unauthenticated). No justfile change.

The resolver's probe stays a bare TCP connect, unauthenticated, on
purpose: answering a probe now confers *reachability* only; trust requires
the handshake. (This sentence goes in transport.md — it is the epitaph of
the trust-by-first-answer hole.)

## 7. Q8 (c) — bound `handleStream`, and the failure-mode table

### Advertised-port bound

`macsync.Syncer` keeps an advertised-set snapshot: the normalized
`(proto byte, port)` pairs most recently sent on the `'M'` session
(`currentSet()` output — TCP listeners plus `UDPPorts`), stored behind an
`atomic.Pointer[map[advKey]struct{}]`, replaced on every poll tick that
sends, **primed once in `Run` before the pool loops start** (else the first
75 ms refuses legitimate activations), and **kept across session drops**
(parked conns outlive an `'M'` blip; clearing would refuse valid
activations mid-reconnect; the guest agent independently drops sync-owned
`mac_ports` when the `'M'` conn dies, so staleness is bounded by the
reconnect). `handleStream` refuses anything else: close + log (row 7).
The del-vs-inflight-activation race (guest activates a port the same tick
the Mac deletes it) resolves as a refusal — correct, and worth its log
line. While in the file: `parkOne` starts checking the activation header's
reserved byte (`hdr[3] != 0` → close conn, row 9), the version rule the
Mac side never enforced.

### Refusal path → log line → doctor check

Log-line discipline is the resolver-Note discipline: each line states the
condition, the most likely cause, and the one command that fixes it. Agent
refusal lines are throttled per (cause, source) to one per 30s — the Mac
retries every second and journal spam would bury the diagnosis. The doctor
check IDs below are Phase 5's contract; the strings' *job* is written next
to each so Phase 5 does not re-litigate.

| # | Where | Condition | Log line (shape) | Doctor check (Phase 5) |
|---|-------|-----------|------------------|------------------------|
| 1 | agent | secret configured, hello has `auth=0` | `transport: refused '<T>' conn from <src>: peer sent no authentication but this guest has a transport secret — the Mac daemon has no secret configured or predates transport auth; re-run 'sudo drawbridge install' (or pass -secret-file) and restart it` | `auth-mac-missing-secret` — job: point at the Mac side when the guest is healthy |
| 2 | agent | secret configured, `proof_mac` invalid | `transport: refused '<T>' conn from <src>: invalid transport secret — the peer holds a different secret than this guest (stale after re-provisioning?); re-run 'drawbridge up <vm>' to converge, then retry` | `auth-mismatch` — job: name convergence, not blame |
| 3 | agent | no secret, hello has `auth=1` | `transport: refused '<T>' conn from <src>: peer requires authentication but this guest has no transport secret (<path> missing) — run 'drawbridge up <vm>' to provision one` | `auth-guest-missing-secret` |
| 4 | Mac (mirror + macsync session errors) | sent `auth=1`, conn closed / 5s deadline before 32 proof bytes | `agent at <ep> closed during transport authentication — the guest's secret differs or the agent predates auth; re-run 'drawbridge up <vm>' ('drawbridge doctor' compares both sides)` | `auth-mismatch` (same ID as 2 — one condition, two vantage points) |
| 5 | Mac | `proof_agent` invalid | `peer at <ep> presented an invalid transport secret: this is NOT the agent '<vm>' was provisioned for — wrong VM or a squatter answered (source=<resolution source>); refusing. Check -vm, and whether the transport fell back to the loopback forwarder` | `auth-wrong-peer` — job: THE line for the demonstrated failure; must name the resolution source so forwarder-fallback attaches are self-explaining |
| 6 | Mac | sent `auth=0` (no local secret), conn died right after the frame | `agent at <ep> closed the connection immediately — if that guest was provisioned with a transport secret, this daemon needs one too: expected at <derived path> (not found). 'drawbridge up' writes it; 'sudo drawbridge install' points the daemon at it` | `auth-mac-missing-secret` |
| 7 | Mac (syncer) | `'D'` activation names an unadvertised port | `refused reverse dial to 127.0.0.1:<port> (proto <p>): not a port this Mac advertised — the guest asked for something the syncer never offered (agent bug or hostile peer); conn closed` | none — runtime alarm; doctor surfaces its presence in the log tail as evidence |
| 8 | both | secret file present but malformed / unreadable | startup: fatal, naming file, expected format (64 hex chars), and mode; per-conn re-read failure post-startup: refuse conn + log same shape | `auth-file-perms` — checks existence, mode 0600, format, both sides |
| 9 | Mac (syncer) | activation header reserved byte nonzero | `dropping reverse-stream conn: nonzero reserved byte in activation header (incompatible agent?)` | folded into version-skew check |

Stale-secret after VM recreation, walked through: user deletes the colima
VM, recreates it, forgets `up`, starts the daemon → agent absent → plain
connection-refused (existing behavior, resolver Note). User re-runs `up` →
Mac file reused, guest converged → healthy. User instead restores a VM
snapshot holding an *old* secret → rows 2+4 fire with the convergence
command. Every path ends in a printed next step.

## 8. Affected files

New:
- `internal/transportauth/` — portable: `Secret` (32 bytes), `Load`
  (absent/malformed as distinct results), `Generate`, `Format`,
  `MacProof(frame)`, `AgentProof(frame)`, constant-time `Verify`,
  `ClientHello(conn, secret, typ, extra []byte)` (builds the one-write
  hello), `AwaitAgentProof(conn, secret, deadline)`, and the server half
  used by the agent. Also the Mac-side default-path derivation
  (`PathForRef(ref)`, `SUDO_USER`-aware home resolution).

Modified:
- `internal/agent/transport.go` — frame byte 1 handling, handshake
  verify/respond pre-dispatch, refusal logs + throttle, handshake
  deadline; `internal/agent/agent.go` gains the secret-file field/loader.
- `cmd/drawbridge-agent/main_linux.go` — `-secret-file` flag (default
  `/etc/drawbridge/transport-secret`), boot-time validation (malformed =
  fatal), startup mode line.
- `internal/macsync/sync.go` — `SecretFile` field; hellos via
  `transportauth`; `parkOne` proof await + `hdr[3]` check; advertised-set
  snapshot + `handleStream` bound + refusal logs.
- `internal/mirror/mirror.go` — `SecretFile` field; hellos on `'E'`
  (`session`), `'S'` (`splice`), `'R'` (`reserveSession`); payload gating
  on `proof_agent`.
- `cmd/drawbridged/main.go` — `-secret-file` flag, default derivation from
  the parsed `-vm` ref, startup mode logging, wiring into both clients.
- `internal/install/plist.go` — `Config.SecretFile` + `Args()` +
  `Validate()` (absolute, no XML-specials/control chars);
  `internal/install/install.go` — `SUDO_USER` home resolution feeding the
  default.
- `internal/guestbin/guestbin.go` — `SecretPath` constant.
- `cmd/drawbridge/up.go` — `ensureSecret` step between agent push and unit
  install (Mac ensure → guest converge via root digest compare +
  `writeFile` `0600`); handoff prints `transport auth: enabled`.
- `cmd/drawbridge/down.go` — no removal change needed (StateDir covers
  it); prints that the Mac-side secret is kept and why.
- `internal/e2e/e2e_test.go` (helpers) — secret loading:
  `DRAWBRIDGE_SECRET_FILE` env, else `transportauth.PathForRef` for the
  target VM, absent = unauthenticated.
- Docs: `docs/transport.md` (§2.6 layout + new auth section, probe
  epitaph), `docs/ergonomics.md` (§8 Phase 4.5 entry), `AGENTS.md` (§11
  below), `docs/HANDOFF.md`, `docs/verify-colima.md` (secret addendum).

Untouched, by design: `internal/bpf/` (nothing here is kernel-side), the
`'S'`/`'D'` activation headers, `internal/udpframe`, `internal/transport`
(endpoint grammar; auth is above it), the justfile.

## 9. Build phases

Ordering rule: Mac-only pure phases first, the guest wire change in one
hard cutover mid-sequence (pre-v0.1.0 lockstep means both sides rebuild
together — `just build` + `just agent-up` — and the interim states stay
runnable because both sides default to auth=0 until provisioned).

**P1 — `internal/transportauth` + Q8 (c).** The new package with full unit
tests (load/malformed/absent matrix, proof vectors, constant-time paths,
path derivation incl. the canonical-ref pin and `SUDO_USER`). In macsync:
advertised-set snapshot, `handleStream` bound, `hdr[3]` check, refusal
logs — pure-Go unit tests against the existing fake agent.
*Verify:* `go test ./internal/...`; `just e2e` (unchanged behavior — no
caller passes a secret yet, and the advertised bound must not break the
outbound leg).

**P2 — agent wire.** `transport.go` handshake + refusal matrix + throttle
+ deadline; agent flag + boot validation. Update
`TestFramedDialConnParksSilent` (parked-silence now asserted *after* the
handshake) and `TestFrameNonzeroReservedRejected` (bytes 2–3 still fatal;
byte 1 ∈ {0,1}); add the mode-matrix dispatch tests (rows 1–3) and a
throttle test.
*Verify:* `just gen` **not** needed (no BPF); `just test-guest` (the
dispatch tests run in the guest per the house rule); `just agent-up &&
just e2e` — still green with no secrets anywhere (mode row 5).

**P3 — Mac clients.** mirror + macsync + drawbridged wiring, payload
gating, log rows 4–6. The fake-agent test doubles in
`internal/mirror`/`internal/macsync` grow an optional secret and cover:
mutual success on all five types, each mismatch row, the `'S'` gate (no
client byte crosses before `proof_agent`), and `'D'` park-then-activate
under auth.
*Verify:* `go test ./internal/...`; live on the dev VM: write a secret
into the guest by hand (`limactl shell drawbridge -- sudo sh -c 'echo
<hex> > /etc/drawbridge/transport-secret && chmod 600 ...'`), export
`DRAWBRIDGE_SECRET_FILE`, `just agent-up && just e2e` — the full suite
authenticated; then flip one hex digit in the Mac file and confirm rows
2/4 fire fast (no hang) and `just e2e` fails loudly, restore, green again.

**P4 — provisioning.** `up`'s `ensureSecret` (+ idempotent re-run: second
`up` streams nothing, journal quiet), handoff line, `down`'s note,
`install` plist rendering + validation, `drawbridged` default derivation.
Unit: plist golden files with `SecretFile`, `Validate` rejections, ensure
step against the fakeguest (generate-when-absent / reuse / converge /
guest-differs cases).
*Verify:* `go test ./internal/... ./cmd/...`; live dev VM: `drawbridge up`
→ both files exist, modes `0600`/`0700` checked, foreground `drawbridged
-vm drawbridge` logs `transport auth: enabled` and mirrors work;
`just agent-up` convergence both directions (transient agent picks the
same guest file — auth stays on); colima per the Phase 3 recipe
(`drawbridge up colima:colima`, daemon with derived secret, e2e subset) —
provider coverage, and append the secret steps to `docs/verify-colima.md`.
**Acceptance (the demonstrated failure, re-run):** with both VMs
provisioned, force the colima daemon onto the dev VM's endpoint (the
loopback forwarder / `DRAWBRIDGE_AGENT`): it must refuse with row 5's
wrong-peer line and keep retrying — never attach. `drawbridge down` on the
dev VM, then confirm `/etc/drawbridge` is gone and the daemon now logs
plain connection-refused, not an auth line.

**P5 — docs + bench.** AGENTS.md invariant edits (§11), transport.md,
ergonomics.md Phase 4.5 results section, HANDOFF. `just bench` with auth
enabled on the dev VM, recorded next to the existing table: outbound
first-byte must be unchanged within noise ('D' handshake is off-path);
inbound first-byte may grow sub-ms (the `proof_agent` gate) — record the
delta explicitly rather than hiding it in "noise".

## 10. Alternatives rejected

| Alternative | Why not | What would revive it |
|---|---|---|
| Challenge-response (nonce + HMAC) | Guest-first challenge on `'D'` = early guest byte (invariant conflict); Mac-first costs an RTT on every `'S'`; only defeats proof-harvest by an attacker who either can't reach the real agent or can read the file (§4) | A topology with a real passive observer (transport leaves the machine) |
| TLS-PSK / Noise over the transport | Closes the cross-user loopback relay, but drags a handshake library into a 4-byte-frame protocol for a threat requiring a boot-time port race by another local user, on the fallback path only | Multi-user Macs as a supported deployment; `auth=2` is reserved for it |
| Per-Mac (install-wide) secret | Fails the acceptance test: both of the user's VMs hold it, wrong-peer attach authenticates | Nothing — it does not close the ratified hole |
| Per-session verification (first conn only / hello conn) | Re-creates trust-by-first-answer for every later conn; endpoint can move between conns (`ReResolve`); adds cross-conn state for the cost of one HMAC per conn | Nothing at this conn rate |
| Secret in the systemd unit / plist argv or env | ps-visible (argv), `systemctl show`-visible (env); plist ProgramArguments is allowlist-validated text | Nothing |
| Fail-closed when both sides lack a secret | Breaks `just agent-up` + e2e/bench one-command flows for zero end-user gain (`up` always provisions) | A first release that ships agents outside `up`'s control |

## 11. AGENTS.md invariant updates (apply in P5, wording proposed here)

1. Amend the conn-type-frame invariant: "The conn-type announcement is a
   4-byte frame `{type, auth, 0, 0}` plus, when `auth=1`, a 32-byte
   static-HMAC proof — all written in one Mac-side `Write` and consumed by
   agent dispatch before parking. Byte 1 is permanently the auth-scheme
   byte (`0` none, `1` static-HMAC-v1; anything else closes pre-dispatch);
   bytes 2–3 remain the reserved-zero version escape hatch. Never shrink
   the frame; never move the proof out of the first segment (DPI)."
2. The parked-`'D'` invariant stands as written — add one clarifying
   clause: "the mutual-auth exchange completes before parking; while
   parked, the wire is exactly as before (Mac silent, guest silent until
   the 4-byte activation header)."
3. New: "Transport secrets are file-borne only — never argv, env, or
   logs (paths are fine; bytes and proofs are not). A configured-but-
   unreadable/malformed secret fails closed. A side with a secret refuses
   unauthenticated peers — a wrong or missing secret is a refusal with a
   named remedy, never a warning-and-continue. `handleStream` dials only
   advertised ports."

## 12. Open questions, ranked (recommendation on each)

1. **Ratify the per-VM scope** (vs the brief's literal "per-install").
   Impact: identity model of the whole feature. Recommendation: per-VM —
   §2 shows per-Mac cannot close the demonstrated failure. Nothing else
   in the design moves if this flips, only the path derivation and the
   ensure step.
2. **Fail-open on both-absent** (§6). Impact: what the feature claims;
   dev ergonomics. Recommendation: accept — `up` always provisions, the
   unauthenticated state is loudly logged on both sides and becomes a
   `doctor` finding. The fail-closed alternative's cost is real (justfile
   + harness + every agent-spawning test) and its benefit is nil for
   provisioned installs.
3. **Inbound `'S'` payload gating** (wait for `proof_agent` before
   forwarding client bytes; §4 latency note). Impact: sub-ms on inbound
   first-byte, quantified in P5's bench. Recommendation: keep the gate —
   forwarding client bytes to an unverified peer is precisely the leak
   this phase exists to close; if the bench shows more than ~1 ms p50
   regression on vznat-direct, revisit by moving the agent's proof write
   ahead of the S-header read (protocol allows it; ordering is
   agent-internal).
4. **Rotation UX**: no `drawbridge secret rotate` in 4.5 — documented
   `rm <mac file> && drawbridge up` (live-heals, §5). Recommendation:
   defer the subcommand until someone asks; the primitive is complete
   without it.
