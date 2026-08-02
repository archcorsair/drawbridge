# Phase 5 — `drawbridge doctor` and the daemon introspection substrate

*Design note, 2026-08-01. Companion to [ergonomics.md](ergonomics.md) §5/§6/§8
(the doctor spec and phase contract), [transport-auth.md](transport-auth.md) §7
(the auth check-ID contract), and
[notes/local-network-permission.md](notes/local-network-permission.md) (the
diagnosis knowledge this verb encodes). Status: design ratified in outline
(introspection substrate approved 2026-08-01); this note fixes the shape.*

## 1. Goal and shape

Two deliverables, one dependency direction:

1. **`drawbridge doctor`** — one verb, the §5 catalog of ordered checks, each
   `ok | warn | fail | skip` with a one-line remediation; `-json` emits the
   full structured report. Every classification is a pure function over
   injected probe results (unit-tested from fixtures, no VM); the impure
   gathering is a thin, separately-testable layer. Doctor **never mutates
   state** — it prints remediations, it does not run them.
2. **The daemon introspection endpoint** — a read-only snapshot socket on
   `drawbridged` that `doctor`, `status`, and the future bubbletea TUI all
   consume. It removes inference: today `status` reconstructs daemon state
   from launchctl and a log file; after this phase the daemon states its own
   endpoint, source, auth mode, mirror table, and recent refusals.

Doctor must work **fully with no daemon installed or running** — diagnosing
that state is part of its job. Introspection is an enrichment tier, never a
dependency. Nothing charm-flavored enters the root daemon (the TUI is
post-v0.1.0 and lives in its own binary/verb; the daemon serves JSON, full
stop).

What this buys: the field knowledge earned in Phases 0–4.5 — the route
deletion, the Local Network gate, three distinct Little Snitch signatures, the
errno misclassification, the wrong-VM attach, the version-skew windows —
becomes an executable checklist instead of a pile of design notes only we can
read.

## 2. Decisions (the open questions, answered)

**D1 — The sudo discriminator runs on evidence tiers; doctor never invokes
`sudo` itself.** The session-6 scar: on macOS 27.0b4 the Local Network denial
presents as a *silent timeout*, so `classifyProbe` files it under
`NoteAgentNotListening`, and the flow dies before Little Snitch's filter sees
it (nothing in LS's monitor). Errno classification is therefore an input, not
a verdict. The conclusive discriminator is exemption-based (TN3179: root,
launchd daemons, and Apple Terminal are exempt) and must be **same-binary**:

- *Tier 1 (conclusive):* `sudo drawbridge doctor` — the same binary probing
  as root. Unprivileged doctor prints this exact instruction when it needs
  the root branch; under euid 0 doctor runs the probe and labels the result
  `root-probe`, noting it cannot see the unprivileged branch from there.
  Doctor never spawns `sudo` (no credential prompts mid-run; the user runs
  the printed one-liner and re-reads).
- *Tier 2 (suggestive):* a running root daemon's introspection snapshot —
  `resolution.source == "vznat-direct"` with a live session is "the root
  vantage reaches the guest", obtained passively with zero new probes. The
  daemon is continuously doing the probe by existing; doctor reads the
  freshest evidence rather than commanding a new one. **Caveat, always
  printed with tier-2 evidence:** LS-class filters are per-*binary* — a
  filter can allow `/usr/local/libexec/drawbridged` and drop the CLI — so
  when check 7 sees an NE content filter, tier-2 cannot fully exonerate it
  and the tier-1 run is named as the conclusive step.

Both branches of the discriminator are spelled out in §4 check 6; the
never-rule is: **a user-only probe never concludes "Local Network gate"**, and
**absence from Little Snitch's Network Monitor is never exoneration**.

**D2 — The introspection protocol is single-shot and write-only: the daemon
never reads a byte from the client.** Connect → daemon writes one JSON
document → daemon closes. There is no request grammar, no verbs, no RPC. This
is the whole answer to the attack-surface question that made
privileged-daemon.md §6 say "no control socket": a listener that never reads
client data cannot be driven; the inbound surface is `accept` + `write` +
`close` with a write deadline and a small accept concurrency cap. It also
forecloses scope creep structurally — the daemon cannot grow control verbs or
become a metrics query engine without a *visible* protocol change. Consumers
that want fresh state re-dial (a unix-socket dial is microseconds; a 1 Hz TUI
tick is noise). §3 has the full contract; §10 has the privileged-daemon.md
amendment this reverses, flagged loudly.

**D3 — Socket privilege model: filesystem-gated unix sockets, root and user
flavors, same protocol.**

- Root daemon: `/var/run/drawbridge/introspect.sock`, dir `0755 root:wheel`
  (created by the daemon at startup), socket `0660 root:staff`. Every macOS
  console user is in `staff`; other-uid service accounts are not. Narrower
  than `0666`, and widening later is compatible while narrowing is not — the
  cheap-to-reverse direction.
- Unprivileged foreground daemon (dev flow): `~/Library/Application
  Support/drawbridge/run/introspect-<provider>-<instance>.sock`, dir `0700`,
  socket `0600` — private to the user, which is the only consumer. Per-VM
  naming because foreground daemons are per-VM; the root daemon path is fixed
  because the LaunchDaemon is a singleton.
- Discovery (doctor/status): try the root socket first, then glob the user
  `run/` dir; each payload names its `vm.ref`, so the consumer matches
  rather than guesses. **Both answering is itself a finding** — the known
  dev-posture pathology (installed daemon and foreground daemon fighting
  over mirror ports) becomes detectable for the first time.
- Stale socket file after a crash: connect gets `ECONNREFUSED` → treated as
  absent; the daemon unlinks-then-binds at startup. macOS's 104-byte
  `sun_path` limit is checked at startup with a clear error (pathological
  home paths only).

**D4 — Payload versioning is loose, with two frozen fields.** Top-level
`"schema": 1` and `"version": "<buildinfo>"` are frozen forever. Within
schema 1, changes are additive-only; readers tolerate unknown and absent
fields. A reader seeing `schema > 1` uses the two frozen fields, reports
"daemon speaks introspection schema N, this CLI knows 1" as version-skew
evidence, and falls back to inference for everything else. Same-host CLI↔
daemon only; no cross-version wire promise beyond this.

**D5 — `doctor -json` and the introspection JSON are different documents with
shared types.** `internal/introspect.State` is the daemon's document;
doctor's report embeds it verbatim as the `daemon.snapshot` field when a
socket answered. One dependency direction (`internal/doctor` imports
`internal/introspect`), two lifetimes (the snapshot is daemon-versioned, the
report is CLI-versioned), zero copying between shapes.

**D6 — Check 8 (`-probe` half-close) ships in v1, opt-in, gated on one live
verification.** The probe speaks the real wire: complete the `'E'` hello
(4-byte frame + auth proof when a secret is configured — through the same
`transportauth.MacConfig` derivation the e2e harness uses), read the initial
snapshot events, then `CloseWrite()` and keep reading for 3 s. The `'E'`
direction is agent-push; the agent has no reason to read post-hello, so
client-FIN-then-server-bytes is exactly the finding-4 shape without any wire
or agent change. Starved read (no bytes, no EOF) on a non-loopback endpoint =
the half-close-killer signature → fail naming the NE filter / a
half-close-dropping forwarder. On a loopback endpoint the probe still runs
but its pass is labeled non-evidence for the vznat path (loopback is exempt
from both LS bugs). **Gate:** P4 live-verifies that the agent keeps writing
`'E'` events after client FIN; if it turns out to close on EOF, the check
reports `skip` with that reason and we do *not* touch the agent (no wire
changes in this plan) — the probe then waits for Phase 7, which needs it
anyway for the gvproxy verdict.

**D6 amendment — P4 live verification, 2026-08-01 (dev VM, loopback
forwarder).** The gate resolved in the probe's favour: the agent *does* keep
writing after client FIN (`serveEvents` never reads its conn), measured as
FIN at t+1.0 s, session intact, `{"op":"ping"}` at t+15.0 s and t+30.0 s. The
check therefore ships active, and the skip branch stays in the classifier
verbatim in case that ever changes. **The 3 s post-FIN window above is wrong
and is 20 s in the build.** After the primed snapshot, the agent's only
self-generated traffic on a quiet guest *is* its 15 s liveness ping, so a 3 s
window starves on a healthy path — it would report the half-close-killer
signature for every guest that happened not to bind a port during the probe.
The window must outlast one ping, and `-probe` puts a matching floor under
`-timeout` (`doctor.ProbeBudget`) so the global budget cannot truncate the one
check the flag was passed for.

**D7 — `status` migrates additively.** When any introspection socket answers,
`status` appends a `daemon:` section (version, endpoint+source, auth mode,
mirror/sync counts) per socket found. `install.Query()` remains the spine and
the exit-code source (0/1/3 unchanged) — scripts keep working, and a daemon
that predates the endpoint degrades to exactly today's output.

## 3. The introspection endpoint

### 3.1 Contract

- **Transport:** unix stream socket, paths per D3. Flag:
  `drawbridged -introspect auto|off|<path>` (default `auto` = the D3 path for
  the current euid). `off` exists for paranoia and tests; the plist renders
  nothing (auto is the default, so `install` needs no change).
- **Protocol:** on accept, the daemon marshals one `introspect.State`, writes
  it with a 2 s deadline, closes. It never calls `Read` on the conn. Accept
  loop caps in-flight writes (8) and continues on error. No TLS, no auth
  beyond filesystem permissions — the payload contains nothing that is not
  already derivable from world-readable sources (netstat/lsof for mirror
  binds, the lease db, the 0644 daemon log), and never secret bytes, proofs,
  or digests.
- **Liveness of the data:** snapshots are assembled on demand from
  mutex/atomic-guarded state the daemon already maintains — no caches to go
  stale, no background sampler.

### 3.2 `introspect.State` v1

```json
{
  "schema": 1,
  "version": "v0.1.0",
  "pid": 4242, "euid": 0,
  "startedAt": "2026-08-01T18:00:00Z",
  "vm": {"ref": "colima:colima", "provider": "colima", "instance": "colima"},
  "mirrorIP": "127.0.0.1",
  "resolution": {
    "endpoint": "tcp://192.168.64.5:4777",
    "source": "vznat-direct",
    "note": "",
    "resolvedAt": "2026-08-01T18:00:01Z"
  },
  "auth": {"mode": "static-hmac-v1", "secretPath": "/Users/nxc/Library/…/transport-secret-colima-colima", "secretState": "ok"},
  "mirror": {
    "sessionUp": true, "lastEventAt": "2026-08-01T18:22:10Z",
    "entries": [{"proto": "tcp", "port": 8080, "state": "bound", "since": "…"}],
    "skip": [22]
  },
  "sync": {
    "sessionUp": true,
    "advertised": [{"proto": "tcp", "port": 5432}],
    "udpPorts": [5353],
    "poolParked": 4
  },
  "recentRefusals": [
    {"at": "…", "id": "auth-mismatch", "line": "agent at tcp://… closed during transport authentication — …"}
  ]
}
```

Field notes:

- `resolution` is the daemon's *live* result including re-resolves — the
  thing `status` could never see. `note` carries the resolver's verbatim
  `Resolution.Note` (unchanged strings; doctor check 4 prints them verbatim).
- `auth.secretState` is `ok | absent | malformed` from the daemon's own last
  per-conn read. Mode and path only — **never bytes, proofs, or digests**
  (digest comparison is doctor's job, done directly against the files).
- `mirror.entries[].state` is `bound | skipped | bind-failed` — `skipped`
  entries plus `mirror.skip` make check 11 exact instead of log-scraping;
  `bind-failed` (the `logBindError` path) is check 10's live evidence of a
  forwarder winning the race.
- `recentRefusals` is a fixed 32-entry ring fed at the same call sites as the
  throttled refusal/skip log lines (mirror skips, macsync row-7 refusals,
  Mac-side auth refusals rows 4/5/6, reserved-byte row 9). Each entry carries
  the transport-auth §7 check ID when one applies, so doctor's evidence
  matching is by ID, not by string-parsing log text. The ring is what makes
  auth evidence work for the *foreground* daemon, which has no log file.

New exported accessors feeding the snapshot closure in `drawbridged`:
`mirror.(*Client).Snapshot()` (entries + skip + session state — the state
already sits behind `c.mu`), `macsync.(*Syncer).Snapshot()` (advertised set +
pool + session state — already behind atomics), and a small shared
`introspect.Ring` type both packages and `transportauth`'s throttle call into
(injected as a nil-safe recorder field, so the packages stay
daemon-independent and tests inject their own).

### 3.3 Behavior when absent, stale, or skewed

| Condition | Consumer behavior |
|---|---|
| No socket / `ECONNREFUSED` / dial timeout (250 ms) | "no daemon introspection" — doctor/status fall back to `install.Query()` + log-tail inference (today's behavior). Never an error by itself. |
| Payload unparseable | Treated as absent, plus a `warn` evidence line (corrupt daemon or truncated write). |
| `schema > 1` | Use the frozen `version` field for the skew check; everything else falls back to inference; evidence line names the schema mismatch. |
| `version` ≠ CLI version | Version-skew finding (check 9, `fail`), remedy `sudo drawbridge install` — same policy as §6 of ergonomics.md. |
| Root and user sockets both answer | `warn`: the documented fighting-daemons posture, with "stop one of them" remediation naming both PIDs. |

## 4. The check catalog

Report order is catalog order (1–11, then the auth block §5). Gathering
happens dependency-first: providers → target-VM selection → parallel probes,
every probe deadline-bounded (global `-timeout`, default 30 s; provider-shell
scripts 10 s; socket dials 250 ms) so doctor terminates against a wedged VM.

Target-VM selection mirrors `up`: explicit `-vm provider:name` wins; else the
single running vz instance; ambiguity lists instances and guest-side checks
report `skip` with "pass -vm". Doctor also accepts `-vm-subnet`/`-vm-mac`
(same grammar as the daemon) so its route/lease views match a pinned install.
**Under euid 0 there is no instance list to select from** (limactl refuses
root — the vmprovider invariant), so selection mirrors the root *daemon*
instead: explicit `-vm`, else the daemon's default VM, through `ParseRef`
(the one vmprovider symbol root may touch) and the lease db. Provider and
guest-shell checks skip with the root-scoping reason; resolution and check
6's probe still run — the first cut gated them on the instance list, which
made `sudo drawbridge doctor` skip the very probe it exists to run
(amendment 2026-08-01, found on the first live root run).
All guest access goes through `vmprovider.Shell` with the standing
convention: argv is single space-free words, scripts ride stdin, and every
script is read-only (`cat`, `stat`, `test`, `ss`, `systemctl is-active`,
`sha256sum` — under `sudo -n` only where the file is root-0600).

Per check: **Inputs** (pure = classified from injected values; live = the
gather step that produces them), **Classification**, **Remedy job** (the §5
discipline: the strings state condition → likely cause → the one command).

**1. `providers` — providers present, instances runnable.**
Inputs: `vmprovider.Detect()` results + `List()` per provider (live);
classification pure over `[]Instance`. No provider binaries → `fail`
("install lima or colima"). Providers but nothing running → `warn` with the
start hint. Running `VMType == "qemu"` instances → `warn` per instance with
the vz switch line (`colima start --vm-type vz` / lima `vmType: vz` — §3.1
matrix verdict "rejected with doctor message"). Running vz → `ok`, listed
with MAC (the pin candidates).

**2. `guest-prereqs` — BTF, cgroup v2, systemd, kernel ≥ 5.7, runtime
versions.** Inputs: one stdin script emitting `key=value` lines (`btf=`,
`cgroup2=`, `systemd=`, `kernel=`, `runc=`, `oci=` from
`/etc/drawbridge/provision.json` presence); parser + classifier pure.
Kernel compare is a parsed semver-ish check, not a string compare. runc/crun
lines only classified when the guest was provisioned `--oci`. Alpine/OpenRC
(no systemd) → `fail` with the §3.1 rejection message. VM not running →
`skip` with the start hint.

**3. `agent` — unit active, version, transport listening.** Inputs: guest
script — `systemctl is-active` on both unit names (persistent from `up`,
transient from `agent-up`), `cat /run/drawbridge-agent.version`, `ss -ltn`
filtered to :4777 (pure parse: loopback bind, vzNAT bind, or both).
Classification: no unit active → `fail` ("run `drawbridge up <vm>`");
version ≠ `buildinfo.Version` → `fail`, remedy "`drawbridge up` re-pushes the
embedded agent" (§6 skew policy — `up` auto-heals this side); listening on
loopback but not the vzNAT address → `warn` (agent predates scoped bind or
`-transport` overridden; vznat-direct impossible, name it). **The `ss`
result is retained as cross-evidence for checks 4/6:** an agent listening
in-guest refutes `NoteAgentNotListening` when the Mac-side probe still fails.

**4. `resolution` — run the resolver, print its words verbatim.** Inputs:
`limaaddr.ResolveTarget` (live; **no changes to resolver logic** — doctor
imports and calls) and, when available, the daemon snapshot's `resolution`.
Print `Endpoint`/`Source`/`Note` exactly. Classification: vznat-direct → `ok`;
any fallback → `warn` carrying the Note verbatim **plus doctor's
cross-reference lines**: if check 3 proved the agent listening while the Note
says "agent not reachable", doctor appends "the guest side is listening — the
errno classification is known to misread host-side gates on macOS 27
(silent-timeout Local Network denial, per-binary LS drops); check 6
discriminates." The ssh-forwarder wrong-VM hazard (Phase 3 addendum: colima
target silently attaching to the dev VM's loopback :4777) is named whenever
`source=ssh-forwarder` and more than one VM is running.

**5. `vznat-route` — route and ARP present.** Inputs: `netstat -rn -f inet`
and `arp -n <candidate IP>` output (live), parsed pure. Route for the vmnet
subnet missing → `fail` naming the finding-1 pathology (route deleted while
`bridge100` still holds the gateway address; Tailscale / LS-uninstall
suspects) and the exact remediation:
`sudo route -n add -net 192.168.64.0/24 192.168.64.1` (substituting a
non-default `-vm-subnet`). Route present, ARP absent, guest running → `warn`
(first traffic populates it; only meaningful with probes also failing).

**6. `local-network` — the sudo discriminator, both branches spelled out.**
Inputs: doctor's own unprivileged TCP dial to the resolved vzNAT candidate
(live; skipped when check 4 already returned vznat-direct — the connect
succeeded), tier-1/tier-2 root evidence per D1, check 7's NE-filter presence,
check 3's in-guest listening evidence. Classification is the four-state
table — **pure over `(userProbe, rootEvidence, neFilterPresent)`**:

| user probe | root evidence | Verdict |
|---|---|---|
| ok | any | `ok` — the permission is not blocking this binary. |
| fail | ok (tier 1, same binary) | `fail`: **Local Network gate confirmed.** Remedies, in TN3179-exemption order: `sudo drawbridge install` (root launchd daemon — exempt twice over, the permanent posture); run from Apple Terminal/SSH (exempt responsible process); the subnet-exemption defaults (`sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses -array "<subnet>"` + WiFi key + reboot). |
| fail | ok (tier 2, daemon vantage) | `fail` with the same remedies **plus the per-binary caveat**: when check 7 found an NE content filter, the daemon binary being allowed does not exonerate the filter for this CLI — "conclusive: `sudo drawbridge doctor`". |
| fail | fail | `fail`: **not the LN gate alone** — an LS-class content filter (check 7's evidence; root is exempt from the permission but not from an NE filter) or a genuine network fault (check 5). Never mentions the LN remedies as the fix. |
| fail | unknown | `warn`, never a conclusion: print the discriminator instruction verbatim — "run `sudo drawbridge doctor` and compare: root-ok + user-fail ⇒ Local Network gate; both-fail ⇒ content filter or network fault." |

Under euid 0, the check runs the probe, reports the `root-probe` branch, and
states it cannot see the unprivileged branch from here. In every non-ok
state the check appends the standing caveat: *absence from Little Snitch's
Network Monitor is not exoneration — LS 6.5's monitor shows nothing for
flows its own filter drops, and the 27.0b4 LN gate drops flows before any
filter sees them.*

**7. `ne-filter` — DPI middlebox, passive.** Inputs: `systemextensionsctl
list` output (live), parsed pure for activated content-filter/network
extensions. Present → `warn`: names the extension(s); states the three
observed LS signatures (first-payload DPI stall on ambiguous method
prefixes; TCP half-close kill on non-loopback flows; per-binary
connect-then-die for unruled binaries) and that these persisted **even with
the filter "disabled"** — only deactivating the NE extension stops them
(System Settings → Login Items & Extensions → Network Extensions); states
that bench numbers are invalid while active. Absent → `ok`. No active DPI
timing probe in v1 (§5's stated rejection stands; check 8 is the active
counterpart, opt-in).

**8. `half-close-probe` — active, opt-in `-probe`.** Per D6 and its
amendment. Not run without the flag (`skip`, "pass -probe"). Pass on
non-loopback → `ok` (genuine evidence). Starved read → `fail` naming the
finding-4 signature and the suspects in order (NE filter when check 7 fired;
otherwise the forwarder — the reason `LIMA_SSH_PORT_FORWARDER=true` is
pinned). Loopback endpoint → result reported but labeled non-evidence for the
vznat path, in both directions: a loopback starve is a `warn` and never the
`fail`, because loopback is exempt from both LS bugs and the fail branch's
remedies would send the user after the wrong thing. A dial or handshake that
never produced a session → `skip` pointing at checks 4/6 and the auth block,
which own that diagnosis and already print its remedy.

**9. `daemon` — install state, version skew, liveness.** Inputs:
`install.Query()` (as today), **new** `install.InstalledVersion()` (exec
`BinaryPath -version` — root-owned 0755, executable unprivileged; absent →
skip), the introspection snapshot(s), log tail. Classification: installed
daemon version ≠ CLI → `fail`, remedy `sudo drawbridge install` (§6: brew
caveat "after upgrade: `drawbridge up && sudo drawbridge install`"); snapshot
`version` ≠ CLI → same; plist present but not loaded → `warn` (booted out by
hand); both root and user sockets alive → the D3 fighting-daemons `warn`;
nothing installed and no foreground daemon → `warn` with both options named
(`sudo drawbridge install` for <1024 + permanence, or foreground
`drawbridged`). Log tail rides along as evidence lines (row-7 refusals
surface here per the §7 contract: presence in the tail/ring is the alarm,
no dedicated check ID).

**10. `coexistence` — provider forwarder overlap.** Inputs:
`vmprovider.Forwarding(inst)` (live) → `Forwarding{HostAgent, Loopback,
Wildcard}` port sets; snapshot `mirror.entries` `bind-failed` states as live
evidence. Wildcard/loopback coverage present → `warn` printing the §3.4
tradeoff honestly: mirror binds that lose the race degrade to the
provider's forwarder (reachable, but no synchronous EADDRINUSE on those
ports and a slower path); reverse path and in-guest arbitration unaffected;
opt-in instructions for full semantics = the template `ignore` rule **with
all three keys** (`guestIP: "0.0.0.0"`, `guestIPMustBeZero: false`,
`proto: any` — lima#4403: a bare `ignore: true` matches loopback binds only)
and the warning to verify after restart. Never suggests auto-disable.

**11. `skip-visibility` — the default exclusion, discoverable.** Inputs:
snapshot `mirror.skip` + `skipped` entries when available, else log-tail
skip lines. Always `ok`/`info`-grade: "guest :22 is not mirrored (default
skip-list; `-skip ""` or `-skip "…"` on drawbridged/install to override)" —
placed exactly where a confused user will look, per the §7 policy that skips
are logged and discoverable.

## 5. The auth checks (transport-auth §7 contract)

The five IDs are the contract; the strings' jobs are fixed in §7 and not
re-litigated here. Two evidence classes feed them:

- **State comparison (authoritative, doctor-computed):** Mac side —
  `transportauth.PathForRef` for the target VM, stat + parse (doctor runs as
  the file's owner). Guest side — `sudo -n sha256sum
  /etc/drawbridge/transport-secret` and a `stat` through the provider shell
  (read-only; the same digest-compare posture `up`'s converge step already
  uses). Doctor compares digests in memory and prints **verdicts plus at
  most an 8-hex-char digest prefix per side** — sanctioned by
  transport-auth §5 ("log a digest prefix only in doctor, where comparison
  is the point"); never bytes, never proofs.
- **Runtime evidence:** the introspection `recentRefusals` ring (ID-tagged
  at the emit sites) and the daemon log tail — for conditions only the wire
  can reveal.

| Finding ID | Condition (state comparison first) | Status + remedy job |
|---|---|---|
| `auth` (healthy/unauth umbrella) | Both present, digests equal, modes/format ok → `ok` ("mutual auth on every conn"). Both absent → `warn`: the §6 fail-open state, flagged on sight — "transport is UNAUTHENTICATED; `drawbridge up <vm>` provisions a secret." (Warn not fail: the bare dev flow is legitimate and loudly logged.) |
| `auth-mac-missing-secret` | Guest file present, Mac file absent at the derived path (or ring/log rows 1/6) | `fail` — point at the Mac side while the guest is healthy: "`drawbridge up` writes it; `sudo drawbridge install` points the daemon at it." |
| `auth-guest-missing-secret` | Mac file present, guest file absent (or ring/log row 3) | `fail` — "run `drawbridge up <vm>` to provision one." |
| `auth-mismatch` | Both present, digests differ (or ring/log rows 2/4) | `fail` — name convergence, not blame: "re-run `drawbridge up <vm>` to converge" (stale snapshot-restored VM walked through in §7). |
| `auth-wrong-peer` | **Evidence-only** — ring/log row-4 line (per the ratified amendment: row 5 is practically unreachable, the refused side closes first, so row 4's line *is* the wrong-peer evidence) while doctor's own digest comparison says the provisioned pair matches | `fail` — "the daemon authenticated against something that is not this VM's agent — resolution source `<s>`; check `-vm` and whether the transport fell back to the loopback forwarder." Must name the resolution source (the §7 row-5 job, carried by row 4). |
| `auth-file-perms` | Either file exists but mode ≠ 0600, wrong owner, or malformed (≠ 64 lowercase hex + `\n`) | `fail` — names the file, the expected mode, and the expected format, both sides. |

When digests differ *and* row-4 evidence exists, the evidence corroborates
`auth-mismatch` (one condition, two vantage points — §7's own note) and
`auth-wrong-peer` is not emitted. VM not running → guest-side comparisons
`skip`; Mac-side file checks still run.

## 6. Report types and exit codes

```go
// internal/doctor
type Status string // "ok" | "warn" | "fail" | "skip" | "info"
type Finding struct {
    ID       string   // stable: catalog + auth contract IDs
    Title    string
    Status   Status
    Evidence []string // verbatim probe lines, resolver Notes, log lines
    Remedy   string   // one line; empty when Status == ok
    Data     map[string]any `json:",omitempty"` // structured extras (-json)
}
type Report struct {
    CLIVersion string
    RanAt      time.Time
    VM         string             // canonical ref, when selected
    Daemon     *introspect.State  // embedded verbatim when a socket answered (D5)
    Findings   []Finding
}
```

Text output: one line per finding (`[ok] agent v0.1.0 …`), evidence indented,
remediation prefixed `→`. `-json` marshals `Report`. Exit codes: `0` no
fails (warns allowed), `1` at least one fail, `2` doctor itself could not
gather (e.g. no providers *and* an explicit `-vm` that cannot resolve). The
codes are part of the contract (scripts and the acceptance matrix branch on
them), mirroring `status`'s documented 0/1/3.

The CLI's terminal renderer (`cmd/drawbridge/render_doctor.go`) styles this
form without changing its words: status tags and summary counts take the
TUI's §3.6 ANSI-16 adaptive colors, tags pad to one title column, and the
default is calm (amended 2026-08-01 after live use — the first cut kept
full evidence for every non-ok status and still read as a wall). Every
finding renders its title line; `warn`/`fail` add only the remedy arrow
(or their first evidence line when no remedy exists, so a verdict never
stands bare); `skip` adds its one-line reason ("pass -probe"); `ok` and
`info` are title-only. `-v` restores full evidence for everything, and
the summary says so whenever anything was elided. Color is never the only
carrier — `NO_COLOR`, `TERM=dumb` and piped output print the same words
uncolored.
`internal/doctor.Render` stays the plain presentation-free form (fixtures
and tests), and `-json` is unaffected by `-v`.

## 7. Affected files

- `internal/doctor/` *(new)* — `report.go` (types above), `checks.go` (pure
  classifiers, one per catalog entry), `auth.go` (pure auth classifier over
  stat/digest/ring inputs), `gather.go` (impure probes: provider shell
  scripts, netstat/arp/systemextensionsctl execs, TCP probe, socket dial),
  `probe.go` (check 8), `*_test.go` (fixtures: `systemextensionsctl` output,
  `netstat -rn`, `arp`, `ss`, version files, lease-note strings, ring
  entries, four-state discriminator table).
- `cmd/drawbridge/doctor.go` *(new)* — flag set (`-json`, `-probe`, `-vm`,
  `-vm-subnet`, `-vm-mac`, `-timeout`), gather → classify → render.
- `cmd/drawbridge/main.go` — verb dispatch + usage line.
- `internal/introspect/` *(new)* — `state.go` (payload types, schema const),
  `server.go` (write-only accept loop), `client.go` (dial + decode + skew
  posture), `paths.go` (D3 path derivations), `ring.go` (the shared refusal
  ring recorder).
- `cmd/drawbridged/main.go` — `-introspect` flag, snapshot closure wiring,
  ring injection into mirror/syncer/auth throttle.
- `internal/mirror/mirror.go` — `Snapshot()`, entry-state tracking
  (`bound|skipped|bind-failed`), ring hook.
- `internal/macsync/sync.go` — `Snapshot()`, ring hook.
- `internal/transportauth/mac.go` — the throttle additionally records into
  the ring (nil-safe field; no behavior change when unset).
- `internal/install/` — `InstalledVersion()` (small; §5's named addition);
  `status.go` doc-comment update (the "does not talk to the daemon" sentence
  becomes "reads the introspection socket when present; never *requires*
  the daemon").
- `internal/e2e/` — one new leg: an in-process daemon pair serving
  introspection on a temp socket; the leg's mirror client goes through the
  existing `newMirror`/`Auth:` seam like every other.
- Docs: `docs/privileged-daemon.md` §6 amendment (§10 below),
  `docs/transport.md` cross-reference from §2.2 to check 6's discriminator,
  `AGENTS.md` invariant addition (§10), and the builder's Phase 5 results
  in `docs/ergonomics.md`/`docs/HANDOFF.md`.

Nothing under `internal/bpf/`, no agent/guest code, no wire changes, no
resolver-logic changes. (If any phase discovers it needs one of these, the
design is wrong — stop and re-open.)

Test traps carried forward from the handoff: any doctor/CLI test touching
`transportauth` paths isolates `HOME` (`t.Setenv("HOME", t.TempDir())` — the
`secret_test.go` discipline); the new e2e leg routes through the auth seam;
introspection unit tests use `t.TempDir()` sockets, never the real paths.

## 8. Alternatives rejected

- **Request/response RPC on the introspection socket** (including "daemon
  performs the root probe on demand"). Rejected: it reopens the exact
  input-surface question privileged-daemon.md §6 closed, and the passive
  snapshot already carries the root-vantage evidence (the daemon probes by
  existing). Revived if a consumer genuinely needs daemon-side *actions* —
  then as a deliberately designed verb set behind its own decision, not a
  growth of this socket.
- **TCP loopback introspection port.** Rejected: no filesystem permissions,
  reachable by any local process; unix sockets give owner/group gating for
  free and match the `unix://` grammar already in `internal/transport`.
- **Doctor spawning `sudo` for the discriminator.** Rejected: credential
  prompts mid-diagnostic, and it breaks "doctor never mutates" *trust* even
  though a probe mutates nothing. Printing the one-liner keeps the user in
  control; euid-0 doctor covers the other branch.
- **Log-file-only auth evidence (no ring).** Rejected: the foreground daemon
  has no log file, and string-scraping throttled log lines is fragile; the
  ring is ID-tagged at the emit site.
- **One shared JSON document for doctor and introspection.** Rejected per
  D5: different owners and lifetimes; embedding is strictly simpler.
- **Synthetic DPI timing probe.** Stays rejected per §5: it would re-derive
  finding 3 on the user's machine for marginal value; passive check 7 +
  opt-in check 8 cover the field cases.

## 9. Build phases

Each independently landable; the system works after each. The user performs
any push.

**P1 — doctor core, no daemon dependency.** `internal/doctor` +
`cmd/drawbridge/doctor.go`: checks 1–5, 7, 9 (Query + `InstalledVersion`,
no snapshot), 10, 11, the auth block on state comparison + log tail, check 6
in tier-1 form (user probe, euid-0 branch, printed discriminator; tier 2
lands in P3). `install.InstalledVersion()`.
*Verify:* `go test ./internal/... ./cmd/...` (every classifier over
fixtures, incl. the full four-state discriminator table and a
route-table/arp fixture pair); live broken-state matrix per ergonomics §8:
agent stopped (`just agent-down`-equivalent → doctor names it), route
removed (`sudo route delete` → doctor prints the restore command), version
mismatch (rebuild CLI with bumped `-ldflags` version → doctor flags the
guest and the daemon), flipped-hex-digit secret → `auth-mismatch` with
prefix evidence, `-json | jq .` round-trips.

**P2 — introspection substrate.** `internal/introspect` (state, write-only
server, client, paths, ring), snapshots in mirror/macsync, ring wiring in
transportauth throttle, `drawbridged -introspect`.
*Verify:* `go test ./internal/...` (server/client over temp sockets: payload
round-trip, never-reads property — client writes garbage first and the
snapshot still arrives; schema-skew reader posture; ring overflow); `just
e2e` stays 13/13 (needs `just agent-up`); live: foreground `drawbridged`
answers on the user socket, `sudo drawbridged` on the root socket with
0660 root:staff verified by `ls -l`.

**P3 — consumers.** Doctor tier-2 enrichment (check 6 daemon vantage with
the per-binary caveat, check 9 snapshot section + fighting-daemons warning,
auth ring evidence, check 11 exact skip states); `status` daemon section
(D7, exit codes untouched); new e2e introspection leg.
*Verify:* `go test ./internal/... ./cmd/...`; `just e2e`; live: installed
root daemon + `drawbridge doctor` shows tier-2 evidence; `drawbridge
status` gains the daemon lines and keeps 0/1/3 (checked against a stopped
daemon).

**P4 — `-probe`, docs, invariants.** Check 8 behind `-probe` gated on the
live agent-FIN verification (D6); privileged-daemon.md §6 amendment;
AGENTS.md invariant; transport.md cross-reference.
*Verify:* live on the dev VM: probe passes with the LS extension
deactivated, and (environmental, recorded honestly like
`TestForwarderHalfClose`) reproduces the starved-read fail with it active;
`just e2e` regression; no `just test-guest` needed anywhere in this plan —
state in the results if that held.

## 10. Posture amendments (apply in P4, wording proposed here)

**privileged-daemon.md §6** currently reads "**No control socket, no IPC, no
XPC, zero new inbound surface** — `drawbridge status` reads launchctl and
the log file, it does not talk to the daemon." This design reverses that
deliberately (ratified 2026-08-01). Proposed replacement: "**One inbound
surface, shaped to be undriveable:** a read-only introspection unix socket
(`/var/run/drawbridge/introspect.sock`, `0660 root:staff`) whose protocol is
write-only — the daemon writes one state snapshot and closes, and **never
reads a byte from the client**, so there is nothing to drive. No control
verbs, no request grammar; the payload contains nothing beyond what
netstat, the lease db, and the daemon log already expose, and never secret
bytes, proofs, or digests. `status` and `doctor` read it when present and
never require it."

**AGENTS.md invariant (proposed):** "**The introspection socket is
write-only and state-only.** The daemon never reads from an accepted
introspection conn (no request grammar — nothing to drive), never serves
secret bytes/proofs/digests through it, and grows no control verbs; a
consumer that needs the daemon to *do* something is a new design decision,
not a new field. Doctor never mutates state — probes are reads, remediations
are printed, and the sudo discriminator is an instruction to the user, never
a doctor-spawned `sudo`."

## 11. Open questions for the user, ranked by plan impact

1. **Root socket group: `0660 root:staff` (recommended) vs `0600` vs
   `0666`.** Impact: whether unprivileged doctor/status/TUI get tier-2
   evidence at all (`0600` forces sudo for every enriched read, gutting the
   substrate's point) vs exposing daemon state to non-staff local accounts
   (`0666`). `0660 root:staff` covers every console user and stays
   narrowable-by-default; widening later is backward-compatible.
2. **Check 8 in v1 (recommended: yes, opt-in, gated per D6) vs slipping to
   Phase 7.** Impact: whether the gvproxy spike's disqualification gate
   exists before the spike; cost of shipping is one probe function whose
   worst case is a `skip` verdict.
3. **The `auth` umbrella's both-absent state: `warn` (recommended) vs
   `fail`.** Impact: whether the bare dev flow (`just agent-up`, no `up`)
   makes doctor exit 1. §6 of transport-auth calls it a legitimate,
   loudly-logged mode; `fail` would train dev users to ignore red.
4. **AGENTS.md wording in §10** — accept/amend; it binds future sessions.
5. **`status` multi-daemon shape:** additive `daemon:` lines for every
   answering socket (recommended) vs a `-vm` flag on `status`. Impact:
   trivial either way; additive keeps `status` argument-free.
