# Privileged drawbridged: root LaunchDaemon + install story

*Design note, 2026-07-30. Status: **shipped 2026-07-30** — approved with all
four §11 questions answered as recommended (leases-file discovery; opt-in
LaunchDaemon for MVP; Mac-only install; identity strings as proposed), then
built and accepted in three phases; results in
[plan.md](plan.md#privileged-daemon-results-2026-07-30). Companion to
[transport.md](transport.md) (the endpoint seam this daemon dials through)
and [plan.md](plan.md) (architecture).*

## 1. Why

Three problems, one posture change:

1. **Ports <1024.** macOS reserves them for root with no `reservedhigh`
   sysctl. Today `mirror.Client.logBindError` (mirror.go ~250) logs-and-skips
   an `EACCES` mirror bind, and `handleReserve` (mirror.go ~370) answers
   `"unknown"` → CONTINUE for a <1024 reservation — the guest bind degrades
   to async instead of getting Phase 4's synchronous answer. The MVP demo
   (`docker run --network host nginx` → `curl localhost:80`) is impossible
   without privilege.
2. **Service posture.** drawbridged is a foreground process you run in a
   terminal. A real tool survives reboots, restarts on crash, and has an
   install/uninstall/status story.
3. **Local Network permission.** The vzNAT-direct transport needs macOS
   Local Network permission, and getting it granted for a CLI is the
   per-machine defaults-and-reboot ritual documented in
   [notes/local-network-permission.md](notes/local-network-permission.md).
   Its §TL;DR item 3 / finding 4 is load-bearing: **TN3179 automatically
   exempts any launchd daemon and any program running as root.** A root
   LaunchDaemon makes vzNAT-direct work out of the box on any machine — no
   subnet-exemption defaults, no reboot, no Settings toggle. This is a
   primary driver, not a side benefit.

All three are solved by running drawbridged as a **root launchd daemon**
(`LaunchDaemon`, not `LaunchAgent` — agents run as the user at login and are
*not* TN3179-exempt). This is the same category of thing as Docker Desktop's
`com.docker.vmnetd` and OrbStack's privileged helper: an ordinary root
daemon granted by the OS's normal mechanism, no kernel extensions, no
entitlement games.

## 2. Decision summary

| Decision | Choice (MVP) | Deferred alternative |
|---|---|---|
| Privilege model | whole drawbridged runs as root | privilege-separated split (§7); the seam is designed now, built later |
| launchd unit | LaunchDaemon, `RunAtLoad` + `KeepAlive` | SMAppService/SMJobBless signed helper (needs an app bundle + signing) |
| Install flow | `sudo drawbridge install` (CLI writes plist, copies binary, `launchctl bootstrap`) | package installer / brew formula |
| Root endpoint discovery | `/var/db/dhcpd_leases` parsing as a new resolver source (§4) | install-time pinned endpoint; user-side LaunchAgent handoff |
| Logs | launchd `StandardOutPath`/`StandardErrorPath` → `/Library/Logs/drawbridge/drawbridged.log` + a `newsyslog.d` rotation entry | os_log adoption |
| Guest side | untouched — `just agent-up` remains the guest story | install-managed persistent guest systemd unit |

## 3. What changes

### 3.1 drawbridged itself: almost nothing

launchd runs daemons in the foreground — no daemonization, no fork, no
pidfile. `cmd/drawbridged/main.go` keeps its exact process model; the same
binary serves `sudo ./bin/drawbridged` (dev) and the LaunchDaemon (installed).
Two additions only:

- **Loopback guard under root** (new invariant enforcement): if
  `os.Geteuid() == 0` and `-mirror-ip` is not a loopback address, `log.Fatal`.
  Mirrors bind `127.0.0.1` only is a standing AGENTS.md invariant; a root
  daemon binding wildcard would be a real regression, so as root there is no
  override flag at all.
- `logBindError`'s <1024 message gains the actionable hint: "run
  `sudo drawbridge install`".

`internal/mirror/mirror.go` bind paths are otherwise **unchanged**: as root,
`net.Listen` on `:80` simply succeeds, `logBindError` stops firing for
privileged ports, and `handleReserve`'s `"unknown"` degrade branch stops
being reachable for them — the reserve-before-ack semantics (bind the real
listener *before* acking, pending entry adopted by the tracker add or
released by `ReserveTTL`) need no modification. `internal/macsync/sync.go`
is unchanged too: the `net.inet.tcp.pcblist_n` sysctls are readable
unprivileged, so root changes nothing about Mac listener visibility.
**`internal/bpf` is untouched — nothing in this direction goes near the
guest kernel side.**

### 3.2 Install machinery: `internal/install` + CLI verbs

New package `internal/install` (paths, plist rendering, launchctl wrappers,
euid checks — plist rendering and path policy unit-testable without root),
driven by three new verbs in `cmd/drawbridge/main.go` (currently a Phase 1
stub, so this is greenfield):

- **`drawbridge install [-vm drawbridge] [-udp ports]`** (requires `sudo`;
  refuses with instructions otherwise). Steps, idempotent on re-run:
  1. `launchctl bootout system/com.archcorsair.drawbridged` if already
     loaded (refresh path).
  2. Copy the `drawbridged` binary from beside the invoking `drawbridge`
     binary (or `-bin` override) to **`/usr/local/libexec/drawbridged`**,
     root:wheel 0755. Copying out of the user-writable build tree is
     mandatory — a plist pointing at `~/ghq/…/drawbridge/bin/` would be a
     user→root escalation (any code that can write the file runs as root on
     next boot).
  3. `mkdir -p /Library/Logs/drawbridge` and write
     `/etc/newsyslog.d/drawbridge.conf` (one line: rotate at 1 MB, keep 5).
  4. Render `/Library/LaunchDaemons/com.archcorsair.drawbridged.plist`
     (root:wheel 0644) and `launchctl bootstrap system` it.
  5. Poll `launchctl print system/com.archcorsair.drawbridged` until
     `state = running`, then echo the daemon's resolved-endpoint log line.
- **`drawbridge uninstall`** — bootout, remove plist + binary + newsyslog
  entry; logs are kept.
- **`drawbridge status`** — plist present? `launchctl print` state + pid?
  Tail the last few log lines (the `agent %s (source=%s)` line is the
  observable transport state). Works without root.

The plist (rendered, not a static asset):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.archcorsair.drawbridged</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/libexec/drawbridged</string>
    <string>-agent</string><string>auto</string>
    <string>-vm</string><string>drawbridge</string>
    <!-- -udp N,N appended when given at install time -->
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Interactive</string> <!-- data plane; avoid background QoS throttling -->
  <key>StandardOutPath</key><string>/Library/Logs/drawbridge/drawbridged.log</string>
  <key>StandardErrorPath</key><string>/Library/Logs/drawbridge/drawbridged.log</string>
</dict></plist>
```

Notes: `-agent auto` (not a pinned endpoint) keeps the Phase 3 re-resolve
hook alive — see §4. No signing needed: LaunchDaemons run unsigned local
binaries fine (Gatekeeper gates quarantined downloads, not local builds).
launchd's default `ThrottleInterval` (10 s) is our crash-loop backstop; the
daemon's own reconnect loops (1 s backoff) handle the VM being down without
exiting, so KeepAlive churn only happens on real crashes.

### 3.3 Boot ordering and lifecycle

The daemon starts at boot; the Lima VM starts whenever the user starts it.
That's fine by construction: the mirror `'E'` session and macsync `'M'`
session already retry at 1 s with the resolver behind a 3 s minimum
interval — the daemon idles cheaply until an agent appears, and heals
endpoint flips (VM recreated → new vzNAT IP) through the same
`ReResolve` path that already handles forwarder→vznat promotion.

**Known sharp edge (deliberate, MVP):** an installed daemon and a dev
foreground `drawbridged` fight over the same mirror ports; the loser
logs-and-skips per bind. No single-instance lock for MVP — `drawbridge
status` shows whether the daemon is running, and the dev workflow is
`sudo launchctl bootout system/com.archcorsair.drawbridged` (or
`drawbridge uninstall`) before foreground runs. Flagged in §8.

## 4. Root endpoint discovery (the real design problem)

`limaaddr.Resolve` shells out to `limactl shell <vm> -- hostname -I`.
As root that breaks: `limactl` state lives in the invoking user's
`$LIMA_HOME` (`~/.lima`), root's `$HOME` is `/var/root`, and the daemon has
no idea which user owns the VM. Options considered:

1. **Pin the endpoint at install time** (`-agent tcp://IP:4777` rendered
   into the plist from the user's own resolution). Simplest, but wrong:
   vzNAT IPs are DHCP-stable per VM MAC yet not guaranteed — deleting and
   recreating the VM (which template edits require) mints a new MAC and a
   new IP, and a pinned `-agent` also disables the `ReResolve` hook by
   design (`main.go`: "nil when -agent is explicit"). Failure mode: daemon
   dials a dead IP forever until the user re-runs install. Rejected.
2. **User-side handoff**: a per-user LaunchAgent (or the CLI) resolves via
   `limactl` and tells the root daemon over a control channel. Correct and
   the eventual shape *if* we ever need per-user multi-VM routing — but it
   adds a second launchd unit plus an authenticated inbound IPC surface on
   the root daemon (who may retarget root's dials?), which §6 deliberately
   keeps at zero. Rejected for MVP; revived by the privilege split (§7).
3. **Parse `/var/db/dhcpd_leases`** (chosen). Lima's vz VMs get their vzNAT
   address from the macOS Virtualization/InternetSharing DHCP server, whose
   lease db is a world-readable plain-text file with `name=lima-<vm>` /
   `ip_address=…` records (verified present on this machine). No
   `$LIMA_HOME`, no shelling out as the wrong user, no new trust surface —
   read-only parse of an OS-owned file, exactly how Tart/UTM tooling finds
   VM IPs.

Concretely: `internal/limaaddr` grows a third source,

```
SourceVZNATLeases = "vznat-leases"
```

Resolution order becomes: `limactl` path (works when run as the VM-owning
user; fails fast as root) → leases parse for `name=lima-<vm>` candidates,
newest lease first, each candidate probed with the existing 800 ms dial
probe → SSH-forwarded loopback `127.0.0.1:4777` (the user-session `lima`
forward is a plain loopback listener; root can dial it like anyone).
Stale-lease ambiguity (recreated VM leaves old records) is resolved by the
probe, same as today's reachability classification. The parser is a pure
function over the file's text — unit-tested against a fixture, no root
needed.

What breaks if Apple changes the leases format: the source degrades to the
forwarder with a resolver `Note` saying so in words (transport.md's
diagnosis discipline), and option 1 becomes the stopgap. The format has
been stable for many years and is widely depended on.

## 5. What does NOT change

- `internal/bpf` — **nothing**. No guest-side changes at all.
- `internal/mirror` bind/reserve logic (§3.1) — root makes the existing
  code sufficient; only the log hint changes.
- `internal/macsync` — pcblist polling is unprivileged already.
- The transport seam, frame protocol (4-byte conn-type frames, `'R'`
  reserve frames, v1 UDP frames), and the `'E'`-stream filtering rules —
  all frozen invariants, all untouched.
- Mirrors bind `127.0.0.1` only — now *enforced* under root, not just
  defaulted (§3.1).
- Dev workflows: `just e2e`, `just bench`, `just test-guest` keep running
  in-process/foreground exactly as today (root only *adds* coverage, §8).

## 6. Security posture (explicit)

- **What runs as root:** the whole drawbridged process — mirror client,
  macsync syncer, splice loops. Accepted for MVP; the split is §7.
- **Listens on:** loopback mirrors of guest listeners and loopback UDP
  delivery sockets, `127.0.0.1` only, fatal-enforced under root — plus, since
  the Phase 5 introspection substrate (ratified 2026-08-01, design in
  [doctor.md](doctor.md) §D2/§D3), exactly one more: **one inbound surface,
  shaped to be undriveable:** a read-only introspection unix socket
  (`/var/run/drawbridge/introspect.sock`, `0660 root:staff`) whose protocol is
  write-only — the daemon writes one state snapshot and closes, and **never
  reads a byte from the client**, so there is nothing to drive. No control
  verbs, no request grammar; the payload contains nothing beyond what netstat,
  the lease db, and the daemon log already expose, and never secret bytes,
  proofs, or digests. `status` and `doctor` read it when present and never
  require it. (This reverses the original posture — "no control socket, no
  IPC, no XPC, zero new inbound surface" — deliberately, and the shape above
  is what the reversal bought back.)
- **Dials out to:** the guest agent (vzNAT IP or loopback forwarder, port
  4777) and `127.0.0.1:<port>` for reverse streams. Reads
  `/var/db/dhcpd_leases` (world-readable OS file). Shells out to `limactl`
  with flag-derived arguments only — never guest-derived data.
- **Trust relationship, stated plainly:** the guest agent's event stream
  drives the root daemon's binds. A compromised guest can therefore make
  root occupy any loopback port — now including <1024 — and steer local
  clients' loopback traffic into the guest. That is the product's feature
  set applied by an attacker, bounded by: loopback only (never LAN), the
  guest is the developer's own VM, and the daemon never executes
  guest-supplied data. This is the same power Docker Desktop's and
  OrbStack's privileged helpers hold, and the honest cost of `:80`
  semantics.
- **Escalation hygiene:** binary and plist are root-owned in root-owned
  directories; install copies the binary out of the user-writable build
  tree (§3.2 step 2). Nothing the user account can write is executed as
  root afterward.
- **Local Network permission:** as a root launchd daemon, drawbridged is
  TN3179-exempt (both "daemon" and "root" categories) — the per-machine
  subnet-exemption defaults in notes/local-network-permission.md stop being
  a setup requirement and demote to a diagnostic footnote.

## 7. The future privilege-separation seam

The right eventual shape: a minimal root helper owning only privileged
binds — it receives `{proto, port}` requests over an authenticated unix
socket and returns *bound listener fds* via `SCM_RIGHTS`; the daemon core
(mirroring, splicing, transport) drops back to the user. The seam that
makes this a refactor instead of a rewrite: `mirror.Client` has exactly
three bind sites (`openLocked`, `openUDPLocked`, `handleReserve`), all of
which can route through one injectable pair —

```go
Listen       func(ip string, port uint16) (net.Listener, error)   // default net.Listen
ListenPacket func(ip string, port uint16) (net.PacketConn, error) // default net.ListenConfig
```

— where the split's implementation is "these two fields dial the helper".
**Not built now** (MVP: fields don't even need to exist yet — the fact that
all binds flow through three named sites is the seam). Revive triggers:
first external security review, any multi-user requirement, or the day the
daemon needs an inbound control surface for other reasons (option 2 of §4).

## 8. Rejected alternatives (and what revives them)

| Alternative | Why rejected | Revived by |
|---|---|---|
| SMAppService / SMJobBless helper + XPC | needs a signed app bundle; we ship an unsigned CLI | shipping a signed .app / menubar UI |
| setuid drawbridged binary | worst of all worlds; no launchd supervision, no TN3179 daemon story | nothing |
| Privilege split now | two processes, fd-passing, an authenticated socket — real work for zero MVP capability delta | §7 triggers |
| launchd socket activation for <1024 (launchd binds, passes fds) | `Sockets` entries are static per-plist; guest ports are dynamic | nothing (wrong tool) |
| Pin endpoint in plist at install | breaks on VM recreation; disables ReResolve | leases format breaking (as a stopgap) |
| Per-user LaunchAgent endpoint handoff | new authenticated IPC surface on root for no MVP gain | privilege split / multi-VM routing |
| Subnet-exemption defaults as the shipped posture | per-machine machine-wide policy ritual + reboot — the exact fragility this design kills | nothing; stays a diagnostic |

## 9. Files touched

| File | Change |
|---|---|
| `internal/limaaddr/limaaddr.go` (+ new `leases.go`, `leases_test.go`) | `SourceVZNATLeases`; leases parser (pure, fixture-tested); resolution order §4 |
| `internal/install/` (new: `install.go`, `plist.go`, `install_test.go`) | paths, plist rendering, newsyslog entry, launchctl wrappers, euid checks |
| `cmd/drawbridge/main.go` | replace Phase 1 stub: `install` / `uninstall` / `status` / `version` verbs |
| `cmd/drawbridged/main.go` | root loopback guard for `-mirror-ip` |
| `internal/mirror/mirror.go` | `logBindError` hint text only |
| `internal/e2e/privileged_test.go` (new) | root-gated <1024 tests (§10 Phase 3), capability-probe skip + its pure decision table |
| `internal/e2e/e2e_test.go` | bind-probe helpers extracted for reuse by the privileged legs |
| `justfile` | `e2e-root` recipe (§10) |
| `docs/HANDOFF.md`, `docs/plan.md` | status/results on landing |
| `internal/bpf/**` | **NOTHING** |

## 10. Phases

Each independently landable and verified.

### Phase 1 — root-capable resolution + root guard

`limaaddr` leases source; drawbridged loopback-under-root guard;
(optionally) the `logBindError` hint.

Verify:
- `go test ./internal/...` — leases parser fixtures (multi-entry, stale
  lease, missing file, foreign VM names); guard unit if extracted.
- `just build`, then manual foreground root run: `sudo ./bin/drawbridged`
  → log shows `source=vznat-leases` (or `vznat-direct` is fine when run
  from a terminal as the user; the leases line is the root-path proof), then
  in the guest `docker run -d --rm --network host nginx` →
  `curl -sf http://localhost:80` on the Mac serves the nginx page. First
  <1024 mirror ever.
- `sudo ./bin/drawbridged -mirror-ip 0.0.0.0` → exits fatal.
- `just e2e` (non-root) — unchanged, still green.

### Phase 2 — install machinery

`internal/install` + CLI verbs.

Verify:
- `go test ./internal/...` — plist rendering golden test, path policy,
  idempotent-reinstall decision table (no root needed).
- **Manual acceptance sequence** (the MVP demo, end to end):

```sh
just build
sudo ./bin/drawbridge install                # copy binary, plist, bootstrap
./bin/drawbridge status                      # state=running, pid, "agent … (source=…)" log line
# inbound <1024 leg:
limactl shell drawbridge -- docker run -d --rm --name db-nginx --network host nginx
curl -sf http://localhost:80 | head -3       # nginx welcome page
limactl shell drawbridge -- docker rm -f db-nginx
# reverse leg (guest → Mac-native :80):
sudo python3 -m http.server 80 --bind 127.0.0.1 &
limactl shell drawbridge -- curl -sf http://127.0.0.1:80/
# synchronous EADDRINUSE leg (Mac still holds :80 — <1024 reserve path now definitive):
limactl shell drawbridge -- docker run --rm --network host busybox nc -l -p 80 -e true
#   → exits with "Address in use", synchronously
sudo kill %1
# lifecycle:
sudo ./bin/drawbridge uninstall
./bin/drawbridge status                      # not installed
```

- Reboot survival (once, optional): `sudo ./bin/drawbridge install`,
  reboot, `limactl start drawbridge` + `just agent-up`, re-run the curl leg
  with no daemon intervention.
- **Verification caveats on this machine:** (a) the Local Network
  exemption-free claim can only be *proven* here after removing the subnet
  defaults (`sudo defaults delete com.apple.network.local-network …` +
  reboot) and is confounded by the acknowledged 27.0b4 permission bug —
  treat "daemon logs `source=vznat-*` on a machine without the defaults" as
  the acceptance signal, ideally on a second machine; (b) any inbound-*bulk*
  verification (bench-class transfers) still needs the Little Snitch
  network extension deactivated (notes/local-network-permission.md
  finding 4 — half-close wedge on non-loopback flows); the small acceptance
  curls above are unaffected in practice.

### Phase 3 — root e2e coverage + docs — **DONE 2026-07-30**

Root-gated tests in `internal/e2e/privileged_test.go`: `TestPrivilegedMirror`
(guest `:80` listener → Mac fetch on `127.0.0.1:80`) and
`TestPrivilegedReserve` (Mac-held `:80` → guest bind fails synchronously
`EADDRINUSE`, i.e. the reserve answer is definitive, not
`"unknown"`-CONTINUE). Gate by capability probe, not euid: attempt a
`127.0.0.1:<lowport>` bind in-process and `t.Skip` on `EACCES`/`EPERM` —
skips gracefully in every unprivileged run of `just e2e`, no daemon required
(the suite runs its own in-process mirror client, so root e2e needs no
installed daemon either).

As built, three details beyond the sketch:

- The probe walks a **candidate list** (`:80`, then `:1023`). A port that is
  merely occupied proves nothing, so `EADDRINUSE` moves on to the next
  candidate; only `EACCES`/`EPERM` is a verdict and exhausting the list is an
  explicit "cannot tell", never a silent "not capable". The classification is
  a pure function (`privPortCapability`) over an injected probe, so both
  branches are unit-tested without root by
  `TestPrivilegedPortCapabilityDecision` — which also runs in a plain
  `go test ./internal/...`.
- The skip message names the exact root invocation, so a future privileged
  runner needs nothing but the `just e2e` output.
- `just e2e-root` wraps the root invocation; the guest bind-probe helpers
  (`guestBindProbe`, `waitBindArbitrationLive`) were lifted out of
  `TestGuestBindGetsSynchronousEADDRINUSE` and shared.

Verify:
- `just e2e` (non-root): both tests visibly SKIP with the root recipe in the
  message; suite green (11 tests: 9 pass incl. the capability table, 2 skip).
- Root run: `just e2e-root` — i.e. `sudo -E env "PATH=$PATH" DRAWBRIDGE_E2E=1
  go test -count=1 -v -run TestPrivileged ./internal/e2e/` (mise shims make a
  bare `sudo just e2e` unreliable, hence the explicit env passthrough).
  **Executed and green (2026-07-30, same night)** — both legs pass as root,
  resolving via `source=vznat-leases`. Getting there required teaching the
  e2e limactl helpers to drop to `$SUDO_USER` under euid 0 (limactl refuses
  root — the harness-side twin of §4's leases-file rationale).
- `just test-guest` — untouched, green.
- Flip HANDOFF.md's open item to done; append results to plan.md.

## 11. Open questions (ranked by how much the answer forks the plan)

1. **Root endpoint discovery via `/var/db/dhcpd_leases` — approve?** This
   is the load-bearing novel choice (§4). The alternatives (pinned endpoint
   / user-side handoff) reshape the resolver and the plist contract, so it
   forks Phase 1. Lease file verified present and parseable on this machine.
2. **Is the LaunchDaemon the default posture or a demo/opt-in posture?**
   MVP as designed: opt-in — dev keeps foreground `drawbridged`, e2e/bench
   stay in-process, and daemon-vs-foreground port fights are a documented
   sharp edge with no single-instance lock. If instead the daemon should
   become *the* way drawbridge runs (tests target it, foreground deprecated),
   Phase 3 grows a daemon-targeting test mode and the lock stops being
   deferrable.
3. **Guest side of install: Mac-only (as designed) or should `drawbridge
   install` also persist the guest agent unit?** Today the agent is a
   transient systemd unit (`just agent-up`) that dies with the VM session —
   so the "works after reboot out of the box" claim currently ends at the
   Mac side. Persisting the guest unit is small but crosses the
   Mac-CLI-manages-guest-state line for the first time.
4. **Identity strings:** label `com.archcorsair.drawbridged`, binary at
   `/usr/local/libexec/drawbridged`, logs at `/Library/Logs/drawbridge/`.
   Cheap to change now, annoying after real installs exist (uninstall by an
   old CLI won't find a renamed label).
