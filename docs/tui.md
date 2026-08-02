# Phase 5.5 — `drawbridge tui`: the read-only observability front end

*Design note, 2026-08-01. Companion to [doctor.md](doctor.md) §2 D2–D5/§3
(the introspection contract this consumes verbatim — nothing here changes
it), [ergonomics.md](ergonomics.md) §8 (the phase roadmap this slots into),
and [HANDOFF.md](HANDOFF.md) §Next. Status: capabilities ratified 2026-08-01
— all four v1 capabilities (live dashboard, refusals pane, doctor view,
multi-VM switcher), verb on the existing CLI, progressive disclosure as the
governing UX principle, TUI lands before v0.1.0 and Phase 6's docs wait on
it. This note fixes the shape, the dependency pins, and — because the Phase 6
quickstart will cite it — the navigation and keybinding map, final.*

## 1. Goal and shape

One new verb, `drawbridge tui`: a bubbletea front end over the daemon
introspection socket. It renders, at ~1 Hz, exactly what
`internal/introspect.State` already carries — per-daemon mirror table with
entry states, the sync advertised set and pool, live resolution
endpoint/source/note, auth posture, the ID-tagged refusal ring — for every
answering socket on the Mac, root and user, and runs the doctor catalog on
demand as an in-process view.

**The TUI is read-only by construction, not by policy.** The introspection
socket has no request grammar — the daemon writes one snapshot and closes,
never reading a byte (doctor.md §D2) — so there is nothing a TUI *could*
command even if it wanted to. The doctor view runs `internal/doctor`'s own
gather/classify pipeline in-process: it probes (reads), it never asks the
daemon to do anything, and it never spawns `sudo`. Anything that would need
the daemon to act — re-resolve now, drop a mirror, rotate a secret — is out
of scope by the AGENTS.md invariant ("a consumer that needs the daemon to
*do* something is a new design decision, not a new field") and is named in
§10 so nobody mistakes its absence for an oversight.

What this buys, concretely: the introspection substrate built in Phase 5
becomes *watchable*. Today the freshest view of a running daemon is
re-running `status` or `doctor` by hand; the failure modes that substrate
exists to surface — a mirror entry flipping to `bind-failed` when a
forwarder wins a race, an auth refusal streaming into the ring, two daemons
fighting over the same VM's ports — are events in time, and a 1 Hz snapshot
loop is the cheapest honest way to see them happen. The quickstart gets one
command that shows a new user their guest listeners appearing on Mac
localhost as they start containers, which is the product's whole pitch made
visible.

## 2. Decisions

**D1 — The verb is `tui`.** Rejected: `watch` (collides with `watch(1)`
semantics — re-run a command — and forecloses a plausible future
`drawbridge watch <port>`); `dash`/`dashboard` (oversells — implies metrics
and graphs — while underselling the doctor and refusals halves, which are
not dashboard-shaped). `tui` names the medium rather than one capability,
is what HANDOFF and the roadmap already call this work, and is unambiguous
in prose and grep. Renaming after Phase 6 means rewriting the quickstart,
so this is the one naming decision that gets expensive later: veto it now
or it ships (§11 q1).

**D2 — Schema 1 is untouched: v1 needs no new field.** Walked pane by pane:
the dashboard needs `vm` (ref/provider/instance), `pid`/`euid`, `version`,
`startedAt` (uptime is `time.Since`), `resolution`
(endpoint/source/note/resolvedAt), `auth` (mode/path/state — never bytes),
`mirror` (sessionUp/lastEventAt/entries/skip), `sync`
(sessionUp/advertised/udpPorts/poolParked); the refusals pane needs
`recentRefusals` (at/id/line); the switcher needs `vm` + the socket path
the client already returns on `Snapshot.Path`; "refreshed Ns ago" is the
client's own fetch timestamp. Every one of those exists. The daemon is not
touched by this phase — not one line.

**D3 — The dependency set is bubbletea + lipgloss, pinned; bubbles is
deliberately out.** Exact pins (checked against the module proxy
2026-08-01; both are the current heads of their stable v1 lines):

- `github.com/charmbracelet/bubbletea v1.3.10` (2025-09-17)
- `github.com/charmbracelet/lipgloss v1.1.0` (2025-03-12)

This pulls ~15 transitive modules, all in the charm/muesli ecosystem
(`charmbracelet/x/{ansi,term,cellbuf}`, `charmbracelet/colorprofile`,
`muesli/{termenv,ansi,cancelreader}`, `mattn/{go-isatty,go-runewidth,
go-localereader}`, `lucasb-eyer/go-colorful`, `rivo/uniseg`,
`aymanbagabas/go-osc52`, `xo/terminfo`, `golang.org/x/text`, and the
windows-only `erikgeiser/coninput`). The repo's existing
`golang.org/x/sys v0.43.0` already satisfies bubbletea's floor. Binary-size
cost is a few MB on a CLI that already embeds four guest binaries —
negligible.

`bubbles` — the assumption was v1 would take it for table/viewport/spinner
— is rejected after reading its go.mod: `bubbles v1.0.0` (2026-02-09,
tracks exactly bubbletea v1.3.10 + lipgloss v1.1.0, so it *is* compatible)
adds a second ring of dependencies we would never call — `atotto/clipboard`,
`sahilm/fuzzy`, `MakeNowJust/heredoc`, `dustin/go-humanize`,
`charmbracelet/harmonica`, `aymanbagabas/go-udiff`, three `clipperhouse/*`
modules — roughly doubling the new tree for three widgets this design
mostly can't use as-is anyway: the mirror table needs per-row state
coloring (hand-rolled with lipgloss either way), the doctor view needs a
cursor-list with expansion (not `viewport`'s shape), and a spinner is a
ten-line frame cycler on a tick the model already has. What v1 hand-rolls:
a scrollback region (~50 lines: offset, clamp, follow-bottom), the
spinner, and the keymap/help tables (which §4 fixes by hand regardless,
because the docs cite them). **What would revive bubbles:** a v2 view that
is genuinely list/table/filter-heavy (e.g. fuzzy-filtering hundreds of
mirror entries) or any text-input need. Adding it later is one `go get`;
removing it later is churn — this is the cheaper-to-reverse side.

Bubbletea v2 (in beta through 2025–26) stays out: no churn on a
pre-first-release dependency; revisit at v2 GA, after v0.1.0.

**D4 — One fetch path: `introspect.FetchAll` per tick; there is no separate
Discover cadence.** The draft assumption ("Discover every few ticks, Fetch
per tick") dissolves on reading the client: `FetchAll` already calls
`Discover()` internally on every invocation, and Discover is one `stat`
plus one glob — microseconds. Splitting the cadence would mean either
duplicating FetchAll's loop or adding a client entry point, to save
nothing measurable. So: every tick runs `FetchAll(introspect.DialTimeout)`
in a `tea.Cmd` goroutine; sockets appearing, disappearing, and going
stale are all caught within one tick by the same code path doctor and
status already exercise. An in-flight guard skips a tick's fetch if the
previous one hasn't returned (worst case per socket is the 250 ms dial +
2.25 s read deadline; sequential over N sockets that could briefly exceed
1 s — the guard means the UI drops a refresh rather than queueing them).

**D5 — Refusals accumulate client-side; the ring's loss bound is stated,
not hidden.** Each snapshot carries the daemon's fixed 32-entry ring. The
TUI keeps, per socket path, an append-only log: entries from the fresh
ring not already present (identity = the full `(At, ID, Line)` triple) are
appended in ring order, capped at 512 with oldest-first eviction. At 1 Hz
this is lossless up to 32 refusals per second sustained; past that the
overflow is gone, and the pane's header says "last 32 per refresh" so
nobody mistakes it for an audit log. No daemon-side change — the ring is
evidence, and 32/s of refusals is itself the finding.

**D6 — The doctor view runs gather asynchronously with a generation token;
the tick loop never blocks.** Entering the view starts
`doctor.Gather(ctx, opts)` in a `tea.Cmd` goroutine (it takes seconds —
guest shell probes at 10 s ceilings inside a 30 s budget; `-probe` has a
~20 s floor). The model stores a `context.CancelFunc` and an integer run
generation; `esc` cancels the context and bumps the generation, and a
completion message carrying a stale generation is dropped on the floor —
the canceled goroutine may take up to one probe timeout to unwind, but
nothing waits for it. Progress is a spinner plus elapsed seconds (Gather
exposes no finer granularity, and inventing fake progress stages would be
lying). Snapshot fetching continues underneath at full cadence, so
returning to the dashboard is instant and current. `Classify` is pure and
instantaneous; the view renders `Finding`s natively (§3.3) rather than
piping `Report.Render`'s text through a pager, because status coloring and
per-finding expansion are the point.

**D7 — Daemon identity and selection are keyed by socket path.** `Discover`
returns a stable order (root socket first, then the user dir sorted), and
`Snapshot.Path` names the source. The selected daemon is the path, not the
index: a socket appearing or vanishing never silently changes which daemon
the user is looking at. If the selected path stops answering, the view
stays on it and renders the no-daemon state for that path (with the rest
still one `tab` away) — a daemon dying is exactly the moment the user is
watching it, and yanking the view to a different daemon at that moment is
hostile. A path gone for 30 consecutive ticks is dropped from the switcher
(and selection falls to the first answering socket).

**D8 — Fighting daemons is a banner, not a view.** When two snapshots name
the same VM (canonical `provider`+`instance` pair; `ref` as fallback) from
different flavors (one from `RootSocketPath`, one from the user dir), a
persistent warn-styled banner renders across every view — dashboard,
refusals, doctor — naming both PIDs and the consequence: they fight over
mirror ports (the documented dev-posture pathology, doctor.md §3.3). The
banner clears itself when one stops answering. It is the one element
progressive disclosure never hides.

## 3. Information architecture

Progressive disclosure, made concrete: the default screen is the calm
dashboard for one daemon — no refusals, no doctor, no overlays — and every
other capability is one labeled keypress away, advertised by a one-line
footer. Nothing pops up on its own except the fighting-daemons banner (D8)
and the empty/degraded states, which are the screen telling the truth about
what answered.

### 3.1 The sane default: the dashboard

At 120×40 (the roomy case):

```
 drawbridge tui · CLI v0.1.0                                    daemon 1/2 · refreshed <1s ago ·  ? help
 ┌ colima:colima ─ user socket · pid 71234 · daemon v0.1.0 · up 2h14m ────────────────────────────────┐
 │ endpoint   tcp://192.168.64.5:4777    source vznat-direct    resolved 2h14m ago                    │
 │ auth       static-hmac-v1 · secret ok · ~/Library/Application Support/drawbridge/transport-secr…   │
 │ mirror     session up · last event 12s ago            sync   session up · pool 4 parked            │
 └────────────────────────────────────────────────────────────────────────────────────────────────────┘
  MIRROR — guest listeners on Mac localhost (5)          SYNC — Mac ports advertised to guest (3)
  PROTO  PORT   STATE         SINCE                      PROTO  PORT
  tcp    8080   bound         2m                         tcp    5432
  tcp    3000   bound         2m                         tcp    6379
  udp    5353   bound         1m                         udp    5353
  tcp    22     skipped       2h
  tcp    5000   bind-failed   40s
                                        skip list: 22
                                                                                                      
  tab next daemon · r refusals · d doctor · ? help · q quit
```

- Header line: program name, CLI version, daemon position (`1/2`),
  staleness of the last successful fetch, and the help hint. When the
  daemon's `version` ≠ the CLI's, a warn chip appears in the daemon box
  title: `daemon v0.0.9 ≠ CLI v0.1.0 — sudo drawbridge install` (the §6
  skew policy, same remedy wording as doctor check 9).
- Summary box: `resolution` verbatim (endpoint, source, and the resolver's
  `note` on its own line when non-empty — the strings doctor prints
  unchanged, unchanged here too), auth mode + secret state + path
  (truncated middle-out to fit; the path is fine to show, the bytes never
  are), session states, `lastEventAt` as relative time, pool parked count.
- Mirror table: one row per entry, `state` colored (`bound` green,
  `skipped` dim, `bind-failed` red), `since` relative. Sorted by port
  within proto. The skip list renders under the table when non-empty, with
  the same discoverability wording doctor check 11 uses available in the
  row's dim styling ("skipped" entries are the default exclusion at work,
  not an error).
- Sync table: the advertised set, plus `udpPorts` rows labeled `udp`.
- Footer: the short help (§4.2). Exactly five entries, always.

At 80×24 (the honest case — SSH sessions, split panes):

```
 drawbridge tui · v0.1.0            daemon 1/2 · <1s ·  ? help
 colima:colima · user · pid 71234 · v0.1.0 · up 2h14m
 endpoint tcp://192.168.64.5:4777 (vznat-direct)
 auth static-hmac-v1 · secret ok
 mirror up · event 12s ago   sync up · adv 3 · parked 4
 MIRROR (5)                              skip: 22
 PROTO  PORT   STATE         SINCE
 tcp    8080   bound         2m
 tcp    3000   bound         2m
 udp    5353   bound         1m
 tcp    22     skipped       2h
 tcp    5000   bind-failed   40s
 ...
 tab daemon · r refusals · d doctor · ? help · q quit
```

Degradation rules, fixed so goldens can pin them:

- Width < 100: the sync table collapses into the summary line
  (`sync up · adv 3 · parked 4`); the advertised set moves to the switcher
  overlay's detail and the full-width mirror table gets the columns.
- Width < 70: the `SINCE` column drops; the auth path drops (mode + state
  stay).
- Height pressure: the mirror table is the elastic region; when entries
  overflow it, the table becomes the dashboard's scrollable region
  (`j/k`), with a `… +N more` tail line when unscrolled.
- Below 44×12: a centered "window too small (need ≥ 44×12)" card and
  nothing else. Resizing back restores the full view — all layout is
  computed per `View` from the last `WindowSizeMsg`, no state involved.

### 3.2 The refusals pane (`r`)

Toggles a bottom split (40% of height, min 6 lines; the dashboard
compresses per §3.1's rules). Content is the accumulated log (D5), newest
at the bottom, auto-following until the user scrolls up (any scroll key
disengages follow; `G` re-engages):

```
 ─ refusals · 34 kept (ring carries last 32 per refresh) ──────────────
 18:22:10  auth-mismatch          agent at tcp://192.168.64.5:4777 closed during transport auth…
 18:22:41  reverse-dial-refused   'D' activation named 127.0.0.1:9099 — not advertised; refused
 18:23:05  mirror-skip            guest tcp :22 not mirrored (skip list)
```

Each line: local wall-clock `at`, the stable ID (colored by class: auth
IDs warn-red, `mirror-skip` dim, others yellow), `line` verbatim. The IDs
are the transport-auth §7 / introspect contract IDs — the pane is the live
counterpart of doctor's ring evidence, and showing the ID teaches the user
the vocabulary doctor's findings use. While open, scroll keys drive this
pane. An empty log renders "(no refusals seen since attach — the ring
starts with what the daemon remembers)".

### 3.3 The doctor view (`d`)

Full-screen replacement (the dashboard keeps refreshing underneath, D6).
Entering runs a plain gather immediately — the user pressed `d` because
they want a diagnosis, and gather is read-only, so there is nothing to
confirm (§11 q2 confirms this).

Running:

```
 doctor — gathering… 7s   ⠸        esc cancel
 (checks are read-only; nothing is mutated, sudo is never spawned)
```

Complete — one line per finding, doctor's own catalog order, cursor
selectable:

```
 doctor — colima:colima · ran 18:31:02 · 14s
 [ok]   providers: colima v0.9.2, 1 vz instance running
 [ok]   agent v0.1.0 active, listening loopback+vznat
 [warn] resolution: ssh-forwarder (fallback)                          ◂
 [fail] local-network: user probe failed, root evidence unknown
 ...
 16 checks: 11 ok, 2 warn, 1 fail, 2 skip, 0 info
 enter expand · j/k move · R re-run · p re-run with probe (~20s+) · esc back
```

`enter` on a finding expands it in place: evidence lines indented, remedy
prefixed `→` — the same content `Report.Render` prints, styled from the
`Finding` struct directly. Statuses are colored *and* keep their bracketed
words (color is never the only carrier — same accessibility rule as §3.6).
`R` re-runs; `p` re-runs with `Probe: true` and is labeled with its cost
in the key line itself — the ~20 s post-FIN window is a deliberate,
priced action, never a default (doctor.md §D6). A gather error (doctor's
exit-2 class) renders as a single card with the error verbatim and `R` to
retry. Results persist when the user returns to the dashboard and
re-enters — `d` shows the last report with its `ran at` age, and `R` is
the explicit refresh (a doctor run is seconds, not a tick; auto-re-running
it would violate the calm default).

The doctor run inherits the TUI's `-vm`/`-vm-subnet`/`-vm-mac`/`-timeout`
flags (§4.3); with no `-vm`, the selected daemon's `vm.ref` seeds
`Options.VM` so the diagnosis targets what the user is looking at (no
daemon at all → `Options.VM` stays empty and doctor does its own
single-running-instance selection, exactly as the CLI verb does).

### 3.4 The multi-VM switcher (`tab`, `1`–`9`, `v`)

`tab`/`shift+tab` cycle daemons directly; `1`–`9` jump; `v` opens the
overlay for the labeled view:

```
 ┌ daemons ────────────────────────────────────────────────┐
 │ ▸ 1  colima:colima   user  pid 71234  v0.1.0  5 mirrors │
 │   2  lima:dev        root  pid 4242   v0.1.0  2 mirrors │
 │   3  lima:scratch    —     schema 2 (daemon v0.2.0)     │
 │      /var/run/drawbridge/introspect.sock  [unreadable]  │
 │ enter select · esc close                                │
 └─────────────────────────────────────────────────────────┘
```

Every discovered socket appears: answering daemons with flavor
(root/user), PID, version, and a mirror-count one-liner; schema-skewed
daemons with their frozen two fields (D2 of doctor.md §3.3 — that is all
they are good for); unreadable sockets (`ErrMalformed` problems from
`FetchAll`) labeled as such. The fighting-daemons banner (§2 D8) renders
above the overlay too, and the two combatants are adjacent rows here —
this is the view that makes the pathology *visible* rather than merely
detected.

### 3.5 Empty and degraded states

All of these are states to render helpfully, never errors (doctor.md §3.3
is the contract; the TUI adds no posture of its own):

| Condition | Rendering |
|---|---|
| No socket answers anywhere | Full-screen calm card: "no drawbridge daemon is answering", the two paths checked (`/var/run/drawbridge/introspect.sock`, `~/Library/Application Support/drawbridge/run/`), how to start one (`drawbridged` foreground for ports ≥1024; `sudo drawbridge install` for the LaunchDaemon), and "re-checking every second — this screen heals itself". Not styled as an error; this is the ordinary pre-start state. |
| Daemon up, no mirror entries | Dashboard renders normally; the mirror table body is a dim "(no guest listeners mirrored yet)". If `mirror.sessionUp` is false, the summary line styles `session down` warn and the footer hint suggests `d`. |
| Selected daemon stops answering | The daemon box renders "this daemon stopped answering Ns ago (path)" over the last-known summary, dimmed; heals on the next successful fetch (D7). |
| `schema > 1` | The daemon's slot renders the skew card: "daemon at `<path>` speaks introspection schema N; this build knows 1 (daemon `<version>`, CLI `<version>`)" — frozen fields only, same wording family as `status`. |
| Malformed payload | The socket appears in the switcher as `[unreadable]`; a warn line in the header area names it while the problem persists. |
| Root + user answering for one VM | The D8 banner, everywhere, until one stops. |

### 3.6 Secrets, color, and terminal reality

- **Secrets:** the TUI renders `auth.mode`, `auth.secretState`, and
  `auth.secretPath` — the fields the snapshot deliberately limits itself
  to. It computes no digests and renders none of its own; doctor findings
  shown in the doctor view already cap at the 8-hex prefix at generation
  (transport-auth §5), and the TUI displays `Evidence` verbatim, adding
  nothing.
- **Color:** ANSI-16 palette only via `lipgloss.AdaptiveColor` light/dark
  pairs (no truecolor requirement — SSH to a Mac from anything still
  renders). Status is always carried by a word as well as a color
  (`bound`/`bind-failed`, `[ok]`/`[fail]`), so `NO_COLOR`/`TERM=dumb`
  degrade to legible monochrome through termenv's profile detection.
  Background detection (OSC 11) failing over SSH defaults to the dark
  palette, which is the safer guess.
- **Lifecycle:** alt-screen (`tea.WithAltScreen()`); bubbletea restores
  the terminal on quit, on `ctrl+c`, and on panic. `Program.Run`'s error
  return becomes a non-zero exit with the error printed after restore.

## 4. Navigation and keybinding map

This section is the Phase 6 contract: the quickstart cites these keys, and
changing them after v0.1.0 is a documented breaking change to muscle
memory. Keys were chosen to survive small keyboards and SSH (no function
keys, no alt/meta chords, no ctrl beyond `ctrl+c`).

### 4.1 The map

Amended additively 2026-08-01 (§12, second visual mock): three rows gained
aliases or a second meaning and one key is new. No key changed or lost a
meaning — everything documented before that date still does exactly what it
said.

**Global (every view):**

| Key | Action |
|---|---|
| `q`, `ctrl+c` | Quit (terminal restored) |
| `?` | Toggle the help overlay |
| `esc` | Close the topmost overlay, else the refusals pane (added 2026-08-01); in the doctor view: cancel a running gather, else return to the dashboard; on the plain dashboard with nothing open: nothing |
| `tab` / `shift+tab`, `l` / `h`, `→` / `←` | Next / previous daemon (the letter and arrow aliases added 2026-08-01, in every view where `tab` already cycled) |
| `1`–`9` | Select daemon N (switcher order) |
| `v` | Toggle the daemon switcher overlay |
| `r` | Toggle the refusals pane (the footer entry carries the unseen count) |
| `d` | Open the doctor view (runs a gather on first entry) |
| `x` | Dashboard only (added 2026-08-01): expand / collapse the sync table's folded ephemeral rows. Full help only — the footer stays five entries |

**Scrolling (whichever single region is scrollable — the refusals pane
when open, else an overflowing mirror table, else the doctor findings
list):**

| Key | Action |
|---|---|
| `j` / `k`, `↓` / `↑` | Line down / up (doctor view: move the cursor) |
| `pgdn` / `pgup`, `space` / `b` | Page down / up |
| `g` / `G` | Top / bottom (`G` re-engages follow in the refusals pane) |

**Doctor view only:**

| Key | Action |
|---|---|
| `enter` | Expand / collapse the selected finding (evidence + remedy) |
| `R` | Re-run the gather |
| `p` | Re-run with the half-close probe (labeled "~20s+" in the view) |
| `esc` | Cancel while running; back to dashboard when idle |

**Switcher overlay only:**

| Key | Action |
|---|---|
| `j`/`k`, `↑`/`↓` | Move the cursor |
| `l`/`h`, `→`/`←` | Next / previous daemon, like `tab` (added 2026-08-01) |
| `enter` | Select daemon and close |
| `esc`, `v` | Close without changing selection |

### 4.2 The help design (progressive disclosure applies to keys too)

- The footer shows the **short help** — exactly five entries, always:
  `tab next daemon · r refusals · d doctor · ? help · q quit`. This is the
  entire advertised surface; a user who never presses `?` can operate
  everything that matters from these five. Amended 2026-08-01: the
  refusals entry carries the selected daemon's unseen count when there is
  one (`r refusals (3)`, warn-colored, capped at `99+`) — part of that
  entry, never a sixth.
- `?` opens the **full overlay**: the §4.1 tables grouped Global /
  Scrolling / Doctor / Switcher, rendered from the same keymap structure
  the Update loop dispatches on (`internal/tui/keys.go` — one source of
  truth, so the help can never drift from the behavior; a unit test walks
  the keymap and asserts every binding appears in the overlay).
- Context-sensitive additions: while the doctor view is open, the footer
  swaps to its own five (`enter expand · R re-run · p probe · esc back ·
  ? help`); while the refusals pane is open, the footer appends nothing —
  scrolling keys are in the full overlay, and the pane works without
  knowing them.

### 4.3 The verb and its flags

```
drawbridge tui [-vm NAME] [-vm-subnet CIDR] [-vm-mac MAC] [-timeout D]
```

- `-vm` pre-selects the matching daemon in the switcher (by canonical ref)
  and seeds the doctor view's `Options.VM`. Optional — the TUI's default
  is every answering daemon, first one selected.
- `-vm-subnet`, `-vm-mac`, `-timeout` exist solely to pass through to
  doctor runs, same grammar and defaults as `drawbridge doctor` (a TUI
  user on a pinned install deserves the same lease view). No other flags:
  the refresh cadence is fixed at 1 Hz (a flag is cheap to add later if
  anyone asks; §11 q4).

Usage text added to `main.go`'s usage block:

```
  drawbridge tui [-vm NAME] [-vm-subnet CIDR] [-vm-mac MAC] [-timeout D]
        Live read-only view of every running daemon: mirror table, sync
        set, resolution, auth posture, refusals, and the doctor catalog
        on demand. Observes via the introspection socket; cannot command
        the daemon (the socket has no request grammar). No root needed.
```

## 5. Model architecture

```
internal/tui/
  tui.go          Run(Options) error — constructs the model, tea.NewProgram(m,
                  tea.WithAltScreen()).Run(); the only exported entry point
  model.go        Model (root), Init, Update; the message types
  fetch.go        tick + FetchAll command; refusal accumulation (pure helper)
  dashboard.go    dashboard rendering (pure View helpers)
  refusals.go     refusals pane state + rendering
  doctorview.go   doctor view state, async run command, rendering
  switcher.go     switcher overlay
  keys.go         the §4 keymap + short/full help rendering (one source of truth)
  scroll.go       the hand-rolled scroll region (offset, clamp, follow)
  styles.go       lipgloss styles; the ANSI-16 adaptive palette
  testdata/       view goldens
cmd/drawbridge/tui.go   flag parsing → tui.Options → tui.Run
```

**The root model** is one struct, one state machine:

```go
type Model struct {
    width, height int
    snaps         []*introspect.Snapshot   // last FetchAll result, Discover order
    problems      []error                  // malformed sockets
    fetchedAt     time.Time
    fetching      bool                     // in-flight guard (D4)
    selected      string                   // socket path (D7)
    missedTicks   map[string]int           // per-path absence counter (D7)
    refusals      map[string][]refusalRow  // accumulated per path, cap 512 (D5)
    pane          pane                     // paneNone | paneRefusals
    view          view                     // viewDashboard | viewDoctor
    overlay       overlay                  // overlayNone | overlaySwitcher | overlayHelp
    doctor        doctorState              // idle | running{gen, cancel, since} | done{report} | failed{err}
    scroll        scrollState
}
```

**Messages and commands:**

- `tickMsg` — from `tea.Tick(time.Second)`; Update returns the next tick
  plus `fetchCmd` unless `fetching` (D4).
- `snapshotsMsg{snaps, problems, at}` — `fetchCmd`'s result: runs
  `introspect.FetchAll(introspect.DialTimeout)` in the command goroutine;
  Update merges refusal rings (the pure `accumulate` helper), bumps or
  resets `missedTicks`, keeps `selected` pinned to its path.
- `doctorDoneMsg{gen, report}` / `doctorFailedMsg{gen, err}` — from the
  gather command; dropped when `gen` is stale (D6).
- `tea.WindowSizeMsg`, `tea.KeyMsg` — stored size; keymap dispatch.

**Update is a pure function** of (Model, Msg) → (Model, Cmd) — every
transition in §3/§4 is a table-testable case with no I/O. The only
impurity lives inside commands (`fetchCmd`, `runDoctorCmd`) and they
return messages, never touch the model. **View is pure** over the model:
layout derives from `width`/`height` per §3.1's fixed rules, styles come
from `styles.go`, and identical models render identical strings — which
is what makes goldens work.

**Styles** live in `styles.go` only: a small set of named
`lipgloss.Style` values built on `AdaptiveColor{Light, Dark}` ANSI-16
pairs (§3.6). No color literals anywhere else; the doctor view maps
`doctor.Status` → style through one function.

## 6. Dependencies and the import-graph pin

go.mod gains exactly two direct requirements (D3 pins) plus their
transitive tree in go.sum. Charm code may link into `cmd/drawbridge` only
— **never** the root daemon (`cmd/drawbridged`), the guest agent
(`cmd/drawbridge-agent`), or the runc wrapper (`cmd/drawbridge-runc`).
That boundary is pinned by a test, not a convention:

`internal/tui/importgraph_test.go` — for each of
`{darwin, ./cmd/drawbridged}`, `{linux, ./cmd/drawbridge-agent}`,
`{linux, ./cmd/drawbridge-runc}`, run
`go list -deps <pkg>` with `GOOS` set, from the repo root, and fail on any
resulting import path containing `github.com/charmbracelet/` (which also
transitively forbids `internal/tui` itself, since it imports charm —
one substring covers both directions). Skips with an explicit note if
`go` is not on PATH (it always is under `go test`; the guard is for
exotic harnesses). Cheap, durable, and it fails at the exact commit that
introduces the leak with the offending package named.

`GOOS=linux go build ./...` stays green: bubbletea and lipgloss build on
linux (the windows-only `coninput` is build-tag guarded upstream), so the
constraint really is the import graph, not the platform — and CI's linux
job proves it every push.

## 7. Testing

No pty, no `tea.Program` in any test — Model/Update/View purity is the
strategy:

- **Update-loop table tests** (`model_test.go`): key sequences and
  injected messages → state assertions. Cases pinned: every §4.1 binding
  in every view (including the esc-cancels-then-esc-returns doctor
  two-step), pane/overlay toggling, tab/number selection with sockets
  appearing and vanishing mid-sequence (D7's pin-to-path behavior), the
  in-flight fetch guard, stale-generation doctor messages dropped (D6).
- **View goldens** (`view_test.go` + `testdata/`): fixture snapshots
  (bound/skipped/bind-failed mix, refusal rings, schema skew, malformed
  problems, fighting pair, the no-daemon state) rendered at 80×24 and
  120×40 with the color profile forced to ASCII
  (`lipgloss.SetColorProfile`) so goldens are byte-stable across
  terminals and CI. The §3.1 degradation rules each get a golden at their
  boundary width.
- **Accumulator tests** (`fetch.go`'s pure helper): ring merge identity,
  ordering, the 512 cap, ring-overflow behavior.
- **Keymap/help drift test** (`keys.go`): every binding the Update loop
  dispatches appears in the full help overlay (§4.2).
- **Fetch integration** (small): a real `introspect.Listen` server on a
  `t.TempDir()` socket (the introspect package's own test pattern) →
  `fetchCmd` → `snapshotsMsg` shape. `HOME` isolated via
  `t.Setenv("HOME", t.TempDir())` per the standing transportauth test
  discipline, so `UserRunDir` never touches the real home.
- **The import-graph test** (§6).
- **e2e untouched**: the TUI adds no daemon or wire behavior to test
  end-to-end; the live acceptance script (§9) is the human-eyes
  complement.

## 8. Affected files

- `go.mod` / `go.sum` — the two pins (D3) and their tree.
- `internal/tui/` *(new)* — the §5 layout: `tui.go`, `model.go`,
  `fetch.go`, `dashboard.go`, `refusals.go`, `doctorview.go`,
  `switcher.go`, `keys.go`, `scroll.go`, `styles.go`, tests, `testdata/`.
- `cmd/drawbridge/tui.go` *(new)* — flags (§4.3) → `tui.Run`.
- `cmd/drawbridge/main.go` — verb dispatch case + the §4.3 usage block.
- `docs/ergonomics.md` — the Phase 5.5 section inserted between Phase 5's
  results and Phase 6 (T4), plus its results subsection when built.
- `docs/HANDOFF.md` — §Next repointed (T4).
- `AGENTS.md` — one proposed invariant (T4, wording in §9).

Nothing under `internal/bpf/`, no daemon, agent, or wire changes, no
`internal/introspect` or `internal/doctor` changes — both are consumed
strictly through their existing exported surfaces. (If any phase discovers
it needs a daemon-side change, the design is wrong — stop and re-open.)

## 9. Build phases

Each independently landable and verified; the user performs any push.

**T1 — dependency spine + the calm dashboard.** The D3 pins; `internal/tui`
with the root model, tick/fetch loop (D4), the dashboard with all §3.1
layouts and §3.5 empty states, the help overlay and footer (§4.2), resize,
clean exit; `cmd/drawbridge/tui.go` + `main.go` dispatch/usage; the
import-graph test.
*Verify:* `gofmt -l .` clean, `go vet ./...`,
`go test ./internal/... ./cmd/...` (update tables, goldens at both sizes,
importgraph, keymap-drift), `GOOS=linux go build ./...`,
`GOOS=darwin go build ./...`. Live: `just agent-up`, foreground
`drawbridged`; `drawbridge tui` shows the dashboard refreshing at 1 Hz;
`docker run --network host` a listener in the guest → the entry appears
within a tick; kill the daemon → the §3.5 stopped-answering state within a
tick; restart → heals; resize through the §3.1 breakpoints; `q` restores
the terminal (prompt intact, no alt-screen residue).

**T2 — many daemons + the refusals pane.** Switcher overlay and `tab`/
number selection (D7), fighting-daemons banner (D8), schema-skew and
malformed rendering, the refusals pane with client-side accumulation (D5).
*Verify:* the T1 command battery; new goldens (fighting, skew, switcher,
refusals). Live: foreground user daemon + a second foreground `sudo
drawbridged` for the same VM → banner appears with both PIDs, clears when
one stops; flip one hex digit in the Mac transport secret and restart the
daemon → auth refusals stream into the pane with their IDs, restore the
secret → they stop (the Phase 5 live-matrix trick, reused); `tab` cycles
between the dev VM's daemon and a colima one.

**T3 — the doctor view.** Async gather with generation token and cancel
(D6), spinner + elapsed, findings list with expansion, `R`, `p` with its
cost label, gather-error card, result persistence across view switches.
*Verify:* the command battery; update tests for the doctor lifecycle
(fixture `Report`s injected as messages — no machine); goldens for
running/complete/failed. Live, against the dev VM: `d` → verdicts match a
side-by-side `drawbridge doctor` run; `esc` mid-gather returns to the
dashboard within a tick and no stale report ever lands; `p` shows the
labeled wait and completes with check 8 populated; stop the agent → re-run
inside the TUI shows check 3's fail exactly as the CLI does.

**T4 — roadmap + posture docs.** Insert "Phase 5.5 — `drawbridge tui`"
into ergonomics.md §8 between Phase 5's results and Phase 6 (spec
paragraph pointing at this note + a *Verify* block naming the live
acceptance above), keeping Phase 6/7 numbering; amend Phase 6's wording to
note the quickstart documents TUI navigation citing this note's §4;
repoint HANDOFF §Next (TUI before v0.1.0, Phase 6 follows); write the
Phase 5.5 results subsection from the T1–T3 live runs. Proposed AGENTS.md
invariant (binds future sessions; accept or amend — §11 q5):

> **Nothing charm-flavored outside `cmd/drawbridge` and `internal/tui`.**
> bubbletea/lipgloss link into the user-facing CLI only — never
> `cmd/drawbridged`, `cmd/drawbridge-agent`, or `cmd/drawbridge-runc`
> (pinned by `internal/tui`'s import-graph test). The TUI observes through
> the introspection socket and runs doctor's in-process gather; it sends
> the daemon nothing, and a TUI feature that needs the daemon to act is a
> new design decision, not a new keybinding.

*Verify:* full command battery one last time; `just e2e` regression
(expected untouched); the §4 map read against the built keymap (the drift
test makes this mechanical); docs render sanely.

## 10. Alternatives rejected (and what would revive them)

- **`watch -n1 drawbridge status` (the null alternative).** Still works
  and always will; rejected as the *answer* because it cannot show the
  refusal stream, cannot run doctor, flickers, and renders one daemon's
  worth of summary lines. Nothing revives it — it coexists.
- **A streaming/push protocol on the introspection socket** ("the TUI
  should get events, not poll"). Rejected: it is a protocol change to the
  ratified single-shot write-only contract (doctor.md §D2), reopening the
  exact input-surface argument that contract closed, to replace a
  microseconds-cheap 1 Hz re-dial. Revived only if the ring's D5 loss
  bound proves inadequate for a real diagnostic need — and then as its own
  ratified design, not a TUI convenience.
- **TUI-triggered daemon actions** (re-resolve now, drop a mirror entry,
  reload the secret). Categorically out — the AGENTS.md invariant names
  this the "new design decision" boundary, and this note deliberately
  ships nothing adjacent to it.
- **A localhost web dashboard.** New inbound surface on the Mac, a
  browser dependency, and none of the SSH-session reach a TUI gets for
  free. Revived by nothing on the current roadmap.
- **tview/tcell instead of bubbletea.** Mature, but callback-driven —
  state transitions live in widget callbacks, which is exactly what makes
  UIs untestable without a terminal. bubbletea's pure Model/Update/View
  is the §7 test strategy; HANDOFF ratified it besides.
- **bubbles, and bubbletea v2.** Per D3: bubbles doubles the new tree for
  widgets this design reshapes anyway (revived by a list/filter-heavy v2
  view or any text input); v2 is beta churn before a first release
  (revisit at GA).
- **A separate `drawbridge-tui` binary.** Would keep charm out of the CLI
  too, but adds a fifth artifact to goreleaser/brew, a second thing to
  version-skew, and a worse quickstart ("install this too"). The verb is
  ratified; the import-graph test does the isolation work instead.
- **`internal/introspect` growing TUI-specific helpers** (e.g. a
  diffing client). Rejected: the accumulator is TUI policy, not protocol;
  the client package stays exactly the shared surface doctor/status
  already trust.
- **A row-detail overlay** (a cursor on the mirror table, `enter` opening
  one entry's detail). Deliberately deferred 2026-08-01, not rejected on
  principle: schema 1 carries proto, port, state and `since`, and an
  overlay showing four fields the row already shows is a keypress that
  costs the user a screen. Revived when the daemon grows per-entry
  counters (active conns, bytes, last activity) — additive schema-1
  fields plus splice-path accounting, bench-gated; a row cursor and
  overlay are the right UI for that data, and mouse capture's cost
  (terminal text selection stops working) gets weighed then, not before.

## 11. Open questions for the user, ranked by plan impact — RESOLVED 2026-08-01

All five resolved as recommended at plan approval (verb `tui`; doctor
auto-runs on first entry; `p` stays, cost-labeled; 1 Hz fixed, no flag;
the T4 invariant as proposed). §12 records what building amended.

### Original questions

1. **The verb name `tui` (D1) — confirm or veto now.** Phase 6's
   quickstart cites it; renaming later rewrites released docs. (`dash` and
   `watch` were considered and rejected for the §2 reasons.)
2. **Doctor auto-runs on first entering the view (recommended: yes).**
   Alternative: `d` opens an empty view and `enter` starts the run. Changes
   the documented key contract and the §3.3 flow; auto-run is one less
   step and gather is read-only, but it does launch guest shell probes the
   moment `d` is pressed.
3. **`p` (the ~20 s `-probe` re-run) inside the TUI (recommended: yes,
   labeled) vs CLI-only.** Dropping it removes a documented key and sends
   users back to the terminal for check 8; keeping it costs a spinner wait
   that D6 already makes cancelable.
4. **Refresh cadence fixed at 1 Hz with no flag (recommended)** vs an
   `-interval` flag now. A flag is cheap to add on request; shipping it
   now is surface the quickstart must explain.
5. **The T4 AGENTS.md invariant wording** — accept or amend; it binds
   future sessions.

## 12. Build amendments (2026-08-01, T1–T3)

What the build corrected against the real terminal; each is the shipped
behavior and supersedes the section it amends:

- **§3.1's mockups measure ~104 columns, not their stated 120** (and the
  80-col header line is 62 chars). Content, column offsets and ordering
  were treated as truth; box borders and right-aligned segments fill to
  the real terminal width.
- **The footer has three spellings, not one** — canonical
  (`tab next daemon · …`), compact below 59 columns (`tab daemon · …`),
  tiny below 54 (`tab · r · d · ? help · q quit`) — because neither
  noted spelling fits the 44-column minimum window. Exactly five entries
  in all three (pinned).
- **The doctor footer says `esc cancel` while a gather runs** and
  `esc back` when idle; `p`'s label is `p probe (~20s+)` in the full
  spelling. The "~20s+" is the post-FIN window; `doctor.ProbeBudget`
  additionally floors `-timeout` at 60 s inside `Gather` — the TUI
  passes Options through untouched and does not reimplement or explain
  the floor.
- **§4.1's j/k contradiction resolves in the doctor view's favor**: in
  the doctor view j/k move the cursor even when the refusals pane is
  open (the pane keeps following underneath). Elsewhere the scroll
  region priority is as written.
- **`accumulate` lives in `refusals.go`**, not `fetch.go` (§5's layout).
- **Switcher numbers appear on selectable rows only** — skewed and
  `[unreadable]` rows are readable but not selectable, so numbering them
  would advertise dead keys. Cycling skips them.
- **The skew card renders in the header chrome on every view** (a
  non-selectable daemon has no slot), two lines by construction — the
  socket path contains spaces on every Mac and word-wrap split it
  mid-directory.
- **Refusal identity keys on `At.UnixNano()`**, not struct equality —
  two JSON decodes of one non-UTC timestamp carry distinct
  `*time.Location` pointers and struct-equality duplicated every entry
  at 1 Hz. Scroll movement clamps before stepping (a following region
  stores offset 0). Both pinned by tests.
- **The help overlay is scrollable** — the full §4.1 map is 29 lines and
  cannot fit 80×24; without scroll the Doctor and Switcher groups would
  be unreachable.
- **`termenv` is a third direct requirement in go.mod**, test-only, for
  byte-stable ASCII-profile goldens (it was already transitive).
- **Canceling a re-run restores the previous report** rather than
  dropping to idle; with no previous report, cancel lands on idle and
  the next `d` auto-runs (the auto-run condition is literally
  `phase == idle`).

### 12.1 Polish pass (2026-08-01, approved from a second visual mock)

Seven changes to the wide dashboard, its sort orders and its key map.
Each supersedes the §3.1 / §4 wording it touches; the compact layout is
unchanged apart from the auth line and the mirror sort, which are not
layout.

- **The sync table folds ephemeral advertisements.** Ports ≥ 49152 (the
  IANA dynamic range) collapse per proto into one dim row —
  `tcp    ·7 ephemeral (49410–56206)` — once that proto has three or
  more of them; two or fewer render as ordinary rows. The header keeps
  counting the whole advertised set, folded or not, and `x` toggles the
  fold. The threshold is where a run stops reading as ports and starts
  reading as noise burying the ports the user chose (a live root daemon
  advertises 19, seven of them ephemeral). The fold row carries a dim
  `x expand` hint, dropped rather than ellipsised when the region is too
  narrow for it (at 100 columns it is) — the key still works and the map
  is one `?` away. Compact is unaffected: the sync set is already a
  summary line there.
- **The mirror table sorts problems first**: `bind-failed`, then any
  state this build does not recognise, then `bound`, then `skipped`,
  with the previous proto-then-port order inside each class. The order
  is total over the row's own fields, so nothing moves between refreshes
  except what changed state.
- **The daemon box is two content lines.** Line 1 is unchanged
  (endpoint, source, resolved-ago). Line 2 merges auth and both
  sessions: `auth  static-hmac-v1 ok   ·   mirror up · event 9s ago   ·
  sync up · pool 8 parked`. **The secret path is dropped at every
  width** — mode plus secret state carry the whole signal and the path
  was machinery (the same calm rule the CLI's `auth` line follows), so
  §3.1's "auth path drops below 70" degradation rule is retired along
  with `layout.showAuthPath`. The secret state is the bare word after
  the mode. The skew chip, the resolver-note line and the D8 banner are
  untouched.
- **The skip list docks into the mirror header** —
  `MIRROR — guest listeners on Mac localhost (3) · skip: 22`, dim,
  only when non-empty — and the floating `skip list: 22` line under the
  table is gone. It was a property of what the table shows, not a row of
  it, and it moved every time the table's height did.
- **A dim `│` rule divides the two table regions** in the wide layout,
  for the full height of the taller one, header rows included. It costs
  two columns, so `syncCol` moves 57 → 62 and the mirror region is
  `syncCol - indent - sepW` = 58: the docked header needs 56, and a
  header truncated to make room for a rule would have been a bad trade.
  Both table titles gained the house fallback spellings (`SYNC — Mac
  ports advertised (3)`, `MIRROR — guest listeners (5)`) for the widths
  where the sentence no longer fits — the same shape the footer and the
  D8 banner already use.
- **The footer's refusals entry carries an unseen count** —
  `r refusals (3)`, warn-colored, `99+` at the cap. The watermark is
  per socket path and is the *identity of the newest refusal the pane
  has shown*, not the log's length: the log trims from its front at
  `refusalCap`, and a length watermark would stop counting exactly when
  a daemon is refusing hard enough to matter. Opening the pane, tabbing
  onto a daemon with the pane open, and a fetch arriving under an open
  pane all mark seen; closing does not resurrect the count. Five footer
  entries, unchanged.
- **Additive navigation.** `l`/`→` and `h`/`←` alias `tab`/`shift+tab`
  in every view where `tab` already cycled daemons (dashboard, doctor,
  switcher). `esc` on the dashboard closes the refusals pane when there
  is no overlay above it — the plain dashboard's `esc` is still inert,
  and the doctor view still claims `esc` first for its cancel/back
  two-step. `x` is dashboard-only and lives in the full help, not the
  footer. No existing key changed meaning.
- **`esc`'s help string was shortened** to fit the overlay once the
  daemon-cycling labels grew (`shift+tab, h, left`): the keymap is the
  one source of truth for the footer *and* the help, so a help string
  that overflows the card is a drift the drift test cannot see.
