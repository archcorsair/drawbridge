package tui

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
)

// Layout constants. §3.1 fixes the degradation rules so goldens can pin them;
// these are those rules as numbers, and nothing else may invent a breakpoint.
const (
	// minWidth/minHeight: below this the only honest thing to draw is a card
	// saying so.
	minWidth  = 44
	minHeight = 12
	// wideWidth is where the sync table earns its own column beside the mirror
	// table and the summary gets its box. Below it the sync set collapses into
	// the summary line and the mirror table takes the full width.
	wideWidth = 100
	// detailWidth is where the SINCE column stops fitting.
	detailWidth = 70
	// syncCol is the absolute column the sync table starts at in the wide
	// layout, and sepW is what the vertical rule between the two tables costs:
	// the rule itself plus the blank column that keeps the sync rows off it.
	// The mirror region is sized from both, so the rule lands in the gap rather
	// than eating the header's docked skip list.
	syncCol = 62
	sepW    = 2

	protoW = 7
	portW  = 7
	stateW = 14
	// labelW is the summary box's label column.
	labelW = 11

	// ephemeralMin is the IANA dynamic/ephemeral range, and foldEphemeral is
	// how many of them one proto has to advertise before they are folded: two
	// stray high ports read as ports, a dozen read as noise burying the ports
	// the user chose.
	ephemeralMin  = 49152
	foldEphemeral = 3
)

type layout struct {
	width, height int
	// wide is the ≥100 layout: boxed summary, mirror and sync side by side.
	wide bool
	// indent is the left margin table rows sit at.
	indent int
	// mirrorWidth is the region the mirror table owns.
	mirrorWidth int
	showSince   bool
}

func (m Model) layout() layout {
	lo := layout{
		width:     m.width,
		height:    m.height,
		wide:      m.width >= wideWidth,
		showSince: m.width >= detailWidth,
	}
	if lo.wide {
		lo.indent = 2
		lo.mirrorWidth = syncCol - lo.indent - sepW
	} else {
		lo.indent = 1
		lo.mirrorWidth = m.width - 2*lo.indent
	}
	return lo
}

// contentWidth is the length every full-width line is built to: one column of
// right margin, so the box's right edge and the header's right segment land in
// the same place.
func (lo layout) contentWidth() int { return lo.width - 1 }

func (m Model) dashboardView() string {
	lo := m.layout()
	head := m.chromeLines(lo)

	snap := m.selectedSnap()
	if snap == nil {
		return m.frame(append(head, m.noDaemonCard(lo)...), lo)
	}

	head = append(head, m.summaryLines(lo, snap)...)
	body := m.tableLines(lo, snap, m.rowBudget(lo, snap))
	return m.frame(append(head, body...), lo)
}

// frame seats the rendered body in the window: the footer always occupies the
// last row, the refusals pane the rows above it when open, spare height
// becomes blank lines between, and an overlong body is cut rather than allowed
// to push either off screen.
func (m Model) frame(body []string, lo layout) string {
	pane := m.refusalPane(lo)
	rows := max(0, lo.height-1-len(pane))
	if len(body) > rows {
		body = body[:rows]
	}
	for len(body) < rows {
		body = append(body, "")
	}
	body = append(body, pane...)
	body = append(body, m.footerLine(lo))
	// The last guard on both frame invariants: one row per line, and never
	// wider than the window.
	for i, l := range body {
		body[i] = strings.TrimRight(truncEnd(oneLine(l), lo.width), " ")
	}
	return strings.Join(body, "\n")
}

// chromeLines is what every view carries above its own body: the header, the
// D8 banner, and the notices for the sockets no dashboard can show. The banner
// is here rather than in dashboardView because §3.4 and D8 both require it
// above the overlays too.
func (m Model) chromeLines(lo layout) []string {
	out := []string{m.headerLine(lo)}
	out = append(out, m.bannerLines(lo)...)
	return append(out, m.noticeLines(lo)...)
}

func (m Model) headerLine(lo layout) string {
	name := "drawbridge tui · CLI " + m.version
	if !lo.wide {
		name = "drawbridge tui · " + m.version
	}
	pos := "no daemon"
	if i, n := m.daemonPos(); n > 0 {
		pos = fmt.Sprintf("daemon %d/%d", i, n)
	}
	age := "—"
	if !m.fetchedAt.IsZero() {
		age = relative(m.now.Sub(m.fetchedAt))
		if lo.wide {
			age = "refreshed " + age + " ago"
		}
	}
	// The doubled space before `? help` is the note's spelling: the hint gets
	// breathing room from the status it trails.
	right := joinDot(pos, age) + " ·  " + styleDim.Render("? help")
	return " " + rightAlign(styleTitle.Render(name), right, lo.contentWidth()-1)
}

// footerLine is §4.2's short help: five entries, always, and the doctor view's
// own five while it is open. The advertised surface is the whole footer — a
// user who never presses `?` operates everything that matters from it.
func (m Model) footerLine(lo layout) string {
	pad, w := strings.Repeat(" ", lo.indent), lo.contentWidth()-lo.indent
	if m.view == viewDoctor {
		return pad + doctorShortHelp(w, m.doctor.phase == doctorRunning)
	}
	return pad + shortHelp(w, m.unseenRefusals(m.selected))
}

// noticeLines is §3.5's rendering of the sockets the dashboard cannot show: a
// card per schema-skewed daemon, and a warn line per socket that answered with
// something that is not a snapshot, for as long as the problem persists. Both
// also get a switcher row (§3.4); the difference is that these are the copy
// that never waits for a keypress.
func (m Model) noticeLines(lo layout) []string {
	var out []string
	for _, s := range m.skewed {
		out = append(out, m.skewCard(lo, s)...)
	}
	w := lo.contentWidth() - 3
	for _, p := range m.problems {
		out = append(out, " "+styleWarn.Render("! ")+truncEnd(oneLine("a socket answered with something that is not a snapshot: "+p.Error()), w))
	}
	return out
}

// skewCard is §3.5's wording for a daemon speaking a schema this build does
// not know. Frozen fields only — schema and version are all a skewed payload
// carries — plus the path, which is how the user knows which daemon to
// restart.
//
// Two lines by construction rather than by wrapping: the path is one atom (it
// has spaces in it on every Mac, so word-wrapping would split it mid-directory
// and read as two paths), and the sentence's own comma is where it breaks
// anyway.
func (m Model) skewCard(lo layout, s *introspect.Snapshot) []string {
	inner := lo.contentWidth() - 5
	full := fmt.Sprintf("speaks introspection schema %d; this build knows %d (daemon %s, CLI %s)",
		s.State.Schema, introspect.Schema, orUnknown(s.State.Version), m.version)
	if visWidth(full) > inner {
		full = fmt.Sprintf("speaks schema %d; this build knows %d (daemon %s, CLI %s)",
			s.State.Schema, introspect.Schema, orUnknown(s.State.Version), m.version)
	}
	body := []string{
		"daemon at " + truncMiddle(oneLine(s.Path), inner-10),
		truncEnd(full, inner),
	}
	return indentAll(titledCard("schema skew", body, lo.contentWidth()-1), 1)
}

// summaryLines is the daemon box (wide) or the borderless summary (compact).
// The resolution strings are rendered verbatim — they are what doctor prints,
// and re-wording them here would make two vocabularies for one fact.
func (m Model) summaryLines(lo layout, s *introspect.Snapshot) []string {
	if lo.wide {
		return m.summaryBox(lo, s)
	}
	return m.summaryCompact(lo, s)
}

func (m Model) summaryBox(lo layout, s *introspect.Snapshot) []string {
	st := s.State
	pal, stale := m.palette(s)
	box := lo.contentWidth() - 1 // one column of left margin
	inner := box - 2
	iw := inner - 2

	title := st.VM.Ref + " ─ " + joinDot(flavor(s.Path)+" socket",
		fmt.Sprintf("pid %d", st.PID), m.versionChip(pal, st), "up "+relative(m.now.Sub(st.StartedAt)))
	top := "┌ " + truncEnd(title, inner-4) + " "
	top += strings.Repeat("─", max(0, box-1-visWidth(top))) + "┐"

	var body []string
	if stale {
		body = append(body, styleWarn.Render(truncEnd(m.stoppedText(s)+" ("+s.Path+")", iw)))
	}
	body = append(body,
		field(pal, "endpoint", joinFields(orUnknown(st.Resolution.Endpoint),
			pal.label.Render("source ")+orUnknown(st.Resolution.Source),
			pal.label.Render("resolved ")+relative(m.now.Sub(st.Resolution.ResolvedAt))+" ago")))
	if st.Resolution.Note != "" {
		body = append(body, field(pal, "note", st.Resolution.Note))
	}
	body = append(body, field(pal, "auth", authSessions(pal, m.now, st)))

	out := []string{" " + top}
	for _, l := range body {
		out = append(out, " │ "+padRight(l, iw)+" │")
	}
	return append(out, " └"+strings.Repeat("─", inner)+"┘")
}

func (m Model) summaryCompact(lo layout, s *introspect.Snapshot) []string {
	st := s.State
	pal, stale := m.palette(s)
	w := lo.contentWidth() - lo.indent
	pad := strings.Repeat(" ", lo.indent)

	var body []string
	if stale {
		body = append(body, styleWarn.Render(truncEnd(m.stoppedText(s), w)))
	}
	body = append(body,
		joinDot(st.VM.Ref, flavor(s.Path), fmt.Sprintf("pid %d", st.PID), m.versionChipCompact(pal, st),
			"up "+relative(m.now.Sub(st.StartedAt))),
		pal.label.Render("endpoint ")+orUnknown(st.Resolution.Endpoint)+" ("+orUnknown(st.Resolution.Source)+")")
	if st.Resolution.Note != "" {
		body = append(body, pal.label.Render("note ")+st.Resolution.Note)
	}
	body = append(body, pal.label.Render("auth ")+authText(pal, st))
	body = append(body, pal.label.Render("mirror ")+pal.upDown(st.Mirror.SessionUp)+eventText(m.now, st.Mirror, "event")+
		"   "+pal.label.Render("sync ")+syncCompact(pal, st.Sync))

	out := make([]string, 0, len(body))
	for _, l := range body {
		out = append(out, pad+truncEnd(l, w))
	}
	return out
}

// palette picks the style set for the selected daemon's summary: a daemon that
// stopped answering keeps its last-known summary on screen, dimmed, with the
// news on top (§3.5, D7 — the view never yanks itself to another daemon at the
// moment the user is watching this one die).
func (m Model) palette(s *introspect.Snapshot) (palette, bool) {
	if m.stale(s) {
		return stalePalette(), true
	}
	return livePalette(), false
}

func (m Model) stoppedText(s *introspect.Snapshot) string {
	return fmt.Sprintf("this daemon stopped answering %s ago",
		relative(time.Duration(m.missedTicks[s.Path])*refreshInterval))
}

// field is one labelled line inside the summary box.
func field(pal palette, label, value string) string {
	return pal.label.Render(padRight(label, labelW)) + value
}

// joinFields is the box's four-space column gap.
func joinFields(parts ...string) string { return strings.Join(parts, "    ") }

// versionChip is §3.1's skew chip: when the daemon's version differs from this
// CLI's, the box title carries the remedy rather than a bare mismatch — same
// wording as doctor check 9.
func (m Model) versionChip(pal palette, st introspect.State) string {
	if st.Version == "" || st.Version == m.version {
		return "daemon " + orUnknown(st.Version)
	}
	return pal.warn.Render(fmt.Sprintf("daemon %s ≠ CLI %s — sudo drawbridge install", st.Version, m.version))
}

func (m Model) versionChipCompact(pal palette, st introspect.State) string {
	if st.Version == "" || st.Version == m.version {
		return orUnknown(st.Version)
	}
	return pal.warn.Render(fmt.Sprintf("%s ≠ CLI %s", st.Version, m.version))
}

// authText is the auth posture in two words: the mode in force and the
// daemon's own last read of the secret file. The path is machinery — mode and
// state carry the whole signal, and the bytes never appear at any width (§3.6).
func authText(pal palette, st introspect.State) string {
	return orUnknown(st.Auth.Mode) + " " + pal.secret(st.Auth.SecretState).Render(orUnknown(st.Auth.SecretState))
}

// authSessions is the wide box's second content line: the auth posture and
// both session states, three facts read independently, so the gap between them
// is wider than the separators inside each.
func authSessions(pal palette, now time.Time, st introspect.State) string {
	return strings.Join([]string{
		authText(pal, st),
		pal.label.Render("mirror ") + pal.upDown(st.Mirror.SessionUp) + eventText(now, st.Mirror, "event"),
		pal.label.Render("sync ") + pal.upDown(st.Sync.SessionUp) + fmt.Sprintf(" · pool %d parked", st.Sync.PoolParked),
	}, "   ·   ")
}

// eventText is `lastEventAt` as relative time. The label shortens with the
// layout — the compact summary has no room for a word it can spare.
func eventText(now time.Time, mir introspect.Mirror, label string) string {
	if mir.LastEventAt.IsZero() {
		return ""
	}
	return " · " + label + " " + relative(now.Sub(mir.LastEventAt)) + " ago"
}

// syncCompact is where the sync table goes below the wide breakpoint: the
// advertised count and the pool, on the summary line.
func syncCompact(pal palette, sy introspect.Sync) string {
	return fmt.Sprintf("%s · adv %d · parked %d", pal.upDown(sy.SessionUp), len(sy.Advertised)+len(sy.UDPPorts), sy.PoolParked)
}

// rowBudget is the elastic region: everything else on the screen is fixed, and
// what is left over belongs to the mirror table.
func (m Model) rowBudget(lo layout, s *introspect.Snapshot) int {
	fixed := len(m.chromeLines(lo)) + len(m.summaryLines(lo, s)) + 1 /*footer*/ + 2 /*table headers*/
	fixed += m.paneLines(lo)
	return max(1, lo.height-fixed)
}

// tableLines renders the mirror table — and, in the wide layout, the sync
// table beside it — into at most `budget` body rows.
func (m Model) tableLines(lo layout, s *introspect.Snapshot, budget int) []string {
	st := s.State
	pad := strings.Repeat(" ", lo.indent)

	left := m.mirrorBlock(lo, st, budget)
	if !lo.wide {
		out := make([]string, 0, len(left))
		for _, l := range left {
			out = append(out, pad+l)
		}
		return out
	}

	right := m.syncBlock(lo, st.Sync, budget)
	n := max(len(left), len(right))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		// The rule runs the full height of the taller region, header rows
		// included: two tables sharing one grid, not two lists that happen to
		// sit beside each other.
		out = append(out, pad+padRight(l, lo.mirrorWidth)+styleDim.Render("│")+" "+r)
	}
	return out
}

func (m Model) mirrorBlock(lo layout, st introspect.State, budget int) []string {
	entries := sortedEntries(st.Mirror.Entries)
	// The skip list rides in the header: it is a property of what this table
	// shows, not a row of it, and a floating line under the table moved every
	// time the table's height did. Styles are composed rather than nested — a
	// dim segment inside a bold Render ends at the inner reset.
	skip := ""
	if len(st.Mirror.Skip) > 0 {
		skip = " · " + skipTextCompact(st.Mirror.Skip)
	}
	head := styleTitle.Render(fitText(lo.mirrorWidth-visWidth(skip),
		fmt.Sprintf("MIRROR — guest listeners on Mac localhost (%d)", len(entries)),
		fmt.Sprintf("MIRROR — guest listeners (%d)", len(entries)),
		fmt.Sprintf("MIRROR (%d)", len(entries)))) + styleDim.Render(skip)
	if !lo.wide {
		head = styleTitle.Render(fmt.Sprintf("MIRROR (%d)", len(entries)))
		if len(st.Mirror.Skip) > 0 {
			s := skipTextCompact(st.Mirror.Skip)
			head = padRight(head, lo.mirrorWidth-visWidth(s)) + styleDim.Render(s)
		}
	}
	cols := padRight("PROTO", protoW) + padRight("PORT", portW) + padRight("STATE", stateW)
	if lo.showSince {
		cols += "SINCE"
	}
	out := []string{head, styleDim.Render(cols)}

	if len(entries) == 0 {
		if !st.Mirror.SessionUp {
			return append(out, styleWarn.Render("(mirror session down — press d for a diagnosis)"))
		}
		return append(out, styleDim.Render("(no guest listeners mirrored yet)"))
	}

	rows := make([]string, 0, len(entries))
	for _, e := range entries {
		row := padRight(e.Proto, protoW) + padRight(strconv.Itoa(int(e.Port)), portW) +
			entryStyle(e.State).Render(padRight(e.State, stateW))
		if lo.showSince {
			row += relative(m.now.Sub(e.Since))
		}
		rows = append(rows, row)
	}
	return append(out, windowRows(rows, m.tableScroll(), budget)...)
}

func (m Model) syncBlock(lo layout, sy introspect.Sync, budget int) []string {
	rows := sortedAdvertised(sy)
	out := []string{
		styleTitle.Render(fitText(lo.contentWidth()-syncCol,
			fmt.Sprintf("SYNC — Mac ports advertised to guest (%d)", len(rows)),
			fmt.Sprintf("SYNC — Mac ports advertised (%d)", len(rows)),
			fmt.Sprintf("SYNC (%d)", len(rows)))),
		styleDim.Render(padRight("PROTO", protoW) + "PORT"),
	}
	if len(rows) == 0 {
		return append(out, styleDim.Render("(nothing advertised)"))
	}
	// The header counts the advertised set, not the rows: the fold is a way of
	// showing the same set, so the number must not move when `x` does.
	//
	// The sync set is not the scrollable region (§3.1 names the mirror table);
	// it truncates with the same tail so an overflow is never silent.
	return append(out, windowRows(m.syncRows(lo, rows), scrollState{}, budget)...)
}

// syncRows folds each proto's ephemeral run into one line unless `x` says
// otherwise. The input is sorted by port within proto, so a proto's ephemeral
// ports are exactly the tail of its run and a fold is one slice.
func (m Model) syncRows(lo layout, rows []introspect.Advertised) []string {
	out := make([]string, 0, len(rows))
	for i := 0; i < len(rows); {
		j := i
		for j < len(rows) && rows[j].Proto == rows[i].Proto {
			j++
		}
		out = append(out, m.protoRows(lo, rows[i:j])...)
		i = j
	}
	return out
}

func (m Model) protoRows(lo layout, rows []introspect.Advertised) []string {
	first := len(rows)
	for i, a := range rows {
		if a.Port >= ephemeralMin {
			first = i
			break
		}
	}
	out := make([]string, 0, len(rows))
	for _, a := range rows[:first] {
		out = append(out, syncRow(a))
	}
	eph := rows[first:]
	if m.syncExpanded || len(eph) < foldEphemeral {
		for _, a := range eph {
			out = append(out, syncRow(a))
		}
		return out
	}
	return append(out, foldRow(lo, eph))
}

func syncRow(a introspect.Advertised) string {
	return padRight(a.Proto, protoW) + strconv.Itoa(int(a.Port))
}

// foldHint is the only thing on screen that says `x` does anything here, so a
// region too narrow for it drops it rather than truncating it to an ellipsis —
// the key still works, and the full map is one `?` away.
const foldHint = "  x expand"

func foldRow(lo layout, eph []introspect.Advertised) string {
	row := padRight(eph[0].Proto, protoW) +
		fmt.Sprintf("·%d ephemeral (%d–%d)", len(eph), eph[0].Port, eph[len(eph)-1].Port)
	if visWidth(row)+visWidth(foldHint) <= lo.contentWidth()-syncCol {
		row += foldHint
	}
	return styleDim.Render(row)
}

// tableScroll is the mirror table's window: m.scroll only while the table is
// the region the keys drive, and the top of the table otherwise. With the
// refusals pane open the offset belongs to the pane, and applying it here
// would scroll a table the user never touched.
func (m Model) tableScroll() scrollState {
	if m.scrollRegion() == regionMirror {
		return m.scroll
	}
	return scrollState{}
}

// windowRows applies the scroll region to a row list. Unscrolled overflow ends
// in a `… +N more` tail so the count is never hidden behind the fold.
func windowRows(rows []string, s scrollState, visible int) []string {
	if visible <= 0 {
		return nil
	}
	if len(rows) <= visible {
		return rows
	}
	if s.offset == 0 {
		out := make([]string, 0, visible)
		out = append(out, rows[:visible-1]...)
		return append(out, styleDim.Render(fmt.Sprintf("… +%d more", len(rows)-(visible-1))))
	}
	lo, hi := s.window(len(rows), visible)
	return rows[lo:hi]
}

// sortedEntries is §3.1's order: problems first by state class, then by port
// within proto. The daemon's own order is arrival order, which makes a row jump
// under the cursor for no reason; the class order puts the rows a user opened
// the TUI for at the top and the default exclusions at the bottom. The order is
// total, so nothing moves between refreshes except what changed state.
func sortedEntries(in []introspect.MirrorEntry) []introspect.MirrorEntry {
	out := append([]introspect.MirrorEntry(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := stateRank(out[i].State), stateRank(out[j].State); a != b {
			return a < b
		}
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// stateRank orders the state classes. A state this build does not know sorts
// with the problems rather than under them — an unrecognised word is not
// evidence that the entry is fine.
func stateRank(state string) int {
	switch state {
	case introspect.EntryBindFailed:
		return 0
	case introspect.EntryBound:
		return 2
	case introspect.EntrySkipped:
		return 3
	default:
		return 1
	}
}

// sortedAdvertised folds Sync.UDPPorts into the advertised rows labelled udp,
// then applies the same order.
func sortedAdvertised(sy introspect.Sync) []introspect.Advertised {
	out := append([]introspect.Advertised(nil), sy.Advertised...)
	for _, p := range sy.UDPPorts {
		out = append(out, introspect.Advertised{Proto: "udp", Port: p})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func skipTextCompact(s []uint16) string { return "skip: " + portList(s) }

func portList(ports []uint16) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	return strings.Join(parts, ",")
}

// noDaemonCard is §3.5's ordinary pre-start state, deliberately not styled as
// an error: nothing is wrong with a Mac that has not started a daemon yet.
func (m Model) noDaemonCard(lo layout) []string {
	body := []string{
		"no drawbridge daemon is answering",
		"",
		styleDim.Render("checked"),
		"  " + introspect.RootSocketPath,
		"  " + m.userRunDir,
		"",
		styleDim.Render("start one"),
		"  drawbridged                  foreground; mirrors ports ≥1024",
		"  sudo drawbridge install      the root LaunchDaemon, for ports <1024",
		"",
		styleDim.Render("re-checking every second — this screen heals itself"),
	}
	inner := 0
	for _, l := range body {
		inner = max(inner, visWidth(l))
	}
	inner = min(inner, lo.contentWidth()-4)
	for i, l := range body {
		body[i] = truncEnd(l, inner)
	}
	return indentAll(card("no daemon", body, inner), 1)
}

// helpVisible is the overlay's body height: the chrome, the blank spacer, the
// card's two borders, the refusals pane if it is open and the footer are
// fixed, and the rest is the map. A terminal too short for all of §4.1 scrolls
// rather than hiding the tail.
func (m Model) helpVisible(lo layout) int {
	// chrome + the blank spacer + the card's two borders + the footer.
	return max(1, lo.height-len(m.chromeLines(lo))-4-m.paneLines(lo))
}

func (m Model) helpView() string {
	lo := m.layout()
	body := windowRows(helpBody(m.keys), m.scroll, m.helpVisible(lo))
	head := append(m.chromeLines(lo), "")
	head = append(head, indentAll(titledCard("keys", body, lo.contentWidth()-1), 1)...)
	return m.frame(head, lo)
}

// tooSmallView is the whole screen below 44×12: a terminal this small cannot
// carry a table honestly, and half a table is worse than a sentence. All
// layout derives from the last WindowSizeMsg, so resizing back restores the
// full view with no state involved.
func tooSmallView(width, height int) string {
	msg := fmt.Sprintf("window too small (need ≥ %d×%d)", minWidth, minHeight)
	lines := make([]string, 0, height)
	top := max(0, (height-1)/2)
	for i := 0; i < top; i++ {
		lines = append(lines, "")
	}
	lines = append(lines, strings.TrimRight(center(truncEnd(msg, width), width), " "))
	for len(lines) < height {
		lines = append(lines, "")
	}
	return strings.Join(lines[:height], "\n")
}

// titledCard boxes a body, sized to the widest line it was given but never
// wider than the terminal. Every overlay is one of these — the help map, the
// switcher list, the skew card — so they share a shape as well as a border.
func titledCard(title string, body []string, width int) []string {
	inner := 0
	for _, l := range body {
		if w := visWidth(l); w > inner {
			inner = w
		}
	}
	if maxInner := width - 4; inner > maxInner {
		inner = maxInner
	}
	for i, l := range body {
		body[i] = truncEnd(l, inner)
	}
	return card(title, body, inner)
}

// card draws a titled box around body lines already truncated to inner.
func card(title string, body []string, inner int) []string {
	if inner < 1 {
		inner = 1
	}
	top := "┌ " + truncEnd(title, inner) + " "
	top += strings.Repeat("─", max(0, inner+3-visWidth(top))) + "┐"
	out := []string{top}
	for _, l := range body {
		out = append(out, "│ "+padRight(l, inner)+" │")
	}
	return append(out, "└"+strings.Repeat("─", inner+2)+"┘")
}

func indentAll(lines []string, n int) []string {
	pad := strings.Repeat(" ", n)
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, pad+l)
	}
	return out
}

// Text primitives. Everything measures with lipgloss.Width so an already
// styled segment does not have its escape bytes counted as columns; padding is
// always computed from the visible width, never len().

func visWidth(s string) int { return lipgloss.Width(s) }

func padRight(s string, n int) string {
	if d := n - visWidth(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return truncEnd(s, n)
}

// fitText is the house fallback, the same shape the footer and the D8 banner
// use: the widest spelling that fits, and the narrowest when none does. A
// table title truncated mid-word teaches nothing, and the wide layout's two
// titles fit their sentences at 120 columns but not at 100.
func fitText(width int, spellings ...string) string {
	for _, s := range spellings {
		if visWidth(s) <= width {
			return s
		}
	}
	return spellings[len(spellings)-1]
}

func truncEnd(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if visWidth(s) <= n {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(n-1).Render(s) + "…"
}

// truncMiddle keeps both ends of a path: the directory says where it lives and
// the basename says which VM it belongs to, and losing either makes the line
// useless.
func truncMiddle(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if visWidth(s) <= n {
		return s
	}
	if n < 5 {
		return ""
	}
	r := []rune(s)
	keep := n - 1
	head := keep / 2
	return string(r[:head]) + "…" + string(r[len(r)-(keep-head):])
}

func center(s string, total int) string {
	d := total - visWidth(s)
	if d <= 0 {
		return s
	}
	return strings.Repeat(" ", d/2) + s
}

// rightAlign seats `right` at the end of a `total`-wide line. The right
// segment is the status, so a line too narrow for both sheds the left one
// rather than pushing the status off the edge.
func rightAlign(left, right string, total int) string {
	if visWidth(right) >= total {
		return truncEnd(right, total)
	}
	left = truncEnd(left, total-visWidth(right)-1)
	gap := total - visWidth(left) - visWidth(right)
	if gap < 1 {
		gap = 1
	}
	return left + strings.Repeat(" ", gap) + right
}

// oneLine flattens a daemon-supplied string. Every rendered line is one row of
// the frame, and a newline smuggled in through a resolver note or an error
// would shear every line below it.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}

// relative is the one duration spelling in the UI. Seconds below a minute,
// minutes below an hour, hours-and-minutes below a day.
func relative(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Second:
		return "<1s"
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 24*time.Hour:
		h, m := int(d/time.Hour), int(d%time.Hour/time.Minute)
		if m == 0 {
			return strconv.Itoa(h) + "h"
		}
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		days, h := int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour)
		if h == 0 {
			return strconv.Itoa(days) + "d"
		}
		return fmt.Sprintf("%dd%dh", days, h)
	}
}

// flavor names which daemon a socket belongs to. Path-based, because "root
// socket" and "user socket" are statements about the path, and the D8 banner
// compares the same two flavors.
const (
	flavorRoot = "root"
	flavorUser = "user"
)

func flavor(path string) string {
	if path == introspect.RootSocketPath {
		return flavorRoot
	}
	return flavorUser
}

// orUnknown is the last stop for every daemon-supplied string on its way to
// the screen, which is where flattening belongs.
func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return oneLine(s)
}
