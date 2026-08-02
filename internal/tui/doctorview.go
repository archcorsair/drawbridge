package tui

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
	tea "github.com/charmbracelet/bubbletea"
)

// The doctor view (docs/tui.md §3.3) over D6's async gather.
//
// Gather takes seconds — guest shell probes at 10 s ceilings inside the
// -timeout budget, and -probe puts a floor under it — so it runs in a tea.Cmd
// goroutine while the 1 Hz snapshot loop keeps running underneath: returning
// to the dashboard is instant and current. Every run carries an integer
// generation; `esc` cancels its context and bumps the generation, and a
// completion message carrying a stale one is dropped on the floor. The
// canceled goroutine may take a probe timeout to unwind and nothing waits for
// it.
//
// Classify is pure and instantaneous, so the command does both halves and the
// model only ever sees a Report. Findings are rendered natively from the
// Finding struct rather than by piping Report.Render's text through a pager,
// because per-status color and per-finding expansion are the point.

type doctorPhase int

const (
	doctorIdle doctorPhase = iota
	doctorRunning
	doctorDone
	doctorFailed
)

const (
	// doctorStatusW is the bracketed status column, sized for the longest of
	// them. The words stay whatever the color does — §3.6's rule is that color
	// is never the only carrier — so `[warn]` reads as warn on a mono terminal.
	doctorStatusW = 6
	// doctorRemedyIndent and doctorEvidenceIndent reproduce Report.Render's
	// relationship between the two: the remedy sits at the title column behind
	// its arrow, the evidence two columns further in.
	doctorRemedyIndent   = doctorStatusW + 1
	doctorEvidenceIndent = doctorRemedyIndent + 2
	// doctorCursor marks the selected finding at the right edge of its row
	// (§3.3's mockup). It is the only marker on the screen, which is what makes
	// one character enough.
	doctorCursor = "◂"
	// spinnerInterval is the spinner's own cadence: the 1 Hz snapshot tick is
	// too slow to read as motion, and this is the whole reason the doctor view
	// has a second timer. It runs only while a gather is in flight, and its
	// chain dies with the generation it was started for.
	spinnerInterval = 250 * time.Millisecond
	// doctorClock is the `ran at` spelling — the refusals pane's, formatted in
	// the same local zone for the same reason (the daemon that stamped it runs
	// on this Mac).
	doctorClock = refusalClock
)

// spinnerFrames is D3's ten-line spinner: bubbles stays out for one widget
// that is a frame cycler over a tick the model already needed.
var spinnerFrames = [...]string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// doctorReadOnly is the running screen's second line, verbatim from §3.3: the
// one sentence that answers "what is it doing to my machine" without waiting
// for a keypress. Gather is reads only and never spawns sudo, and a user
// watching a progress spinner deserves to be told so.
const doctorReadOnly = "(checks are read-only; nothing is mutated, sudo is never spawned)"

// doctorState is the view's whole state machine: idle before the first run,
// running with a generation and the cancel that belongs to it, done with a
// report, failed with the gather error (doctor's exit-2 class).
//
// report/ranAt/elapsed/err outlive their phase on purpose. Results persist
// across view switches (§3.3) — `d` re-entered shows the last report with its
// age — and a canceled re-run falls back to whichever screen was on display
// before it started rather than throwing the previous diagnosis away.
type doctorState struct {
	phase doctorPhase
	// gen is bumped by every start and every cancel. A message carrying an
	// older one is a run nobody is waiting for any more.
	gen    int
	cancel context.CancelFunc
	since  time.Time
	// probe records whether the in-flight run is the priced one, so the
	// running screen can say so.
	probe bool
	frame int
	// restore is the phase a cancel returns to: the screen the run replaced.
	restore doctorPhase

	report  doctor.Report
	ranAt   time.Time
	elapsed time.Duration
	err     error

	cursor int
	// expanded is keyed by Finding.ID, which is the stable half of a finding
	// (the prose is not), so an expansion survives a re-run of the same check.
	expanded map[string]bool
}

// doctorDoneMsg and doctorFailedMsg are the gather command's two landings.
// Both carry the generation they were started for and the wall clock of the
// run, because "ran at" is when the gather began, not when the model heard
// about it.
type doctorDoneMsg struct {
	gen     int
	report  doctor.Report
	ranAt   time.Time
	elapsed time.Duration
}

type doctorFailedMsg struct {
	gen     int
	err     error
	ranAt   time.Time
	elapsed time.Duration
}

// doctorTickMsg drives the spinner. It carries its generation so a canceled
// run's chain stops at the next frame instead of ticking forever.
type doctorTickMsg struct{ gen int }

func doctorTickCmd(gen int) tea.Cmd {
	return tea.Tick(spinnerInterval, func(time.Time) tea.Msg { return doctorTickMsg{gen: gen} })
}

// startDoctorCmd builds one run: the cancel goes to the model, the command
// goes to bubbletea. Gather and Classify both happen on the command goroutine
// — Classify is pure and microseconds, and splitting them into two messages
// would buy nothing but a second stale-generation check.
//
// The context is never given a deadline here: -timeout is Options.Timeout and
// Gather applies it (with the -probe floor) itself. Reimplementing that ceiling
// on this side would silently override the floor the probe needs.
func startDoctorCmd(gen int, opts doctor.Options) (context.CancelFunc, tea.Cmd) {
	ctx, cancel := context.WithCancel(context.Background())
	return cancel, func() tea.Msg {
		start := time.Now()
		in, err := doctor.Gather(ctx, opts)
		if err != nil {
			return doctorFailedMsg{gen: gen, err: err, ranAt: start, elapsed: time.Since(start)}
		}
		return doctorDoneMsg{gen: gen, report: doctor.Classify(in), ranAt: start, elapsed: time.Since(start)}
	}
}

// doctorOptions is §3.3's seeding rule. The TUI's own -vm wins; with none, the
// selected daemon's canonical ref seeds it so the diagnosis targets the daemon
// the user is looking at; with no daemon at all it stays empty and doctor does
// its own single-running-instance selection, exactly as the CLI verb does.
//
// Subnet, HWAddr and Timeout pass through untouched: a TUI user on a pinned
// install gets the same lease view `drawbridge doctor` gives, and the -probe
// timeout floor stays Gather's own.
func (m Model) doctorOptions(probe bool) doctor.Options {
	o := doctor.Options{
		VM:         m.opts.VM,
		Subnet:     m.opts.Subnet,
		HWAddr:     m.opts.HWAddr,
		Timeout:    m.opts.Timeout,
		CLIVersion: m.version,
		Probe:      probe,
	}
	if o.VM == "" {
		if s := m.selectedSnap(); s != nil {
			o.VM = s.State.VM.Ref
		}
	}
	return o
}

// openDoctor is the `d` arm. Entering runs a plain gather immediately — the
// user pressed `d` because they want a diagnosis and gather is read-only, so
// there is nothing to confirm — but only on the first entry: a run is seconds,
// not a tick, and re-entering shows the last report with its age. `R` is the
// explicit refresh.
func (m Model) openDoctor() (Model, tea.Cmd) {
	if m.view == viewDoctor {
		return m, nil
	}
	m.view = viewDoctor
	m.scroll = m.freshScroll()
	if m.doctor.phase == doctorIdle {
		return m.startDoctor(false)
	}
	return m, nil
}

// startDoctor cancels whatever was in flight, bumps the generation and starts
// a run. probe is `p`: the half-close probe is a priced action (its window
// outlasts the agent's liveness ping), never a default.
func (m Model) startDoctor(probe bool) (Model, tea.Cmd) {
	d := m.doctor.stop()
	d.restore = d.phase
	d.phase, d.probe = doctorRunning, probe
	d.since, d.frame = m.now, 0
	cancel, cmd := startDoctorCmd(d.gen, m.doctorOptions(probe))
	d.cancel = cancel
	m.doctor = d
	m.scroll = scrollState{}
	return m, tea.Batch(cmd, doctorTickCmd(d.gen))
}

// stop cancels an in-flight gather and bumps the generation so its completion
// lands on nothing. Canceling is the one side effect Update performs: it takes
// no lock, cannot block, and the alternative (waiting for a probe to unwind
// before the screen responds) is the thing D6 exists to avoid.
func (d doctorState) stop() doctorState {
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	if d.phase == doctorRunning {
		d.phase = d.restore
	}
	d.gen++
	return d
}

// handleDoctorKey is §4.1's doctor-view table. It answers before the shared
// arms so esc, enter, j/k and the paging keys mean what the doctor view says
// they mean; everything it does not claim falls through to the global map, so
// `tab`, `1`–`9`, `v` and `r` keep working from inside the view.
func (m Model) handleDoctorKey(msg tea.KeyMsg) (Model, tea.Cmd, bool) {
	k := m.keys
	switch {
	case k.Esc.matches(msg):
		// The two-step §4.1 fixes: cancel a running gather, else back to the
		// dashboard. One key, and neither meaning can surprise the other —
		// there is always something on screen that says which state this is.
		if m.doctor.phase == doctorRunning {
			m.doctor = m.doctor.stop()
			return m, nil, true
		}
		m.view = viewDashboard
		m.scroll = m.freshScroll()
		return m, nil, true
	case k.Rerun.matches(msg):
		next, cmd := m.startDoctor(false)
		return next, cmd, true
	case k.Probe.matches(msg):
		next, cmd := m.startDoctor(true)
		return next, cmd, true
	case k.Expand.matches(msg):
		m.doctor = m.doctor.toggleExpanded()
		return m.revealCursor(), nil, true
	case k.LineDown.matches(msg):
		return m.moveDoctorCursor(1), nil, true
	case k.LineUp.matches(msg):
		return m.moveDoctorCursor(-1), nil, true
	case k.PageDown.matches(msg):
		return m.moveDoctorCursor(max(1, m.doctorBudget(m.layout()))), nil, true
	case k.PageUp.matches(msg):
		return m.moveDoctorCursor(-max(1, m.doctorBudget(m.layout()))), nil, true
	case k.Top.matches(msg):
		return m.moveDoctorCursor(-len(m.doctor.report.Findings)), nil, true
	case k.Bottom.matches(msg):
		return m.moveDoctorCursor(len(m.doctor.report.Findings)), nil, true
	}
	return m, nil, false
}

// applyDoctorDone and applyDoctorFailed are D6's stale-generation drop. A
// canceled run's message arrives whenever its probes unwind; by then the
// generation has moved and the model has already gone back to whatever it was
// showing.
func (m Model) applyDoctorDone(msg doctorDoneMsg) Model {
	d := m.doctor
	if d.phase != doctorRunning || msg.gen != d.gen {
		return m
	}
	d.cancel = nil
	d.phase = doctorDone
	d.report, d.ranAt, d.elapsed, d.err = msg.report, msg.ranAt, msg.elapsed, nil
	m.doctor = d
	return m.revealCursor()
}

func (m Model) applyDoctorFailed(msg doctorFailedMsg) Model {
	d := m.doctor
	if d.phase != doctorRunning || msg.gen != d.gen {
		return m
	}
	d.cancel = nil
	d.phase = doctorFailed
	d.err, d.ranAt, d.elapsed = msg.err, msg.ranAt, msg.elapsed
	m.doctor = d
	return m
}

// tickDoctor advances the spinner and re-arms itself for as long as the run it
// belongs to is the current one. A canceled or completed run's chain ends here
// rather than spinning a timer nobody reads.
func (m Model) tickDoctor(msg doctorTickMsg) (Model, tea.Cmd) {
	d := m.doctor
	if d.phase != doctorRunning || msg.gen != d.gen {
		return m, nil
	}
	d.frame++
	m.doctor = d
	return m, doctorTickCmd(msg.gen)
}

func (d doctorState) cursorIndex() int {
	n := len(d.report.Findings)
	if n == 0 {
		return -1
	}
	return min(max(d.cursor, 0), n-1)
}

// toggleExpanded flips the selected finding. The map is rebuilt rather than
// mutated: Model is a value, and an in-place write would let one Update's
// expansion set alias another's.
func (d doctorState) toggleExpanded() doctorState {
	i := d.cursorIndex()
	if i < 0 {
		return d
	}
	id := d.report.Findings[i].ID
	next := make(map[string]bool, len(d.expanded)+1)
	for k, v := range d.expanded {
		next[k] = v
	}
	next[id] = !next[id]
	d.expanded = next
	return d
}

func (m Model) moveDoctorCursor(n int) Model {
	d := m.doctor
	if len(d.report.Findings) == 0 {
		return m
	}
	d.cursor = min(max(d.cursorIndex()+n, 0), len(d.report.Findings)-1)
	m.doctor = d
	return m.revealCursor()
}

// revealCursor scrolls the findings list just far enough to show the selected
// finding — its whole block when the expansion fits, its header line when it
// does not. The region only moves when the cursor would otherwise leave it.
func (m Model) revealCursor() Model {
	if m.scrollRegion() != regionDoctor {
		return m
	}
	lo := m.layout()
	rows, starts := m.doctorRows(lo)
	i := m.doctor.cursorIndex()
	if i < 0 || i >= len(starts) {
		return m
	}
	last := len(rows) - 1
	if i+1 < len(starts) {
		last = starts[i+1] - 1
	}
	m.scroll = m.scroll.reveal(starts[i], last, len(rows), m.doctorBudget(lo))
	return m
}

// doctorBudget is the findings list's height: everything else on the doctor
// screen is fixed, and what is left over is the list.
func (m Model) doctorBudget(lo layout) int {
	fixed := len(m.chromeLines(lo)) + 1 /*header*/ + 1 /*summary*/ + 1 /*footer*/ + m.paneLines(lo)
	return max(1, lo.height-fixed)
}

func (m Model) doctorView() string {
	lo := m.layout()
	body := m.chromeLines(lo)
	switch m.doctor.phase {
	case doctorRunning:
		body = append(body, m.doctorRunningLines(lo)...)
	case doctorDone:
		body = append(body, m.doctorReportLines(lo)...)
	case doctorFailed:
		body = append(body, m.doctorFailedLines(lo)...)
	default:
		// Unreachable while `d` auto-runs on an idle state, and rendered
		// anyway: a screen that says what to press beats an empty one.
		body = append(body, " "+styleDim.Render("doctor — press R to run the check catalog"))
	}
	return m.frame(body, lo)
}

// doctorRunningLines is §3.3's running screen: what it is doing, how long it
// has been doing it, a spinner, and the two things the user can act on — esc,
// and the knowledge that nothing is being mutated. No fake progress stages:
// Gather exposes no finer granularity and inventing one would be lying.
func (m Model) doctorRunningLines(lo layout) []string {
	pad := strings.Repeat(" ", lo.indent)
	w := lo.contentWidth() - lo.indent
	left := "doctor — gathering… "
	if m.doctor.probe {
		left += "with probe (~20s+) "
	}
	left += secondsText(m.now.Sub(m.doctor.since)) + "   " + m.doctor.spinner()
	return []string{
		pad + rightAlign(left, styleDim.Render("esc cancel"), w),
		pad + styleDim.Render(truncEnd(doctorReadOnly, w)),
	}
}

func (d doctorState) spinner() string {
	return spinnerFrames[((d.frame%len(spinnerFrames))+len(spinnerFrames))%len(spinnerFrames)]
}

// doctorReportLines is the complete screen: the header with the target and the
// run's age, doctor's own catalog order one line per finding, and the summary
// sentence a long report ends with.
func (m Model) doctorReportLines(lo layout) []string {
	pad := strings.Repeat(" ", lo.indent)
	w := lo.contentWidth() - lo.indent
	out := []string{pad + truncEnd(m.doctorHeader(), w)}

	rows, _ := m.doctorRows(lo)
	if len(rows) == 0 {
		rows = []string{styleDim.Render("(the catalog produced no findings)")}
	}
	// Plain windowing, not the table's `… +N more` tail: the summary line
	// directly below already states the total, and a tail line would sit where
	// the cursor is trying to go.
	first, last := m.listScroll().window(len(rows), m.doctorBudget(lo))
	for _, l := range rows[first:last] {
		out = append(out, pad+l)
	}
	return append(out, pad+truncEnd(m.doctor.report.Summary(), w))
}

// doctorHeader names what was diagnosed and when. The age is always shown —
// results persist across view switches (§3.3), so a report on screen has to
// say how old it is or it reads as live.
func (m Model) doctorHeader() string {
	d := m.doctor
	head := "doctor"
	if vm := m.doctorTarget(); vm != "" {
		head += " — " + vm
	}
	return joinDot(head, "ran "+d.ranAt.Format(doctorClock), secondsText(d.elapsed),
		relative(m.now.Sub(d.ranAt))+" ago")
}

// doctorTarget is what the last run diagnosed: the report's own resolved ref
// when it got that far, the seeding rule's answer otherwise (a failed gather
// has no report to ask).
func (m Model) doctorTarget() string {
	if vm := m.doctor.report.VM; vm != "" {
		return oneLine(vm)
	}
	return oneLine(m.doctorOptions(false).VM)
}

// doctorRows renders the findings list and returns the row each finding starts
// at, so the cursor can be revealed without deriving the layout twice.
//
// The cursor marker sits two columns past the longest title rather than at the
// window's right edge: on a wide terminal a marker at column 118 is a marker
// nobody finds, and the list's own block is where the eye already is.
func (m Model) doctorRows(lo layout) (rows []string, starts []int) {
	d := m.doctor
	w := lo.contentWidth() - lo.indent
	cur := d.cursorIndex()

	titles := make([]string, 0, len(d.report.Findings))
	mark := 0
	for _, f := range d.report.Findings {
		t := padRight(doctorStatusStyle(f.Status).Render("["+string(f.Status)+"]"), doctorStatusW) +
			" " + oneLine(f.Title)
		titles = append(titles, t)
		mark = max(mark, min(visWidth(t)+2, w))
	}

	for i, f := range d.report.Findings {
		starts = append(starts, len(rows))
		if i == cur {
			rows = append(rows, rightAlign(titles[i], doctorCursor, mark))
		} else {
			rows = append(rows, truncEnd(titles[i], w))
		}
		if !d.expanded[f.ID] {
			continue
		}
		rows = append(rows, evidenceLines(f, w)...)
	}
	return rows, starts
}

// evidenceLines is one expanded finding's body: evidence indented, remedy
// prefixed `→` — the same content Report.Render prints, styled from the struct
// instead of parsed back out of its text. Evidence is rendered verbatim (§3.6:
// the TUI computes no digests and adds nothing to what doctor generated).
func evidenceLines(f doctor.Finding, w int) []string {
	var out []string
	for _, e := range f.Evidence {
		for _, l := range strings.Split(strings.TrimRight(e, "\n"), "\n") {
			out = append(out, indentedLine(doctorEvidenceIndent, styleDim.Render(oneLine(l)), w))
		}
	}
	if f.Remedy == "" {
		return out
	}
	for i, l := range strings.Split(strings.TrimRight(f.Remedy, "\n"), "\n") {
		prefix := "→ "
		if i > 0 {
			prefix = "  "
		}
		out = append(out, indentedLine(doctorRemedyIndent, prefix+oneLine(l), w))
	}
	return out
}

func indentedLine(indent int, s string, w int) string {
	return strings.Repeat(" ", indent) + truncEnd(s, max(0, w-indent))
}

// doctorFailedLines is doctor's exit-2 class: one card, the error verbatim,
// and the key that retries it. This is the only screen in the package that
// wraps rather than truncates — the error is the entire content, and a
// truncated gather failure is a bug report nobody can file.
func (m Model) doctorFailedLines(lo layout) []string {
	d := m.doctor
	inner := lo.contentWidth() - 5
	body := wrapText(oneLine(d.err.Error()), inner)
	body = append(body, "", styleDim.Render("press R to retry"),
		styleDim.Render(joinDot("attempted "+d.ranAt.Format(doctorClock), secondsText(d.elapsed),
			relative(m.now.Sub(d.ranAt))+" ago")))
	return indentAll(titledCard("doctor could not gather", body, lo.contentWidth()-1), 1)
}

// listScroll is the findings list's window, on the same guard every other
// region uses: an overlay borrows the scroll keys, and a list left at the
// overlay's offset would be showing an arbitrary slice.
func (m Model) listScroll() scrollState {
	if m.scrollRegion() == regionDoctor {
		return m.scroll
	}
	return scrollState{}
}

// secondsText is the one elapsed spelling: whole seconds, truncated, at every
// magnitude. `relative` collapses to minutes above a minute, which is exactly
// the granularity a gather's duration is measured in.
func secondsText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return strconv.Itoa(int(d/time.Second)) + "s"
}

// wrapText breaks a message into rows at spaces, hard-splitting any single
// word wider than the region (a path, an endpoint) rather than dropping its
// tail.
func wrapText(s string, w int) []string {
	if w < 1 {
		return nil
	}
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case visWidth(line)+1+visWidth(word) <= w:
			line += " " + word
		default:
			out = append(out, line)
			line = word
		}
		for visWidth(line) > w {
			r := []rune(line)
			out, line = append(out, string(r[:w])), string(r[w:])
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
