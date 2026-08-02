package tui

import (
	"net/netip"
	"sort"
	"time"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
	tea "github.com/charmbracelet/bubbletea"
)

// Options is what the verb's flags carry in (docs/tui.md §4.3). -vm-subnet,
// -vm-mac and -timeout exist solely to reach the doctor view's Options so a
// TUI user on a pinned install gets the same lease view the CLI verb gives;
// they are stored here and consumed in T3.
type Options struct {
	// VM pre-selects the daemon whose snapshot names this VM, by canonical
	// ref, and seeds the doctor run. Empty means every answering daemon with
	// the first selected.
	VM      string
	Subnet  netip.Prefix
	HWAddr  string
	Timeout time.Duration
	// CLIVersion is what the header prints and what the skew chip compares a
	// daemon's version against. Empty takes the linked buildinfo.Version.
	CLIVersion string
}

type pane int

const (
	paneNone pane = iota
	paneRefusals
)

type view int

const (
	viewDashboard view = iota
	viewDoctor
)

type overlay int

const (
	overlayNone overlay = iota
	overlaySwitcher
	overlayHelp
)

// maxMissedTicks is D7's drop bound: a socket path absent for this many
// consecutive fetches leaves the switcher, and selection falls to the first
// answering daemon. Until then the view stays on it — a daemon dying is
// exactly the moment the user is watching it.
const maxMissedTicks = 30

// Model is the whole state machine. Update is a pure function of it; every
// side effect lives in a tea.Cmd closure, and View is pure over it, which is
// what makes the goldens and the update tables possible.
type Model struct {
	opts    Options
	keys    keyMap
	version string

	// pinProvider/pinInstance are -vm parsed once at construction. Matching a
	// snapshot on the canonical pair rather than the flag text means
	// `colima:default` and `colima:colima` select the same daemon.
	pinProvider string
	pinInstance string
	pinned      bool

	// userRunDir is resolved once, at construction: View is pure, and the
	// no-daemon card names the two paths that were checked.
	userRunDir string

	width, height int

	// snaps holds the usable snapshots in Discover order (root socket first,
	// then the user dir sorted), merged across fetches: a path that stops
	// answering keeps its last-known snapshot here until missedTicks retires
	// it, because §3.5's stopped-answering state is that summary with a
	// message over it.
	snaps []*introspect.Snapshot
	// skewed and problems are the latest fetch only — a schema-skewed or
	// unreadable socket has nothing worth retaining.
	skewed   []*introspect.Snapshot
	problems []error

	fetchedAt   time.Time
	now         time.Time
	fetching    bool
	selected    string
	missedTicks map[string]int

	// refusals is D5's client-side log, per socket path: what the daemon's
	// ring has carried since this TUI attached, capped at refusalCap.
	refusals map[string][]introspect.Refusal
	// refusalsSeen is the newest refusal each path's pane has actually shown,
	// which is what the footer counts against.
	refusalsSeen map[string]string

	pane    pane
	view    view
	overlay overlay
	// doctor is the doctor view's own state machine (D6): the run generation,
	// the cancel that belongs to it, and the last report, which outlives every
	// view switch until `R` replaces it.
	doctor doctorState
	// cursor is the switcher overlay's row, an index into daemonRows. It may
	// rest on a row that is not selectable — reading a skewed daemon's detail
	// is the point of that row existing.
	cursor int
	scroll scrollState
	// syncExpanded unfolds the sync table's ephemeral rows (`x`). One flag for
	// the view, not one per daemon: it is a way of looking, and carrying it
	// across a `tab` is what the user means by pressing the key.
	syncExpanded bool
}

func newModel(opts Options) Model {
	m := Model{
		opts:         opts,
		keys:         defaultKeys(),
		version:      opts.CLIVersion,
		missedTicks:  map[string]int{},
		refusals:     map[string][]introspect.Refusal{},
		refusalsSeen: map[string]string{},
		now:          time.Now(),
		// The constructor's Init fires a fetch alongside the first tick, so
		// the guard starts closed: the 1 Hz tick must not race it.
		fetching:   true,
		userRunDir: userRunDirDisplay(),
	}
	if m.version == "" {
		m.version = buildinfo.Version
	}
	if opts.VM != "" {
		// A ref that does not parse is not fatal here: the flag layer already
		// rejected it, and a TUI that refuses to start over a selection hint
		// would be worse than one that shows every daemon.
		if ref, err := vmprovider.ParseRef(opts.VM); err == nil {
			m.pinProvider, m.pinInstance = ref.Provider, ref.Instance
		}
	}
	return m
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), fetchCmd)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	case tickMsg:
		m.now = time.Time(msg)
		cmds := []tea.Cmd{tickCmd()}
		// D4: one fetch path, and a tick whose predecessor has not returned
		// drops its refresh rather than queueing another.
		if m.wantFetch() {
			m.fetching = true
			cmds = append(cmds, fetchCmd)
		}
		return m, tea.Batch(cmds...)
	case snapshotsMsg:
		return m.applySnapshots(msg), nil
	case doctorDoneMsg:
		return m.applyDoctorDone(msg), nil
	case doctorFailedMsg:
		return m.applyDoctorFailed(msg), nil
	case doctorTickMsg:
		return m.tickDoctor(msg)
	}
	return m, nil
}

// wantFetch is D4's in-flight guard, split out so the tick arm's decision is
// testable without inspecting an opaque tea.Batch.
func (m Model) wantFetch() bool { return !m.fetching }

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := m.keys
	// Quit and help answer in every view; the switcher overlay redefines the
	// rest of the map (§4.1's switcher table) and takes them first.
	switch {
	case k.Quit.matches(msg):
		return m, tea.Quit
	case k.Help.matches(msg):
		if m.overlay == overlayHelp {
			m.overlay = overlayNone
		} else {
			m.overlay = overlayHelp
		}
		return m, nil
	}
	if m.overlay == overlaySwitcher {
		return m.handleSwitcherKey(msg), nil
	}
	// The doctor view's own table answers first; what it does not claim falls
	// through to the global map below, which is what keeps `tab`, `1`–`9`, `v`
	// and `r` working from inside the view (§4.1's global table is global).
	if m.view == viewDoctor {
		if next, cmd, handled := m.handleDoctorKey(msg); handled {
			return next, cmd
		}
	}
	switch {
	case k.Esc.matches(msg):
		// One step out of whatever is layered on the dashboard: the topmost
		// overlay first, then the refusals pane. On the *plain* dashboard esc
		// still does nothing — an escape that quits is how people lose a
		// session they meant to keep.
		switch {
		case m.overlay != overlayNone:
			m.overlay = overlayNone
		case m.pane == paneRefusals:
			m.pane = paneNone
			m.scroll = m.freshScroll()
		}
		return m, nil
	case k.NextDaemon.matches(msg):
		return m.step(1), nil
	case k.PrevDaemon.matches(msg):
		return m.step(-1), nil
	case k.SelectDaemon.matches(msg):
		m, _ = m.selectNth(numberKey(msg))
		return m, nil
	case k.Switcher.matches(msg):
		m.overlay = overlaySwitcher
		m.cursor = m.rowIndexOf(m.selected)
		return m, nil
	case k.Doctor.matches(msg):
		next, cmd := m.openDoctor()
		return next, cmd
	case k.Refusals.matches(msg):
		if m.pane == paneRefusals {
			m.pane = paneNone
		} else {
			m.pane = paneRefusals
		}
		// The scroll region changed under the keys; the new one starts where
		// its own kind starts (the pane at the newest line, a table at its
		// top) rather than at the offset the old one left behind.
		m.scroll = m.freshScroll()
		return m.markRefusalsSeen(), nil
	case k.SyncExpand.matches(msg):
		// Dashboard only: the fold it toggles exists nowhere else, and a key
		// that silently changed a screen the user is not looking at would
		// surprise them on the way back.
		if m.view == viewDashboard {
			m.syncExpanded = !m.syncExpanded
		}
		return m, nil
	case k.LineDown.matches(msg):
		m.scroll = m.scroll.down(1, m.scrollTotal(), m.scrollVisible())
		return m, nil
	case k.LineUp.matches(msg):
		m.scroll = m.scroll.up(1, m.scrollTotal(), m.scrollVisible())
		return m, nil
	case k.PageDown.matches(msg):
		m.scroll = m.scroll.down(m.scrollVisible(), m.scrollTotal(), m.scrollVisible())
		return m, nil
	case k.PageUp.matches(msg):
		m.scroll = m.scroll.up(m.scrollVisible(), m.scrollTotal(), m.scrollVisible())
		return m, nil
	case k.Top.matches(msg):
		m.scroll = m.scroll.top()
		return m, nil
	case k.Bottom.matches(msg):
		m.scroll = m.scroll.bottom(m.scrollTotal(), m.scrollVisible())
		return m, nil
	}
	return m, nil
}

// handleSwitcherKey is §4.1's switcher table. Movement is a cursor, not a
// selection: the overlay is for reading the list, and only enter (or a number,
// or tab) changes which daemon the dashboard is showing.
func (m Model) handleSwitcherKey(msg tea.KeyMsg) Model {
	k := m.keys
	rows := m.daemonRows()
	switch {
	case k.SwitcherClose.matches(msg):
		m.overlay = overlayNone
	case k.SwitcherSelect.matches(msg):
		// A skewed or unreadable row has no daemon to become the active one;
		// enter on it does nothing rather than closing the overlay on a
		// selection that did not happen.
		if i := m.cursorIndex(rows); i >= 0 && rows[i].selectable() {
			m = m.selectPath(rows[i].snap.Path)
			m.overlay = overlayNone
		}
	case k.SwitcherMove.matches(msg):
		if s := msg.String(); s == "j" || s == "down" {
			m = m.moveCursor(1)
		} else {
			m = m.moveCursor(-1)
		}
	case k.PageDown.matches(msg), k.Bottom.matches(msg):
		m = m.moveCursor(len(rows))
	case k.PageUp.matches(msg), k.Top.matches(msg):
		m = m.moveCursor(-len(rows))
	case k.NextDaemon.matches(msg):
		m = m.step(1)
	case k.PrevDaemon.matches(msg):
		m = m.step(-1)
	case k.SelectDaemon.matches(msg):
		if next, ok := m.selectNth(numberKey(msg)); ok {
			m, m.overlay = next, overlayNone
		}
	}
	return m
}

// numberKey is the 1-9 arm's index, 0-based.
func numberKey(msg tea.KeyMsg) int { return int(msg.String()[0]-'0') - 1 }

// step moves the selection by n daemons, wrapping, over the same ordered list
// the switcher shows — skipping the rows that are not a daemon this build can
// render. Any deliberate selection also retires the -vm pin: the flag chooses
// the first view, not every one.
func (m Model) step(n int) Model {
	rows := m.selectableRows()
	if len(rows) == 0 {
		return m
	}
	i := 0
	for j, r := range rows {
		if r.snap.Path == m.selected {
			i = (j + n + len(rows)) % len(rows)
			break
		}
	}
	return m.selectPath(rows[i].snap.Path)
}

// selectNth is the 1-9 jump, over the same order and the same skips.
func (m Model) selectNth(i int) (Model, bool) {
	rows := m.selectableRows()
	if i < 0 || i >= len(rows) {
		return m, false
	}
	return m.selectPath(rows[i].snap.Path), true
}

func (m Model) selectPath(path string) Model {
	m.pinned = true
	m.selected = path
	m.scroll = m.freshScroll()
	m.cursor = m.rowIndexOf(path)
	// With the pane open the new daemon's log is on screen the moment the
	// selection lands, so it counts as shown.
	return m.markRefusalsSeen()
}

func (m Model) selectedIndex() int {
	for i, s := range m.snaps {
		if s.Path == m.selected {
			return i
		}
	}
	return -1
}

func (m Model) selectedSnap() *introspect.Snapshot {
	if i := m.selectedIndex(); i >= 0 {
		return m.snaps[i]
	}
	return nil
}

// applySnapshots folds one fetch into the model: fresh snapshots replace their
// path's last-known, absent paths accrue a missed tick until D7 retires them,
// and the selection stays pinned to its path throughout.
func (m Model) applySnapshots(msg snapshotsMsg) Model {
	m.fetching = false
	m.fetchedAt = msg.at
	m.now = msg.at
	m.problems = msg.problems

	fresh := map[string]*introspect.Snapshot{}
	m.skewed = nil
	for _, s := range msg.snaps {
		if s == nil {
			continue
		}
		if !s.Usable {
			m.skewed = append(m.skewed, s)
			continue
		}
		fresh[s.Path] = s
	}

	missed := map[string]int{}
	var kept []*introspect.Snapshot
	for _, s := range m.snaps {
		if f, ok := fresh[s.Path]; ok {
			kept = append(kept, f)
			delete(fresh, s.Path)
			continue
		}
		n := m.missedTicks[s.Path] + 1
		if n > maxMissedTicks {
			continue
		}
		missed[s.Path] = n
		kept = append(kept, s)
	}
	for _, s := range fresh {
		kept = append(kept, s)
	}
	sortSnaps(kept)
	m.snaps = kept
	m.missedTicks = missed
	m.refusals = m.mergeRefusals(kept, msg.snaps)
	m.refusalsSeen = m.pruneSeen()

	// An open pane is showing whatever this fetch just added, so the counter
	// must not start climbing under a pane the user is reading.
	return m.resolveSelection().markRefusalsSeen()
}

// mergeRefusals folds every answering daemon's ring into its path's log (D5) —
// every path, not just the selected one, so switching daemons shows what that
// daemon refused while the user was looking elsewhere. A path D7 has retired
// takes its log with it; a fresh map keeps one Update's logs from aliasing
// another's.
func (m Model) mergeRefusals(kept, fresh []*introspect.Snapshot) map[string][]introspect.Refusal {
	out := make(map[string][]introspect.Refusal, len(kept))
	for _, s := range kept {
		if log := m.refusals[s.Path]; len(log) > 0 {
			out[s.Path] = log
		}
	}
	for _, s := range fresh {
		if s == nil || !s.Usable {
			continue
		}
		if log := accumulate(out[s.Path], s.State.RecentRefusals); len(log) > 0 {
			out[s.Path] = log
		}
	}
	return out
}

// resolveSelection keeps D7's promise: selection is a path, never an index, so
// a socket appearing or vanishing cannot silently move the view. It only
// changes when the selected path is gone entirely.
func (m Model) resolveSelection() Model {
	if !m.pinned && m.pinProvider != "" {
		for _, s := range m.snaps {
			if matchesVM(s, m.pinProvider, m.pinInstance, m.opts.VM) {
				m.selected = s.Path
				m.pinned = true
				return m
			}
		}
	}
	if m.selectedIndex() >= 0 {
		return m
	}
	m.selected = ""
	if len(m.snaps) > 0 {
		m.selected = m.snaps[0].Path
	}
	return m
}

func matchesVM(s *introspect.Snapshot, provider, instance, spec string) bool {
	vm := s.State.VM
	if vm.Provider != "" && vm.Instance != "" {
		return vm.Provider == provider && vm.Instance == instance
	}
	return vm.Ref == spec
}

// sortSnaps reproduces Discover's order — the root socket first, then the user
// dir lexicographically — for the merged list, so a retained absent path holds
// the position it had while answering.
func sortSnaps(snaps []*introspect.Snapshot) {
	sort.SliceStable(snaps, func(i, j int) bool {
		a, b := snaps[i].Path, snaps[j].Path
		if a == introspect.RootSocketPath {
			return b != introspect.RootSocketPath
		}
		if b == introspect.RootSocketPath {
			return false
		}
		return a < b
	})
}

// stale reports whether the selected daemon has stopped answering (§3.5): the
// view stays on it and renders the last-known summary under a message.
func (m Model) stale(s *introspect.Snapshot) bool {
	return s != nil && m.missedTicks[s.Path] > 0
}

func (m Model) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}
	if m.width < minWidth || m.height < minHeight {
		return tooSmallView(m.width, m.height)
	}
	switch m.overlay {
	case overlayHelp:
		return m.helpView()
	case overlaySwitcher:
		return m.switcherView()
	}
	if m.view == viewDoctor {
		return m.doctorView()
	}
	return m.dashboardView()
}
