package tui

import (
	"fmt"
	"strconv"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// The switcher overlay (docs/tui.md §3.4) and the D8 fighting-daemons banner.
//
// The row order the overlay renders is the same order `tab`/`shift+tab` and
// `1`–`9` walk — daemonRows is the only ordering in the package — so the
// number a user reads in the overlay is the number they can press.

type rowKind int

const (
	// rowDaemon is an answering daemon this build understands: the only kind
	// that can be the active daemon.
	rowDaemon rowKind = iota
	// rowSkewed speaks a schema this build does not know. Its frozen two
	// fields are all it is good for (doctor.md §3.3 D2), so that is all its
	// row claims.
	rowSkewed
	// rowUnreadable is a socket that answered with something that is not a
	// snapshot. FetchAll hands these back as errors and nothing else — the
	// path lives inside the error string, so the row prints that string
	// verbatim rather than parsing a path back out of it.
	rowUnreadable
)

type daemonRow struct {
	kind rowKind
	snap *introspect.Snapshot
	err  error
}

func (r daemonRow) selectable() bool { return r.kind == rowDaemon && r.snap != nil }

// switcherKeys is the overlay's own key line, inside the card.
const switcherKeys = "enter select · esc close"

// switcherNameW caps the identity column: a socket path stands in for a name
// when there is no usable payload, and one long path must not push the detail
// column off the card.
const switcherNameW = 34

// daemonRows is the one ordering: answering daemons in Discover order (root
// socket first, then the user dir sorted) with a fighting pair pulled
// adjacent, then schema-skewed sockets, then unreadable ones. Only the first
// group is selectable; the rest are here to be read.
func (m Model) daemonRows() []daemonRow {
	out := make([]daemonRow, 0, len(m.snaps)+len(m.skewed)+len(m.problems))
	for _, s := range m.orderedSnaps() {
		out = append(out, daemonRow{kind: rowDaemon, snap: s})
	}
	for _, s := range m.skewed {
		out = append(out, daemonRow{kind: rowSkewed, snap: s})
	}
	for _, p := range m.problems {
		out = append(out, daemonRow{kind: rowUnreadable, err: p})
	}
	return out
}

func (m Model) selectableRows() []daemonRow {
	rows := m.daemonRows()
	out := make([]daemonRow, 0, len(rows))
	for _, r := range rows {
		if r.selectable() {
			out = append(out, r)
		}
	}
	return out
}

// rowIndexOf locates a socket path among all rows, which is where the switcher
// cursor lands when the overlay opens.
func (m Model) rowIndexOf(path string) int {
	for i, r := range m.daemonRows() {
		if r.snap != nil && r.snap.Path == path {
			return i
		}
	}
	return 0
}

// daemonPos is the header's `daemon N/M`, counted over selectable rows in the
// switcher's order so the two agree.
func (m Model) daemonPos() (pos, total int) {
	for i, r := range m.selectableRows() {
		total++
		if r.snap.Path == m.selected {
			pos = i + 1
		}
	}
	return pos, total
}

// orderedSnaps is Discover order, except that a fighting pair's two combatants
// are made adjacent: §3.4 is the view that makes the pathology visible, and
// two rows describing the same VM belong side by side.
func (m Model) orderedSnaps() []*introspect.Snapshot {
	c := fightingPair(m.answering())
	if c == nil {
		return m.snaps
	}
	out := make([]*introspect.Snapshot, 0, len(m.snaps))
	for _, s := range m.snaps {
		if s == c.user {
			continue
		}
		out = append(out, s)
		if s == c.root {
			out = append(out, c.user)
		}
	}
	if len(out) != len(m.snaps) {
		return m.snaps
	}
	return out
}

// answering is the snapshots that answered this fetch. A path that stopped
// answering keeps its last-known snapshot in m.snaps for D7's grace window,
// and counting those as live is what would keep the D8 banner up after one of
// the two daemons died.
func (m Model) answering() []*introspect.Snapshot {
	out := make([]*introspect.Snapshot, 0, len(m.snaps))
	for _, s := range m.snaps {
		if m.missedTicks[s.Path] == 0 {
			out = append(out, s)
		}
	}
	return out
}

// combatants is one D8 pair: the same VM served by both flavors at once.
type combatants struct {
	vm   string
	root *introspect.Snapshot
	user *introspect.Snapshot
}

// fightingPair is D8's detection, pure over the answering snapshots: the same
// VM — canonical provider+instance, `ref` as fallback — named by one snapshot
// from RootSocketPath and one from the user run dir. The root socket is a
// singleton path, so there is at most one pair.
func fightingPair(answering []*introspect.Snapshot) *combatants {
	for _, r := range answering {
		if flavor(r.Path) != flavorRoot {
			continue
		}
		key := vmKey(r)
		if key == "" {
			continue
		}
		for _, u := range answering {
			if flavor(u.Path) == flavorRoot || vmKey(u) != key {
				continue
			}
			return &combatants{vm: vmName(r, key), root: r, user: u}
		}
	}
	return nil
}

// vmKey is the identity two snapshots are compared on: the canonical pair when
// the daemon reported one, the -vm spelling otherwise. Two daemons that name
// no VM at all are not evidence of anything, so an empty key never matches.
func vmKey(s *introspect.Snapshot) string {
	vm := s.State.VM
	if vm.Provider != "" && vm.Instance != "" {
		return vm.Provider + ":" + vm.Instance
	}
	return vm.Ref
}

func vmName(s *introspect.Snapshot, key string) string {
	if s.State.VM.Ref != "" {
		return s.State.VM.Ref
	}
	return key
}

// bannerLines is D8's banner: warn-styled, above every view including the
// switcher overlay, naming both PIDs and the consequence, and gone the moment
// one of the two stops answering. It is the one element progressive disclosure
// never hides.
func (m Model) bannerLines(lo layout) []string {
	c := fightingPair(m.answering())
	if c == nil {
		return nil
	}
	w := lo.contentWidth() - 3
	return []string{" " + styleWarn.Render(truncEnd("! "+oneLine(bannerText(c, w-2)), w))}
}

func bannerText(c *combatants, width int) string {
	for _, s := range []string{
		fmt.Sprintf("two daemons serve %s — root pid %d and user pid %d — whichever binds a mirror port first wins it and the other reports bind-failed; stop one",
			c.vm, c.root.State.PID, c.user.State.PID),
		fmt.Sprintf("two daemons serve %s — root pid %d and user pid %d fight over mirror ports; stop one",
			c.vm, c.root.State.PID, c.user.State.PID),
		fmt.Sprintf("%s: root pid %d and user pid %d fight over mirror ports",
			c.vm, c.root.State.PID, c.user.State.PID),
	} {
		if visWidth(s) <= width {
			return s
		}
	}
	return fmt.Sprintf("%s: pids %d and %d fight over mirror ports", c.vm, c.root.State.PID, c.user.State.PID)
}

func (m Model) switcherView() string {
	lo := m.layout()
	body := append(m.chromeLines(lo), "")
	body = append(body, indentAll(titledCard("daemons", m.switcherBody(), lo.contentWidth()-1), 1)...)
	return m.frame(body, lo)
}

// switcherBody is §3.4's list: every discovered socket, one row each, with the
// cursor marker, the press-this number of the selectable ones, and a detail
// column that says only what that row's kind actually knows.
func (m Model) switcherBody() []string {
	rows := m.daemonRows()
	if len(rows) == 0 {
		return []string{styleDim.Render("(no introspection socket answered)"), switcherKeys}
	}
	cur := m.cursorIndex(rows)

	nameW, pidW, verW := 0, 0, 0
	for _, r := range rows {
		nameW = max(nameW, visWidth(rowName(r)))
		if r.kind == rowDaemon {
			pidW = max(pidW, visWidth(pidText(r.snap)))
			verW = max(verW, visWidth(orUnknown(r.snap.State.Version)))
		}
	}

	out := make([]string, 0, len(rows)+1)
	n := 0
	for i, r := range rows {
		marker, num := "  ", "   "
		if i == cur {
			marker = "▸ "
		}
		// Numbers belong to the rows `1`–`9` can actually select; a number on
		// a row that answers nothing is an invitation to press a dead key.
		if r.selectable() {
			if n++; n <= 9 {
				num = strconv.Itoa(n) + "  "
			}
		}
		out = append(out, marker+num+padRight(rowName(r), nameW+2)+m.rowDetail(r, pidW, verW))
	}
	return append(out, switcherKeys)
}

// rowName is the identity column: the daemon's own VM ref when there is a
// usable payload, the socket name's provider-instance hint when there is not,
// and the label itself when the socket answered with nothing readable.
func rowName(r daemonRow) string {
	switch r.kind {
	case rowDaemon:
		return truncEnd(orDash(r.snap.State.VM.Ref), switcherNameW)
	case rowSkewed:
		if p, i, ok := introspect.VMFromSocketPath(r.snap.Path); ok {
			return truncEnd(p+":"+i, switcherNameW)
		}
		return truncMiddle(r.snap.Path, switcherNameW)
	default:
		return "[unreadable]"
	}
}

func (m Model) rowDetail(r daemonRow, pidW, verW int) string {
	switch r.kind {
	case rowDaemon:
		st := r.snap.State
		out := padRight(flavor(r.snap.Path), 6) + padRight(pidText(r.snap), pidW+2) +
			padRight(orUnknown(st.Version), verW+2) + fmt.Sprintf("%d mirrors", len(st.Mirror.Entries))
		if m.stale(r.snap) {
			out += " · " + styleWarn.Render("stopped answering")
		}
		return out
	case rowSkewed:
		return padRight("—", 6) + styleWarn.Render(fmt.Sprintf("schema %d (daemon %s)",
			r.snap.State.Schema, orUnknown(r.snap.State.Version)))
	default:
		return padRight("—", 6) + styleWarn.Render(oneLine(r.err.Error()))
	}
}

func pidText(s *introspect.Snapshot) string { return fmt.Sprintf("pid %d", s.State.PID) }

// cursorIndex clamps the stored cursor to the rows that exist right now. Rows
// appear and vanish between renders, and View is pure — it clamps rather than
// corrects the model.
func (m Model) cursorIndex(rows []daemonRow) int {
	switch {
	case len(rows) == 0:
		return -1
	case m.cursor < 0:
		return 0
	case m.cursor >= len(rows):
		return len(rows) - 1
	}
	return m.cursor
}

func (m Model) moveCursor(n int) Model {
	rows := m.daemonRows()
	i := m.cursorIndex(rows) + n
	m.cursor = min(max(i, 0), max(len(rows)-1, 0))
	return m
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return oneLine(s)
}
