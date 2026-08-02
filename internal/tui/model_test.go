package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	tea "github.com/charmbracelet/bubbletea"
)

func key(s string) tea.KeyMsg {
	switch s {
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "ctrl+c":
		return tea.KeyMsg{Type: tea.KeyCtrlC}
	case " ":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func send(m Model, msgs ...tea.Msg) (Model, tea.Cmd) {
	var cmd tea.Cmd
	for _, msg := range msgs {
		var next tea.Model
		next, cmd = m.Update(msg)
		m = next.(Model)
	}
	return m, cmd
}

func press(m Model, keys ...string) Model {
	for _, k := range keys {
		m, _ = send(m, key(k))
	}
	return m
}

// D4: every tick runs one FetchAll, and a tick whose predecessor has not
// returned drops its refresh rather than queueing another.
func TestTickFetchGuard(t *testing.T) {
	m := testModel(120, 40)
	m.fetching = false
	if !m.wantFetch() {
		t.Fatal("an idle model does not want a fetch")
	}
	m, cmd := send(m, tickMsg(fixtureNow))
	if !m.fetching {
		t.Fatal("tick did not start a fetch")
	}
	if cmd == nil {
		t.Fatal("tick returned no command — the loop would stop")
	}
	if m.wantFetch() {
		t.Fatal("an in-flight model still wants a fetch")
	}
	// A second tick with the first fetch outstanding must not start another.
	m2, _ := send(m, tickMsg(fixtureNow.Add(time.Second)))
	if m2.wantFetch() {
		t.Fatal("the in-flight guard released early")
	}
	// The result reopens the guard.
	m3, _ := send(m2, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap()}, at: fixtureNow})
	if !m3.wantFetch() {
		t.Fatal("a returned fetch left the guard closed")
	}
}

// D7: selection is a socket path, so a socket appearing or vanishing never
// silently changes which daemon the user is looking at.
func TestSelectionIsPinnedToPath(t *testing.T) {
	m := testModel(120, 40)
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap()}, at: fixtureNow})
	if m.selected != userSock {
		t.Fatalf("selected = %q, want the only answering socket", m.selected)
	}

	// The root socket appears and sorts ahead of the user one. Selection must
	// not follow the reordering.
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap(), rootSnap()}, at: fixtureNow})
	if m.selected != userSock {
		t.Fatalf("a new socket moved the selection to %q", m.selected)
	}
	if m.snaps[0].Path != rootSock {
		t.Fatalf("Discover order lost: %q first", m.snaps[0].Path)
	}

	// The selected socket stops answering: the view stays on it, rendering the
	// stopped state, with the other still one tab away.
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{rootSnap()}, at: fixtureNow})
	if m.selected != userSock {
		t.Fatalf("a dying daemon yanked the view to %q", m.selected)
	}
	if !m.stale(m.selectedSnap()) {
		t.Fatal("the absent daemon does not read as stale")
	}
	if !strings.Contains(m.View(), "stopped answering") {
		t.Fatal("the stopped-answering state is not rendered")
	}

	// After maxMissedTicks it leaves the list and selection falls to the first
	// answering socket.
	for i := 0; i < maxMissedTicks; i++ {
		m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{rootSnap()}, at: fixtureNow})
	}
	if m.selected != rootSock || len(m.snaps) != 1 {
		t.Fatalf("after %d missed ticks: selected %q, %d daemons", maxMissedTicks, m.selected, len(m.snaps))
	}
}

func TestTabAndNumberSelection(t *testing.T) {
	m := testModel(120, 40, healthySnap(), rootSnap())
	if m.selected != rootSock {
		t.Fatalf("first daemon is %q, want the root socket (Discover order)", m.selected)
	}
	if got := press(m, "tab").selected; got != userSock {
		t.Fatalf("tab selected %q", got)
	}
	if got := press(m, "tab", "tab").selected; got != rootSock {
		t.Fatalf("tab wrapped to %q", got)
	}
	if got := press(m, "shift+tab").selected; got != userSock {
		t.Fatalf("shift+tab selected %q", got)
	}
	if got := press(m, "tab", "1").selected; got != rootSock {
		t.Fatalf("1 selected %q", got)
	}
	if got := press(m, "2").selected; got != userSock {
		t.Fatalf("2 selected %q", got)
	}
	// Out of range is a no-op, not a panic and not a wrap.
	if got := press(m, "9").selected; got != rootSock {
		t.Fatalf("9 with two daemons selected %q", got)
	}
	// Selecting by hand retires the -vm pin so a later fetch cannot re-seat it.
	if !press(m, "tab").pinned {
		t.Fatal("tab did not retire the -vm pin")
	}
}

// `h`/`l` and the left/right arrows are aliases of shift+tab/tab, in every
// view where tab already cycles daemons — including the overlays that redefine
// j/k for their own cursors.
func TestDaemonCyclingAliases(t *testing.T) {
	base := testModel(120, 40, healthySnap(), rootSnap())
	views := map[string]Model{
		"dashboard": base,
		"doctor":    press(base, "d"),
		"switcher":  openSwitcher(base),
		"refusals":  press(base, "r"),
	}
	for name, m := range views {
		if m.selected != rootSock {
			t.Fatalf("%s: fixture starts on %q", name, m.selected)
		}
		for _, k := range []string{"tab", "l", "right"} {
			if got := press(m, k).selected; got != userSock {
				t.Errorf("%s: %q selected %q, want the next daemon", name, k, got)
			}
		}
		for _, k := range []string{"shift+tab", "h", "left"} {
			if got := press(m, k).selected; got != userSock {
				t.Errorf("%s: %q selected %q, want the previous daemon", name, k, got)
			}
		}
		// The aliases move the selection and nothing else: the view they were
		// pressed in is still the view.
		if got := press(m, "l"); got.view != m.view || got.overlay != m.overlay {
			t.Errorf("%s: l changed the view (%v/%v)", name, got.view, got.overlay)
		}
	}
	// j/k keep meaning what each view says they mean — the aliases are extra
	// keys, not a reassignment.
	if got := press(openSwitcher(base), "j").selected; got != rootSock {
		t.Errorf("j in the switcher moved the selection to %q", got)
	}
}

// The footer counts what the refusals pane has not shown yet, per daemon, and
// opening the pane clears it.
func TestUnseenRefusalCounter(t *testing.T) {
	m := testModel(120, 40, healthySnap(), devSnap())
	if got := m.unseenRefusals(userSock); got != 0 {
		t.Fatalf("a fresh model counts %d unseen", got)
	}
	ring := refusalRing()
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{withRefusals(healthySnap(), ring), devSnap()}, at: fixtureNow})
	if got := m.unseenRefusals(userSock); got != len(ring) {
		t.Fatalf("counted %d unseen after a fetch carrying %d", got, len(ring))
	}
	if !strings.Contains(m.View(), "r refusals (3)") {
		t.Fatalf("the footer does not carry the counter:\n%s", m.View())
	}
	// Opening the pane marks the whole log seen; closing it does not undo that.
	open := press(m, "r")
	if got := open.unseenRefusals(userSock); got != 0 {
		t.Fatalf("opening the pane left %d unseen", got)
	}
	if got := press(open, "r"); got.unseenRefusals(userSock) != 0 {
		t.Fatal("closing the pane resurrected the counter")
	}
	// A refusal arriving under an open pane is seen as it lands.
	grown := append(append([]introspect.Refusal(nil), ring...),
		introspect.Refusal{At: fixtureNow, ID: introspect.IDMirrorSkip, Line: "guest tcp :23 not mirrored (skip list)"})
	live, _ := send(open, snapshotsMsg{snaps: []*introspect.Snapshot{withRefusals(healthySnap(), grown), devSnap()}, at: fixtureNow})
	if got := live.unseenRefusals(userSock); got != 0 {
		t.Fatalf("an open pane let the counter climb to %d", got)
	}
	// The same refusal arriving with the pane closed does count.
	closed, _ := send(press(open, "r"), snapshotsMsg{snaps: []*introspect.Snapshot{withRefusals(healthySnap(), grown), devSnap()}, at: fixtureNow})
	if got := closed.unseenRefusals(userSock); got != 1 {
		t.Fatalf("counted %d unseen after one new refusal", got)
	}
	// The count is per daemon: reading one daemon's pane says nothing about
	// what another has refused.
	two, _ := send(m, snapshotsMsg{snaps: []*introspect.Snapshot{
		withRefusals(healthySnap(), ring), withRefusals(devSnap(), ring)}, at: fixtureNow})
	two = press(two, "r") // opens on the selected (user) daemon
	if got := two.unseenRefusals(devSock); got != len(ring) {
		t.Fatalf("one daemon's pane cleared another's counter (%d unseen)", got)
	}
	// Watching the other daemon with the pane open clears that one instead.
	if got := press(two, "tab").unseenRefusals(devSock); got != 0 {
		t.Fatalf("tabbing onto a daemon with the pane open left %d unseen", got)
	}
}

func withRefusals(s *introspect.Snapshot, log []introspect.Refusal) *introspect.Snapshot {
	s.State.RecentRefusals = log
	return s
}

// -vm pre-selects by canonical ref (§4.3), which is why `colima:default` and
// the instance it maps to select the same daemon.
func TestVMPinPreselects(t *testing.T) {
	m := newModel(Options{VM: "lima:dev", CLIVersion: "v0.1.0"})
	m.width, m.height = 120, 40
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap(), rootSnap()}, at: fixtureNow})
	if m.selected != rootSock {
		t.Fatalf("-vm lima:dev selected %q", m.selected)
	}
	// Once applied, a later fetch must not drag the selection back.
	m = press(m, "tab")
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap(), rootSnap()}, at: fixtureNow})
	if m.selected != userSock {
		t.Fatalf("the pin re-seated the selection to %q after a manual tab", m.selected)
	}
}

// A schema-skewed daemon never becomes the active one — its frozen two fields
// cannot fill a dashboard — but §3.5's card names it, and §3.4 gives it a row
// the cursor can rest on.
func TestSkewedSnapshotsAreNotSelectable(t *testing.T) {
	m := testModel(120, 40)
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{skewedSnap(rootSock), healthySnap()}, at: fixtureNow})
	if len(m.snaps) != 1 || m.selected != userSock {
		t.Fatalf("skewed snapshot reached the daemon list: %d snaps, selected %q", len(m.snaps), m.selected)
	}
	v := m.View()
	for _, want := range []string{"schema skew", rootSock, "v0.2.0"} {
		if !strings.Contains(v, want) {
			t.Fatalf("the skew card is missing %q:\n%s", want, v)
		}
	}
	// The card's sentence may wrap, so the wording is asserted on the joined
	// body rather than on one rendered row.
	if body := strings.Join(m.skewCard(m.layout(), m.skewed[0]), " "); !strings.Contains(body, "speaks introspection schema 2; this build knows 1") {
		t.Fatalf("the skew card does not carry the §3.5 wording: %s", body)
	}
}

// With nothing answering the screen is the calm pre-start card, not an error.
func TestNoDaemonState(t *testing.T) {
	m := testModel(120, 40)
	m, _ = send(m, snapshotsMsg{at: fixtureNow})
	v := m.View()
	for _, want := range []string{
		"no drawbridge daemon is answering",
		introspect.RootSocketPath,
		"drawbridged",
		"sudo drawbridge install",
		"heals itself",
		shortHelpFull,
	} {
		if !strings.Contains(v, want) {
			t.Fatalf("the no-daemon card is missing %q:\n%s", want, v)
		}
	}
}

func TestHelpToggleAndEsc(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	if m.overlay != overlayNone {
		t.Fatal("the dashboard did not start bare")
	}
	m = press(m, "?")
	if m.overlay != overlayHelp {
		t.Fatal("? did not open the help overlay")
	}
	if !strings.Contains(m.View(), "Switcher overlay") {
		t.Fatal("the help overlay does not render the full map")
	}
	if got := press(m, "?"); got.overlay != overlayNone {
		t.Fatal("? did not close the help overlay")
	}
	if got := press(m, "esc"); got.overlay != overlayNone {
		t.Fatal("esc did not close the help overlay")
	}
}

// esc on a plain dashboard does nothing at all: an escape that quits is how
// people lose a session they meant to keep.
func TestEscOnPlainDashboardIsInert(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	got, cmd := send(m, key("esc"))
	if cmd != nil {
		t.Fatal("esc returned a command")
	}
	if got.View() != m.View() {
		t.Fatal("esc changed the plain dashboard")
	}
}

// esc steps out of one layer at a time: the overlay first, then the refusals
// pane, and nothing at all once the dashboard is plain. The doctor view claims
// esc before any of this, which is what keeps its cancel/back two-step intact.
func TestEscClosesTheRefusalsPane(t *testing.T) {
	m := refusalsModel(120, 40)
	if got := press(m, "esc"); got.pane != paneNone {
		t.Fatal("esc left the refusals pane open")
	}
	if got := press(m, "esc", "esc"); got.pane != paneNone || got.overlay != overlayNone {
		t.Fatalf("a second esc changed something: pane %v overlay %v", got.pane, got.overlay)
	}
	// With an overlay up, the first esc spends itself on the overlay.
	if got := press(helpModel(m), "esc"); got.overlay != overlayNone || got.pane != paneRefusals {
		t.Fatalf("esc closed the pane out from under the overlay: pane %v overlay %v", got.pane, got.overlay)
	}
	// Closing the pane hands the scroll keys back to the table, at its top.
	if got := press(manyRefusalsModel(120, 40), "k", "esc"); got.scroll != (scrollState{}) {
		t.Fatalf("esc left the pane's scroll state behind: %+v", got.scroll)
	}
	// The doctor view answers esc first: its two-step is untouched, and the
	// step that leaves the view leaves the pane exactly as it found it.
	doc := press(m, "d")
	if doc.view != viewDoctor {
		t.Fatal("d did not open the doctor view")
	}
	if got := press(doc, "esc"); got.view != viewDoctor || got.pane != paneRefusals {
		t.Fatalf("the doctor view's cancel esc: view %v, pane %v", got.view, got.pane)
	}
	if got := press(doc, "esc", "esc"); got.view != viewDashboard || got.pane != paneRefusals {
		t.Fatalf("the doctor view's back esc: view %v, pane %v", got.view, got.pane)
	}
}

// `x` folds and unfolds the sync table's ephemeral rows, and only from the
// dashboard — the doctor view has no such table to change.
func TestSyncExpandToggle(t *testing.T) {
	m := testModel(120, 40, ephemeralSnap())
	if !strings.Contains(m.View(), "·6 ephemeral (49410–56206)") {
		t.Fatalf("the ephemeral run did not fold:\n%s", m.View())
	}
	if strings.Contains(m.View(), "51002") {
		t.Fatal("a folded row still lists its ports")
	}
	// Below the threshold nothing folds: udp advertises two.
	for _, want := range []string{"49999", "50001"} {
		if !strings.Contains(m.View(), want) {
			t.Fatalf("two ephemeral rows were folded away (%s)", want)
		}
	}
	one := press(m, "x")
	if !one.syncExpanded || !strings.Contains(one.View(), "51002") {
		t.Fatalf("x did not expand the fold:\n%s", one.View())
	}
	if strings.Contains(one.View(), "ephemeral") {
		t.Fatal("an expanded table still carries the fold row")
	}
	if got := press(one, "x"); got.syncExpanded {
		t.Fatal("x did not fold back")
	}
	// The header counts the advertised set, folded or not.
	for _, v := range []Model{m, one} {
		if !strings.Contains(v.View(), "SYNC — Mac ports advertised to guest (11)") {
			t.Fatalf("the fold moved the header's count:\n%s", v.View())
		}
	}
	if got := press(press(m, "d"), "x"); got.syncExpanded {
		t.Fatal("x changed the fold from inside the doctor view")
	}
}

func TestQuitKeys(t *testing.T) {
	for _, k := range []string{"q", "ctrl+c"} {
		_, cmd := send(testModel(120, 40, healthySnap()), key(k))
		if cmd == nil {
			t.Fatalf("%s returned no command", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Fatalf("%s did not quit", k)
		}
	}
}

// All layout derives from the last WindowSizeMsg, so every transition is a
// resize away and no state carries across it.
func TestResizeTransitions(t *testing.T) {
	base := testModel(120, 40, healthySnap())
	for _, tc := range []struct {
		w, h int
		want []string
		skip []string
	}{
		{120, 40, []string{"┌ colima:colima", "SYNC — Mac ports advertised"}, nil},
		{100, 40, []string{"┌ colima:colima", "SYNC — Mac ports advertised"}, nil},
		{99, 40, []string{"adv 3 · parked 4"}, []string{"SYNC — Mac ports advertised", "┌ colima:colima"}},
		// The secret path is gone at every width now (§12): mode and state
		// carry the signal, and the path was machinery.
		{70, 24, []string{"SINCE", "auth static-hmac-v1 ok"}, []string{"/Users/x/Library"}},
		{69, 24, []string{"auth static-hmac-v1 ok"}, []string{"SINCE", "/Users/x/Library"}},
		{43, 40, []string{"window too small"}, []string{"MIRROR"}},
		{120, 11, []string{"window too small"}, []string{"MIRROR"}},
	} {
		m, _ := send(base, tea.WindowSizeMsg{Width: tc.w, Height: tc.h})
		v := m.View()
		for _, want := range tc.want {
			if !strings.Contains(v, want) {
				t.Errorf("%dx%d: missing %q:\n%s", tc.w, tc.h, want, v)
			}
		}
		for _, no := range tc.skip {
			if strings.Contains(v, no) {
				t.Errorf("%dx%d: still carries %q:\n%s", tc.w, tc.h, no, v)
			}
		}
	}
	// Resizing back restores the full view byte for byte.
	m, _ := send(base, tea.WindowSizeMsg{Width: 40, Height: 8}, tea.WindowSizeMsg{Width: 120, Height: 40})
	if m.View() != base.View() {
		t.Fatal("a round trip through the too-small card did not restore the view")
	}
}

// Scroll keys drive whichever single region is scrollable — in T1 an
// overflowing mirror table, and the help overlay when it is open.
func TestScrollKeysDriveTheOverflowingTable(t *testing.T) {
	m := testModel(120, 16, manyEntries())
	if !strings.Contains(m.View(), "… +13 more") {
		t.Fatal("an unscrolled overflow has no tail line")
	}
	m = press(m, "j", "j")
	if m.scroll.offset != 2 {
		t.Fatalf("j twice left offset %d", m.scroll.offset)
	}
	if strings.Contains(m.View(), "… +") {
		t.Fatal("a scrolled table still shows the unscrolled tail")
	}
	if got := press(m, "k", "k", "k").scroll.offset; got != 0 {
		t.Fatalf("k past the top left offset %d", got)
	}
	if got := press(m, "G").scroll; got.offset != maxOffset(20, m.scrollVisible()) || !got.follow {
		t.Fatalf("G left %+v", got)
	}
	if got := press(m, "G", "g").scroll; got.offset != 0 || got.follow {
		t.Fatalf("g left %+v", got)
	}
	fresh := testModel(120, 16, manyEntries())
	if got := press(fresh, " ").scroll.offset; got != fresh.scrollVisible() {
		t.Fatalf("space paged to %d, want %d", got, fresh.scrollVisible())
	}
	if got := press(m, "G", "b").scroll.offset; got == maxOffset(20, m.scrollVisible()) {
		t.Fatal("b did not page up")
	}
	// Changing daemon resets the region: the offset belonged to the old table.
	two := press(testModel(120, 16, manyEntries(), rootSnap()), "j", "j", "tab")
	if two.scroll.offset != 0 {
		t.Fatalf("tab kept a scroll offset of %d", two.scroll.offset)
	}
}

func TestScrollRegionClamps(t *testing.T) {
	s := scrollState{}
	if lo, hi := s.window(0, 5); lo != 0 || hi != 0 {
		t.Fatalf("empty region windowed to [%d,%d)", lo, hi)
	}
	if lo, hi := s.window(3, 5); lo != 0 || hi != 3 {
		t.Fatalf("under-full region windowed to [%d,%d)", lo, hi)
	}
	s = scrollState{offset: 99}
	if lo, hi := s.window(10, 4); lo != 6 || hi != 10 {
		t.Fatalf("a stale offset windowed to [%d,%d)", lo, hi)
	}
	if got := (scrollState{offset: 4, follow: true}).clamp(10, 4); got.offset != 6 {
		t.Fatalf("a following region clamped to %d, want the bottom", got.offset)
	}
	if got := (scrollState{offset: 4, follow: true}).up(1, 10, 4); got.follow {
		t.Fatal("moving up did not disengage follow")
	}
	// A following region moves from where it is drawn, not from its stored
	// offset: one `k` at the bottom of a followed log steps back one line, it
	// does not jump to the top.
	if got := (scrollState{follow: true}).up(1, 10, 4); got.offset != 5 {
		t.Fatalf("k at the bottom of a following region left offset %d, want 5", got.offset)
	}
	if got := (scrollState{follow: true}).down(1, 10, 4); got.offset != 6 {
		t.Fatalf("j at the bottom of a following region left offset %d", got.offset)
	}
}

// View is pure over the model: the same model renders the same bytes, which is
// the whole basis of the goldens.
func TestViewIsPure(t *testing.T) {
	m := testModel(120, 40, healthySnap(), devSnap())
	if m.View() != m.View() {
		t.Fatal("two renders of one model differ")
	}
	if testModel(120, 40, healthySnap(), devSnap()).View() != m.View() {
		t.Fatal("two identical models render differently")
	}
}

// An empty model must render rather than panic: bubbletea calls View before
// the first WindowSizeMsg and before the first fetch returns.
func TestZeroModelRenders(t *testing.T) {
	var m Model
	if got := m.View(); got != "" {
		t.Fatalf("a zero model rendered %q", got)
	}
	m = newModel(Options{})
	m.width, m.height = 120, 40
	if !strings.Contains(m.View(), "no drawbridge daemon is answering") {
		t.Fatal("a model with no fetch yet did not render the pre-start card")
	}
}
