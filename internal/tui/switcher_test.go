package tui

import (
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

func rowKinds(rows []daemonRow) string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		switch r.kind {
		case rowDaemon:
			out = append(out, "daemon:"+r.snap.Path)
		case rowSkewed:
			out = append(out, "skewed:"+r.snap.Path)
		default:
			out = append(out, "unreadable")
		}
	}
	return strings.Join(out, " ")
}

// One ordering serves both the overlay and the cycling keys: answering daemons
// in Discover order first, then the sockets that answered with something this
// build cannot use.
func TestDaemonRowOrder(t *testing.T) {
	m := switcherModel(120, 40)
	want := "daemon:" + rootSock + " daemon:" + userSock + " skewed:" + scratchSock + " unreadable"
	if got := rowKinds(m.daemonRows()); got != want {
		t.Fatalf("row order:\n got %s\nwant %s", got, want)
	}
	if got := len(m.selectableRows()); got != 2 {
		t.Fatalf("%d selectable rows, want the two answering daemons", got)
	}
}

// Cycling and the number keys walk the selectable rows only: a schema-skewed
// or unreadable socket has no daemon to make active, and a tab that landed on
// one would render a dashboard with nothing in it.
func TestCyclingSkipsNonSelectableRows(t *testing.T) {
	m := switcherModel(120, 40)
	m.overlay = overlayNone
	if m.selected != rootSock {
		t.Fatalf("the first daemon is %q", m.selected)
	}
	if got := press(m, "tab").selected; got != userSock {
		t.Fatalf("tab selected %q", got)
	}
	// Two selectable rows: tab twice wraps rather than landing on the skewed
	// socket at row three.
	if got := press(m, "tab", "tab").selected; got != rootSock {
		t.Fatalf("tab twice selected %q", got)
	}
	if got := press(m, "3").selected; got != rootSock {
		t.Fatalf("3 — the skewed socket's row — selected %q", got)
	}
	if _, ok := m.selectNth(2); ok {
		t.Fatal("selectNth reached past the selectable rows")
	}
	// The header counts the same rows the numbers do.
	if !strings.Contains(m.View(), "daemon 1/2") {
		t.Fatalf("the header counts rows the numbers cannot reach:\n%s", m.View())
	}
}

// §3.4: every discovered socket appears, and each row claims only what its
// kind actually knows.
func TestSwitcherOverlayListsEverySocket(t *testing.T) {
	v := switcherModel(120, 40).View()
	for _, want := range []string{
		"colima:colima", "lima:dev",
		"user", "root", "pid 71234", "pid 4242", "5 mirrors",
		"lima:scratch", "schema 2 (daemon v0.2.0)",
		"[unreadable]", "/tmp/introspect-bad.sock",
		switcherKeys,
	} {
		if !strings.Contains(v, want) {
			t.Errorf("the switcher overlay is missing %q:\n%s", want, v)
		}
	}
}

// A daemon D7 is still holding on to has stopped answering, and the row that
// offers it says so — the list must not read as four live daemons when one of
// them is a corpse.
func TestSwitcherMarksStoppedDaemons(t *testing.T) {
	m := openSwitcher(stoppedModel(120, 40))
	if !strings.Contains(m.View(), "stopped answering") {
		t.Fatalf("the switcher does not mark the daemon that stopped answering:\n%s", m.View())
	}
}

// §4.1's switcher table: j/k move a cursor, enter selects and closes, esc and
// v close without changing anything.
func TestSwitcherKeys(t *testing.T) {
	m := switcherModel(120, 40)
	if m.cursor != 0 || m.selected != rootSock {
		t.Fatalf("the overlay opened at row %d with %q selected", m.cursor, m.selected)
	}
	if got := press(m, "j").cursor; got != 1 {
		t.Fatalf("j moved the cursor to %d", got)
	}
	if got := press(m, "k").cursor; got != 0 {
		t.Fatalf("k past the top moved the cursor to %d", got)
	}
	// Moving the cursor is not selecting.
	if got := press(m, "j").selected; got != rootSock {
		t.Fatalf("moving the cursor selected %q", got)
	}
	sel := press(m, "j", "enter")
	if sel.selected != userSock || sel.overlay != overlayNone {
		t.Fatalf("enter left %q selected with overlay %v", sel.selected, sel.overlay)
	}
	for _, k := range []string{"esc", "v"} {
		got := press(m, "j", k)
		if got.overlay != overlayNone {
			t.Errorf("%s did not close the overlay", k)
		}
		if got.selected != rootSock {
			t.Errorf("%s changed the selection to %q", k, got.selected)
		}
	}
	// The cursor may rest on a row that cannot become the active daemon —
	// reading its detail is why the row exists — and enter there does nothing.
	onSkew := press(m, "j", "j")
	if onSkew.cursor != 2 {
		t.Fatalf("the cursor stopped at %d instead of the skewed row", onSkew.cursor)
	}
	if got := press(onSkew, "enter"); got.selected != rootSock || got.overlay != overlaySwitcher {
		t.Fatalf("enter on a skewed row selected %q and left overlay %v", got.selected, got.overlay)
	}
	// The cursor clamps at both ends rather than wrapping.
	if got := press(m, "G").cursor; got != 3 {
		t.Fatalf("G left the cursor at %d, want the last row", got)
	}
	if got := press(m, "G", "j").cursor; got != 3 {
		t.Fatalf("j past the end moved the cursor to %d", got)
	}
	if got := press(m, "G", "g").cursor; got != 0 {
		t.Fatalf("g left the cursor at %d", got)
	}
}

func TestSwitcherToggleAndReopen(t *testing.T) {
	m := switcherModel(120, 40)
	m.overlay = overlayNone
	m = press(m, "v")
	if m.overlay != overlaySwitcher {
		t.Fatal("v did not open the overlay")
	}
	// Reopening lands on the daemon the dashboard is showing, not wherever the
	// cursor was left.
	m = press(m, "j", "j", "v", "tab", "v")
	if got := m.cursorIndex(m.daemonRows()); got != 1 {
		t.Fatalf("the overlay reopened at row %d, want the selected daemon's", got)
	}
	// Quit and help answer from inside the overlay; nothing else global does.
	if _, cmd := send(m, key("q")); cmd == nil {
		t.Fatal("q did not quit from the switcher overlay")
	}
	if got := press(m, "?"); got.overlay != overlayHelp {
		t.Fatal("? did not reach the help overlay from the switcher")
	}
}

// D8's detection is the canonical pair across two flavors — not merely two
// daemons — and it is over the answering snapshots, which is what makes the
// banner clear itself.
func TestFightingPairDetection(t *testing.T) {
	user, root := healthySnap(), fightingSnap()
	if got := fightingPair([]*introspect.Snapshot{user, root}); got == nil {
		t.Fatal("two flavors serving one VM is not detected")
	} else if got.root.State.PID != 4242 || got.user.State.PID != 71234 {
		t.Fatalf("combatants: root pid %d, user pid %d", got.root.State.PID, got.user.State.PID)
	}
	// Two daemons, two VMs: not a fight.
	if got := fightingPair([]*introspect.Snapshot{user, rootSnap()}); got != nil {
		t.Fatalf("daemons for different VMs read as fighting: %+v", got)
	}
	// Two user daemons for one VM cannot happen through the path grammar, and
	// two of one flavor is not the D8 posture either way.
	twin := healthySnap()
	twin.Path = devSock
	if got := fightingPair([]*introspect.Snapshot{user, twin}); got != nil {
		t.Fatal("two user sockets read as fighting")
	}
	// A snapshot that names no VM at all matches nothing.
	blankUser, blankRoot := healthySnap(), fightingSnap()
	blankUser.State.VM = introspect.VM{}
	blankRoot.State.VM = introspect.VM{}
	if got := fightingPair([]*introspect.Snapshot{blankUser, blankRoot}); got != nil {
		t.Fatal("two daemons naming no VM read as fighting")
	}
	// The canonical pair wins over the ref spelling: `colima:default` and the
	// instance it resolves to are one VM.
	spelled := fightingSnap()
	spelled.State.VM.Ref = "colima:default"
	if fightingPair([]*introspect.Snapshot{user, spelled}) == nil {
		t.Fatal("two spellings of one canonical pair are not detected")
	}
}

// The banner names both PIDs and the consequence, renders above every view,
// and goes away on its own when one daemon stops answering (D8).
func TestFightingBannerEverywhereAndClears(t *testing.T) {
	base := fightingModel(120, 40)
	for _, tc := range []struct {
		name string
		m    Model
	}{
		{"dashboard", base},
		{"refusals pane", func() Model { m := base; m.pane = paneRefusals; return m }()},
		{"switcher", openSwitcher(base)},
		{"help", helpModel(base)},
	} {
		v := tc.m.View()
		for _, want := range []string{"colima:colima", "4242", "71234", "mirror ports"} {
			if !strings.Contains(v, want) {
				t.Errorf("%s: the banner is missing %q:\n%s", tc.name, want, v)
			}
		}
	}
	// One daemon stops answering: its snapshot is retained for D7's grace
	// window, but it is no longer evidence of a fight.
	m, _ := send(base, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap()}, at: fixtureNow})
	if got := fightingPair(m.answering()); got != nil {
		t.Fatal("the banner survived one daemon going quiet")
	}
	if strings.Contains(m.View(), "fight over mirror ports") {
		t.Fatalf("the banner is still rendered:\n%s", m.View())
	}
}

// §3.4: the two combatants are adjacent rows, which is what makes the
// pathology visible rather than merely detected.
func TestFightingCombatantsAreAdjacent(t *testing.T) {
	other := devSnap()
	m := testModel(120, 40, healthySnap(), fightingSnap(), other)
	rows := m.daemonRows()
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	if rows[0].snap.Path != rootSock || rows[1].snap.Path != userSock {
		t.Fatalf("combatants are not adjacent: %s", rowKinds(rows))
	}
	// With no fight the order is Discover's, untouched.
	plain := testModel(120, 40, healthySnap(), rootSnap(), other)
	if got := rowKinds(plain.daemonRows()); got != "daemon:"+rootSock+" daemon:"+devSock+" daemon:"+userSock {
		t.Fatalf("Discover order was disturbed without a fight: %s", got)
	}
}
