package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
)

func ref(sec int, id, line string) introspect.Refusal {
	return introspect.Refusal{At: fixtureNow.Add(time.Duration(sec) * time.Second), ID: id, Line: line}
}

func ids(log []introspect.Refusal) string {
	out := make([]string, 0, len(log))
	for _, r := range log {
		out = append(out, r.ID)
	}
	return strings.Join(out, ",")
}

// D5's identity is the full (At, ID, Line) triple, and new entries append in
// ring order: the ring is re-read every second and only what it has not
// already shown may be added.
func TestAccumulateIdentityAndOrder(t *testing.T) {
	first := []introspect.Refusal{ref(0, "a", "one"), ref(1, "b", "two")}
	log := accumulate(nil, first)
	if got := ids(log); got != "a,b" {
		t.Fatalf("first ring accumulated %q", got)
	}
	// The same ring again adds nothing.
	if got := accumulate(log, first); ids(got) != "a,b" {
		t.Fatalf("re-reading one ring duplicated it: %q", ids(got))
	}
	// A ring that rotated by one: the overlap is recognised, the new entry
	// appends at the end.
	if got := accumulate(log, []introspect.Refusal{ref(1, "b", "two"), ref(2, "c", "three")}); ids(got) != "a,b,c" {
		t.Fatalf("a rotated ring accumulated %q", ids(got))
	}
	// Same instant and ID, different line: a different refusal.
	if got := accumulate(log, []introspect.Refusal{ref(1, "b", "different")}); ids(got) != "a,b,b" {
		t.Fatalf("a line change was swallowed: %q", ids(got))
	}
	// Same ID and line, different instant: also a different refusal — that is
	// what makes a repeating cause visible as a stream rather than one row.
	if got := accumulate(log, []introspect.Refusal{ref(9, "b", "two")}); ids(got) != "a,b,b" {
		t.Fatalf("a repeat at a new time was swallowed: %q", ids(got))
	}
	// An empty ring never rewrites the log.
	if got := accumulate(log, nil); &got[0] != &log[0] {
		t.Fatal("an empty ring reallocated the log")
	}
}

// The same instant decoded twice carries two distinct *time.Location pointers
// whenever the daemon's zone is not UTC, so identity compares the instant, not
// the struct. Without this the log fills with duplicates at 1 Hz.
func TestAccumulateIdentityIgnoresLocation(t *testing.T) {
	utc := introspect.Refusal{At: fixtureNow, ID: "auth-mismatch", Line: "same"}
	elsewhere := introspect.Refusal{
		At:   fixtureNow.In(time.FixedZone("somewhere", -7*3600)),
		ID:   "auth-mismatch",
		Line: "same",
	}
	if utc == elsewhere {
		t.Fatal("the fixture does not reproduce the hazard: the two structs compare equal")
	}
	if got := accumulate([]introspect.Refusal{utc}, []introspect.Refusal{elsewhere}); len(got) != 1 {
		t.Fatalf("one refusal in two zones accumulated %d entries", len(got))
	}
}

// The cap is D5's, oldest-first: the pane is bounded evidence, not an audit
// log, and the bound is stated in its header.
func TestAccumulateCapsOldestFirst(t *testing.T) {
	var log []introspect.Refusal
	for i := 0; i < refusalCap+introspect.RingSize; i++ {
		log = accumulate(log, []introspect.Refusal{ref(i, "id", fmt.Sprintf("line %d", i))})
	}
	if len(log) != refusalCap {
		t.Fatalf("log grew to %d, want the %d cap", len(log), refusalCap)
	}
	if got := log[0].Line; got != fmt.Sprintf("line %d", introspect.RingSize) {
		t.Fatalf("eviction was not oldest-first: the log starts at %q", got)
	}
	if got := log[len(log)-1].Line; got != fmt.Sprintf("line %d", refusalCap+introspect.RingSize-1) {
		t.Fatalf("the newest entry is %q", got)
	}
}

// A ring that overflowed between two fetches loses the middle — the bound the
// pane header states. What must not happen is the survivors landing out of
// order or the overlap being missed.
func TestAccumulateRingOverflow(t *testing.T) {
	log := accumulate(nil, []introspect.Refusal{ref(0, "a", "one")})
	full := make([]introspect.Refusal, 0, introspect.RingSize)
	for i := 0; i < introspect.RingSize; i++ {
		full = append(full, ref(100+i, "id", fmt.Sprintf("line %d", i)))
	}
	log = accumulate(log, full)
	if len(log) != introspect.RingSize+1 {
		t.Fatalf("a full ring accumulated %d entries", len(log))
	}
	if log[0].Line != "one" || log[len(log)-1].Line != fmt.Sprintf("line %d", introspect.RingSize-1) {
		t.Fatal("a full ring did not append in ring order")
	}
}

// Accumulation is per path and survives a daemon leaving the selection: the
// pane shows what the daemon the user is looking at refused, whichever one
// that is.
func TestRefusalsAccumulatePerPath(t *testing.T) {
	user, root := healthySnap(), rootSnap()
	user.State.RecentRefusals = []introspect.Refusal{ref(0, "auth-mismatch", "user line")}
	root.State.RecentRefusals = []introspect.Refusal{ref(0, introspect.IDMirrorSkip, "root line")}
	m := testModel(120, 40)
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{user, root}, at: fixtureNow})
	if got := len(m.refusals); got != 2 {
		t.Fatalf("%d paths accumulated, want one per daemon", got)
	}
	if ids(m.refusals[userSock]) != "auth-mismatch" || ids(m.refusals[rootSock]) != introspect.IDMirrorSkip {
		t.Fatalf("logs crossed paths: %+v", m.refusals)
	}
	// A path D7 retires takes its log with it.
	for i := 0; i <= maxMissedTicks; i++ {
		m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{root}, at: fixtureNow})
	}
	if _, ok := m.refusals[userSock]; ok {
		t.Fatal("a retired daemon's log outlived it")
	}
}

// The pane is the region the scroll keys drive while it is open (§4.1), and it
// follows the newest line until the user scrolls away from it.
func TestRefusalPaneToggleAndFollow(t *testing.T) {
	m := manyRefusalsModel(80, 24)
	m.pane, m.scroll = paneNone, scrollState{}

	m = press(m, "r")
	if m.pane != paneRefusals {
		t.Fatal("r did not open the pane")
	}
	if m.scrollRegion() != regionRefusals {
		t.Fatal("the open pane is not the scroll region")
	}
	if !m.scroll.follow {
		t.Fatal("the pane did not open following the newest line")
	}
	v := m.View()
	if !strings.Contains(v, "ring carries last 32 per refresh") && !strings.Contains(v, "last 32/refresh") {
		t.Fatalf("the pane header does not state the ring's loss bound:\n%s", v)
	}
	if !strings.Contains(v, "guest tcp :9011 not mirrored") {
		t.Fatalf("a following pane does not show the newest line:\n%s", v)
	}
	// §4.2: the footer is the same five entries with the pane open.
	if !strings.Contains(v, shortHelpFull) && !strings.Contains(v, shortHelpCompact) {
		t.Fatal("the footer changed while the pane was open")
	}

	up := press(m, "k")
	if up.scroll.follow {
		t.Fatal("scrolling up did not disengage follow")
	}
	if strings.Contains(up.View(), "guest tcp :9011 not mirrored") {
		t.Fatal("a scrolled pane is still pinned to the bottom")
	}
	if back := press(up, "G"); !back.scroll.follow || back.View() != m.View() {
		t.Fatal("G did not re-engage follow")
	}
	if got := press(m, "r"); got.pane != paneNone || got.scrollRegion() != regionMirror {
		t.Fatal("r did not close the pane and hand the keys back to the table")
	}
}

// While an overlay borrows the scroll keys the pane keeps showing its newest
// lines rather than the overlay's offset.
func TestRefusalPaneIgnoresAnotherRegionsOffset(t *testing.T) {
	m := manyRefusalsModel(80, 24)
	m.overlay = overlayHelp
	m.scroll = scrollState{offset: 7}
	if got := m.paneScroll(); !got.follow || got.offset != 0 {
		t.Fatalf("the pane borrowed the help overlay's offset: %+v", got)
	}
	if !strings.Contains(m.View(), "guest tcp :9011 not mirrored") {
		t.Fatal("the pane under an overlay is not showing its newest line")
	}
}

// The empty pane says what it does and does not know: the ring starts with
// whatever the daemon remembers, not with nothing.
func TestRefusalPaneEmptyWording(t *testing.T) {
	if !strings.Contains(emptyRefusalsModel(120, 40).View(), refusalEmpty) {
		t.Fatal("an empty pane does not carry the §3.2 wording")
	}
}

// The ID's class is carried by the ID text itself, so the coloring rule never
// has to be the only signal — and the auth family is matched by prefix rather
// than by a list this package would have to keep in step with §7.
func TestRefusalIDStyling(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want lipgloss.Style
	}{
		{"auth-mismatch", styleErr},
		{"auth-wrong-peer", styleErr},
		{"auth-mac-missing-secret", styleErr},
		{introspect.IDMirrorSkip, styleDim},
		{introspect.IDReverseDialRefused, styleWarn},
		{"", styleWarn},
	} {
		if got := refusalStyle(tc.id).GetForeground(); got != tc.want.GetForeground() {
			t.Errorf("%q styled %v, want %v", tc.id, got, tc.want.GetForeground())
		}
	}
	// The widest contract ID fits its column whole: an ID truncated to a
	// prefix is not the vocabulary doctor's findings use.
	if got := visWidth("auth-mac-missing-secret"); got > refusalIDW-2 {
		t.Errorf("the ID column is %d columns, too narrow for a %d-column ID", refusalIDW-2, got)
	}
}
