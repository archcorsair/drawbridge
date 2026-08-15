package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// groupRefusals folds by ID with the newest line as the exemplar, ordered by
// each group's newest entry ascending: the same newest-at-the-bottom reading
// order as the raw pane.
func TestGroupRefusalsFoldsAndOrders(t *testing.T) {
	at := func(s int) time.Time { return fixtureNow.Add(time.Duration(s) * time.Second) }
	log := []introspect.Refusal{
		{At: at(0), ID: "auth-mismatch", Line: "first auth line"},
		{At: at(1), ID: introspect.IDMirrorSkip, Line: "skip 22"},
		{At: at(2), ID: "auth-mismatch", Line: "newest auth line"},
	}
	groups := groupRefusals(log)
	if len(groups) != 2 {
		t.Fatalf("groups = %+v", groups)
	}
	// mirror-skip's newest (t+1) precedes auth-mismatch's newest (t+2).
	if groups[0].id != introspect.IDMirrorSkip || groups[0].count != 1 {
		t.Fatalf("group 0 = %+v", groups[0])
	}
	g := groups[1]
	if g.id != "auth-mismatch" || g.count != 2 || g.lastLine != "newest auth line" ||
		!g.first.Equal(at(0)) || !g.last.Equal(at(2)) {
		t.Fatalf("group 1 = %+v", g)
	}
	// A one-off renders without a span or a multiplier; a fold carries both.
	lo := layout{width: 120, showSince: true}
	if l := refusalGroupLine(groups[0], lo, 118); strings.Contains(l, "×") || strings.Contains(l, "→") {
		t.Fatalf("a one-off grew a count or a span: %q", l)
	}
	if l := refusalGroupLine(g, lo, 118); !strings.Contains(l, "×2") || !strings.Contains(l, "→") {
		t.Fatalf("the fold lost its count or span: %q", l)
	}
}

// u folds the pane and only the pane: with the log off screen the key means
// nothing, and toggling resets the scroll region to its own fresh start.
func TestGroupToggleIsPaneOnly(t *testing.T) {
	m := manyRefusalsModel(80, 24)
	if got := press(m, "u"); !got.refusalsGrouped {
		t.Fatal("u did not fold the open pane")
	}
	if got := press(m, "u", "u"); got.refusalsGrouped {
		t.Fatal("u twice did not unfold")
	}
	closed := press(m, "r") // pane closed
	if got := press(closed, "u"); got.refusalsGrouped {
		t.Fatal("u acted with the pane closed")
	}

	folded := press(m, "u")
	if !strings.Contains(folded.View(), "×13") {
		t.Fatalf("the storm did not fold to a counted group:\n%s", folded.View())
	}
	if !strings.Contains(folded.View(), "grouped by id · u raw") {
		t.Fatal("the pane header does not name the mode and the way back")
	}
	// The scroll region's total follows the fold: three IDs, three rows.
	if got := folded.scrollTotal(); got != 3 {
		t.Fatalf("grouped scrollTotal = %d, want 3", got)
	}
}
