package tui

import (
	"strings"
	"testing"
)

// enter opens the detail strip for the selected mirror row, enter and esc
// close it, and a daemon switch drops it with the cursor.
func TestRowDetailStrip(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m = press(m, "j", "enter")
	if !m.mirrorDetail {
		t.Fatal("enter did not open the detail strip")
	}
	v := m.View()
	for _, want := range []string{"meaning", "enter/esc close", "since"} {
		if !strings.Contains(v, want) {
			t.Fatalf("the strip is missing %q:\n%s", want, v)
		}
	}
	if got := press(m, "esc"); got.mirrorDetail {
		t.Fatal("esc did not close the strip")
	}
	if got := press(m, "enter"); got.mirrorDetail {
		t.Fatal("enter did not toggle the strip closed")
	}
	if got := press(m, "tab"); got.mirrorDetail || got.mirrorMoved || got.mirrorCursor != 0 {
		t.Fatal("a daemon switch did not drop the strip and the cursor")
	}
}

// The strip translates each state into its consequence and the next command:
// the sorted order puts bind-failed first, so the fixture's cursor starts on
// the row whose strip carries the lsof line.
func TestRowDetailMeaningAndTry(t *testing.T) {
	m := press(testModel(120, 40, healthySnap()), "g", "enter")
	v := m.View()
	if !strings.Contains(v, "tcp/5000") {
		t.Fatalf("the strip rule does not name the row:\n%s", v)
	}
	if !strings.Contains(v, "another Mac process holds this port") {
		t.Fatal("bind-failed lost its meaning line")
	}
	if !strings.Contains(v, "lsof -nP -iTCP:5000") {
		t.Fatal("bind-failed lost its lsof line")
	}
	// Moving the cursor moves the strip with it: the next row is bound.
	m = press(m, "g", "j")
	v = m.View()
	if !strings.Contains(v, "tcp/3000") || !strings.Contains(v, "nc 127.0.0.1 3000") {
		t.Fatalf("the strip did not follow the cursor:\n%s", v)
	}
}

// The cursor bar is invisible until the user drives it: an untouched
// dashboard renders no reverse-video row and no strip, and enter alone
// reveals the bar with the strip it opens.
func TestRowCursorHiddenUntilDriven(t *testing.T) {
	m := testModel(120, 16, manyEntries())
	if m.mirrorMoved {
		t.Fatal("a fresh model claims the cursor was driven")
	}
	if lines := m.detailLines(m.layout()); lines != 0 {
		t.Fatalf("an untouched dashboard budgets %d strip lines", lines)
	}
	if got := press(m, "enter"); !got.mirrorMoved || !got.mirrorDetail {
		t.Fatal("enter did not reveal the cursor with the strip")
	}
	// esc with both the strip and the pane open closes the strip first,
	// then the pane.
	both := press(testModel(120, 40, healthySnap()), "j", "enter", "r")
	if !both.mirrorDetail || both.pane != paneRefusals {
		t.Fatalf("fixture drift: detail=%v pane=%v", both.mirrorDetail, both.pane)
	}
	one := press(both, "esc")
	if one.mirrorDetail || one.pane != paneRefusals {
		t.Fatal("esc did not close the strip before the pane")
	}
	if got := press(one, "esc"); got.pane == paneRefusals {
		t.Fatal("the second esc did not close the pane")
	}
}
