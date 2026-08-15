package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// A daemon switch arms the flash and starts its tick chain; the chain
// decrements once per tick and ends on its own. The discipline is the doctor
// spinner's: every arm bumps the generation, and a superseded chain's ticks
// die on arrival.
func TestFlashArmsAndDecays(t *testing.T) {
	m := testModel(120, 40, healthySnap(), devSnap())
	next, cmd := send(m, key("tab"))
	if next.flashLeft != flashFrames {
		t.Fatalf("tab armed flashLeft = %d, want %d", next.flashLeft, flashFrames)
	}
	if cmd == nil {
		t.Fatal("tab armed no tick chain")
	}
	gen := next.flashGen
	for i := flashFrames - 1; i >= 1; i-- {
		var c tea.Cmd
		next, c = send(next, flashMsg{gen: gen})
		if next.flashLeft != i {
			t.Fatalf("tick left flashLeft = %d, want %d", next.flashLeft, i)
		}
		if (c == nil) != (i == 0) && i == 0 {
			t.Fatal("the chain re-armed past its end")
		}
	}
	next, c := send(next, flashMsg{gen: gen})
	if next.flashLeft != 0 || c != nil {
		t.Fatalf("the chain did not end: left=%d cmd=%v", next.flashLeft, c)
	}
}

// A stale generation's tick is a no-op: a second switch supersedes the first
// pulse rather than fighting it, and the first chain's ticks land on nothing.
func TestFlashSupersededChainDies(t *testing.T) {
	m := testModel(120, 40, healthySnap(), devSnap())
	m1, _ := send(m, key("tab"))
	stale := m1.flashGen
	m2, _ := send(m1, key("tab"))
	if m2.flashGen == stale {
		t.Fatal("a second switch did not bump the flash generation")
	}
	m3, c := send(m2, flashMsg{gen: stale})
	if m3.flashLeft != flashFrames || c != nil {
		t.Fatalf("a stale tick advanced the pulse: left=%d cmd=%v", m3.flashLeft, c)
	}
}

// The flash confirms a landing: a number key with no daemon behind it pulses
// nothing, from the dashboard and from inside the switcher alike.
func TestFlashDeadNumberIsQuiet(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	if got := press(m, "9"); got.flashLeft != 0 {
		t.Fatalf("a dead number key pulsed: flashLeft = %d", got.flashLeft)
	}
	if got := press(openSwitcher(m), "9"); got.flashLeft != 0 {
		t.Fatalf("a dead number key pulsed inside the switcher: flashLeft = %d", got.flashLeft)
	}
	if got := press(openSwitcher(testModel(120, 40, healthySnap(), devSnap())), "2"); got.flashLeft != flashFrames || got.overlay != overlayNone {
		t.Fatalf("a live number inside the switcher: flashLeft=%d overlay=%v", got.flashLeft, got.overlay)
	}
}

// flashStyle is a pure decay ramp over flashLeft: accent while the pulse is
// live, the ordinary frame styles at rest. Styles are compared by their
// foreground and weight (lipgloss.Style carries funcs and is not comparable).
func TestFlashStyleRamp(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	border, title := m.flashStyle()
	if border.GetForeground() != styleFrame.GetForeground() || !title.GetBold() || title.GetForeground() != styleTitle.GetForeground() {
		t.Fatal("at rest the chrome must render in its ordinary styles")
	}
	m.flashLeft = flashFrames
	if b, _ := m.flashStyle(); b.GetForeground() != styleAccent.GetForeground() || !b.GetBold() {
		t.Fatal("a fresh pulse must open bold accent")
	}
	m.flashLeft = 1
	if b, _ := m.flashStyle(); b.GetForeground() != styleAccent.GetForeground() || b.GetBold() {
		t.Fatal("the tail of the pulse must decay to plain accent")
	}
}

// The heartbeat brightens for the render right after a fetch and settles by
// the next 1 Hz tick; with no fetch yet there is nothing to pulse.
func TestHeartbeatDotSettles(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	if got := m.heartbeatDot(); !strings.Contains(got, "●") {
		t.Fatalf("300ms after a fetch the dot is settled: %q", got)
	}
	m.now = m.fetchedAt.Add(2 * time.Second)
	if got := m.heartbeatDot(); !strings.Contains(got, "·") {
		t.Fatalf("2s after a fetch the dot is still bright: %q", got)
	}
	m.fetchedAt = time.Time{}
	if got := m.heartbeatDot(); !strings.Contains(got, "·") {
		t.Fatalf("with no fetch at all the dot pulses: %q", got)
	}
}
