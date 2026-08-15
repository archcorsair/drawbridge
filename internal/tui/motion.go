package tui

// Motion: the selection flash and the header heartbeat. Both are ambience,
// not information channels; everything they signal is also on screen as
// text, so a terminal that drops frames or a user who looks away loses
// nothing.

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// The selection flash: a daemon switch pulses the summary chrome in the
// accent color for a few frames, so `tab` lands somewhere the eye can catch
// even when two daemons' layouts are near-identical. The chain follows the
// doctor spinner's discipline: each pulse carries a generation, and a
// superseded pulse's ticks die on arrival. Five frames at 80 ms is under
// half a second: long enough to register, short enough to stay calm, and
// esc-free because it interrupts itself the moment another switch lands.
const (
	flashFrames   = 5
	flashInterval = 80 * time.Millisecond
)

type flashMsg struct{ gen int }

func flashTickCmd(gen int) tea.Cmd {
	return tea.Tick(flashInterval, func(time.Time) tea.Msg { return flashMsg{gen: gen} })
}

func (m Model) armFlash() (Model, tea.Cmd) {
	m.flashGen++
	m.flashLeft = flashFrames
	return m, flashTickCmd(m.flashGen)
}

func (m Model) tickFlash(msg flashMsg) (Model, tea.Cmd) {
	if msg.gen != m.flashGen || m.flashLeft <= 0 {
		return m, nil
	}
	m.flashLeft--
	if m.flashLeft <= 0 {
		return m, nil
	}
	return m, flashTickCmd(m.flashGen)
}

// flashStyle is the pulse's decay ramp: bold accent, accent, then the frame's
// ordinary styles. Rendering derives from flashLeft alone, so View stays
// pure.
func (m Model) flashStyle() (border, title lipgloss.Style) {
	switch {
	case m.flashLeft >= 4:
		return styleAccentBold, styleAccentBold
	case m.flashLeft >= 1:
		return styleAccent, styleAccent
	default:
		return styleFrame, styleTitle
	}
}

// heartbeatDot is the header's fetch pulse: it brightens for the render that
// lands right after a fetch and settles by the next 1 Hz tick, so the screen
// visibly breathes at the refresh cadence instead of looking like a static
// screenshot.
func (m Model) heartbeatDot() string {
	if !m.fetchedAt.IsZero() && m.now.Sub(m.fetchedAt) < 500*time.Millisecond {
		return styleAccent.Render("●")
	}
	return styleDim.Render("·")
}
