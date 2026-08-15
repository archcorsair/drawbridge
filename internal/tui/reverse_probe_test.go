package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// The goldens run under the ASCII profile, where reverse video renders as
// nothing: this probe pins that a color terminal actually gets the SGR-7
// span for the driven cursor, and that an undriven table emits none.
func TestCursorBarEmitsReverseUnderColor(t *testing.T) {
	lipgloss.SetColorProfile(termenv.ANSI256)
	defer lipgloss.SetColorProfile(termenv.Ascii)

	idle := testModel(120, 16, manyEntries())
	if strings.Contains(idle.View(), "\x1b[7m") {
		t.Fatal("an undriven table emitted a reverse span")
	}
	if got := press(idle, "j").View(); !strings.Contains(got, "\x1b[7m") {
		t.Fatal("a driven cursor emitted no reverse span under a color profile")
	}
}
