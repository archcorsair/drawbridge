package tui

import (
	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
)

// The palette is ANSI-16 only, through AdaptiveColor light/dark pairs
// (docs/tui.md §3.6): SSH into this Mac from anything still renders, and no
// truecolor terminal is assumed. Every status is carried by a word AND a
// one-column glyph (`● bound`, `✕ bind-failed`), so NO_COLOR and TERM=dumb
// keep every semantic distinction instead of collapsing the states into the
// same gray word.
//
// Two light-terminal rules, each with a rationale:
//   - dim is Light "8" (bright black), not "7" (light gray): ANSI 7 on a
//     white background is close to invisible, and dim text still has to read.
//   - a dedicated accent pair carries focus and selection (the switcher's
//     cursor marker, the doctor spinner) so "selected" stops borrowing the
//     label blue and the verdict colors stay reserved for verdicts.
//
// DRAWBRIDGE_TUI_BG=light|dark pins the palette half where background
// detection cannot see the terminal (applyBackgroundOverride in tui.go).
//
// Color literals live here and nowhere else.
var (
	styleTitle = lipgloss.NewStyle().Bold(true)
	styleDim   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "8", Dark: "8"})
	styleLabel = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "4", Dark: "12"})
	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "2", Dark: "10"})
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "3", Dark: "11"})
	styleErr   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "1", Dark: "9"})
	styleFrame = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "8", Dark: "7"})

	// styleAccent/styleAccentBold are the focus pair: selection markers and
	// activity affordances. Cyan because it collides with none of the three
	// verdict colors and is not the label blue.
	styleAccent     = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "6", Dark: "14"})
	styleAccentBold = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "6", Dark: "14"}).Bold(true)
)

// State glyphs: one column each, chosen to differ in silhouette so they stay
// distinct without color. The skip glyph is deliberately quiet: the skip
// list is the default exclusion at work, not an error.
const (
	glyphBound   = "●"
	glyphSkipped = "·"
	glyphFailed  = "✕"
	glyphOther   = "◌"
	glyphUp      = "●"
	glyphDown    = "○"
)

func entryGlyph(state string) string {
	switch state {
	case introspect.EntryBound:
		return glyphBound
	case introspect.EntrySkipped:
		return glyphSkipped
	case introspect.EntryBindFailed:
		return glyphFailed
	default:
		return glyphOther
	}
}

// entryStyle colors one mirror entry state. `skipped` is dim because the skip
// list is the default exclusion at work, not an error (doctor check 11's
// discoverability wording, carried into the row's styling).
func entryStyle(state string) lipgloss.Style {
	switch state {
	case introspect.EntryBound:
		return styleOK
	case introspect.EntrySkipped:
		return styleDim
	case introspect.EntryBindFailed:
		return styleErr
	default:
		return styleWarn
	}
}

// doctorStatusGlyph pairs each verdict with a mark that reads without color:
// the check, the bang, the cross, the quiet dot, the lowercase i.
func doctorStatusGlyph(s doctor.Status) string {
	switch s {
	case doctor.StatusOK:
		return "✓"
	case doctor.StatusWarn:
		return "!"
	case doctor.StatusFail:
		return "✕"
	case doctor.StatusSkip:
		return "·"
	default:
		return "i"
	}
}

// doctorStatusStyle is the one doctor.Status → style mapping in the package
// (§5). `skip` is dim and `info` is a label color rather than a verdict color:
// check 11's job is discoverability, and it must be readable without ever
// coloring a run red or green.
func doctorStatusStyle(s doctor.Status) lipgloss.Style {
	switch s {
	case doctor.StatusOK:
		return styleOK
	case doctor.StatusWarn:
		return styleWarn
	case doctor.StatusFail:
		return styleErr
	case doctor.StatusSkip:
		return styleDim
	default:
		return styleLabel
	}
}

// palette is the style set one block renders through. Choosing styles at the
// block rather than baking them into each segment is what lets the last-known
// summary of a daemon that stopped answering dim as a whole — nesting a dim
// style around already-styled text would break at the first inner reset.
type palette struct {
	label lipgloss.Style
	dim   lipgloss.Style
	ok    lipgloss.Style
	warn  lipgloss.Style
	err   lipgloss.Style
}

func livePalette() palette {
	return palette{label: styleLabel, dim: styleDim, ok: styleOK, warn: styleWarn, err: styleErr}
}

func stalePalette() palette {
	return palette{label: styleDim, dim: styleDim, ok: styleDim, warn: styleDim, err: styleDim}
}

// secret colors a secret state word. A configured secret the daemon could not
// read is the fail-closed posture showing itself, so it reads red.
func (p palette) secret(state string) lipgloss.Style {
	switch state {
	case introspect.SecretOK:
		return p.ok
	case introspect.SecretAbsent:
		return p.warn
	case introspect.SecretMalformed:
		return p.err
	default:
		return p.warn
	}
}

func (p palette) upDown(up bool) string {
	if up {
		return p.ok.Render(glyphUp + " up")
	}
	return p.warn.Render(glyphDown + " down")
}
