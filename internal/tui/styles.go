package tui

import (
	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
)

// The palette is ANSI-16 only, through AdaptiveColor light/dark pairs
// (docs/tui.md §3.6): SSH into this Mac from anything still renders, and no
// truecolor terminal is assumed. Every status is also carried by a word
// (`bound`/`bind-failed`, `session up`/`session down`), so NO_COLOR and
// TERM=dumb degrade to legible monochrome rather than losing meaning.
//
// Color literals live here and nowhere else.
var (
	styleTitle = lipgloss.NewStyle().Bold(true)
	styleDim   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "7", Dark: "8"})
	styleLabel = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "4", Dark: "12"})
	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "2", Dark: "10"})
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "3", Dark: "11"})
	styleErr   = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "1", Dark: "9"})
	styleFrame = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "8", Dark: "7"})
)

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
		return p.ok.Render("up")
	}
	return p.warn.Render("down")
}
