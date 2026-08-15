package tui

// The change pulse: a client-side "what moved since the last refresh"
// treatment for the mirror table. A row whose state changed, or that appeared
// on a daemon already being watched, carries a warn gutter mark for pulseTTL.
// Everything is diffed between consecutive fetches on this side of the
// socket; no schema fields are involved and the daemon knows nothing about
// it.

import (
	"strconv"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// pulse is one observed entry transition: what the row said before and when
// it changed. A row that is new to the table pulses with from == "".
type pulse struct {
	from string
	at   time.Time
}

// pulseTTL is how long a changed row keeps its marker: long enough to catch
// the eye across a few refreshes, short enough that the table calms down.
const pulseTTL = 5 * time.Second

// pulseKey identifies one mirror row across refreshes.
func pulseKey(path string, e introspect.MirrorEntry) string {
	return path + "\x00" + e.Proto + "\x00" + strconv.Itoa(int(e.Port))
}

// mergePulses folds one fetch into the change map: a row whose state differs
// from the previous fetch's (or that is new on a path already being watched)
// starts a pulse, a live pulse survives until pulseTTL, and rows whose paths
// vanished take their pulses with them. A path's first-ever snapshot pulses
// nothing: attaching to a daemon is not an event on that daemon.
func (m Model) mergePulses(msg snapshotsMsg) map[string]pulse {
	prev := map[string]string{}
	known := map[string]bool{}
	for _, s := range m.snaps {
		if m.missedTicks[s.Path] > 0 {
			// Last-known, not last-seen: rows held through D7's grace window
			// must not read as changes when the daemon answers again.
			continue
		}
		known[s.Path] = true
		for _, e := range s.State.Mirror.Entries {
			prev[pulseKey(s.Path, e)] = e.State
		}
	}
	out := make(map[string]pulse)
	for _, s := range msg.snaps {
		if s == nil || !s.Usable {
			continue
		}
		for _, e := range s.State.Mirror.Entries {
			k := pulseKey(s.Path, e)
			old, existed := prev[k]
			switch {
			case existed && old != e.State:
				out[k] = pulse{from: old, at: msg.at}
			case !existed && known[s.Path]:
				out[k] = pulse{at: msg.at}
			default:
				if p, ok := m.pulses[k]; ok && msg.at.Sub(p.at) < pulseTTL {
					out[k] = p
				}
			}
		}
	}
	return out
}

// entryPulse reports the active pulse for one row, if any. Expiry is checked
// against the render clock too, so a pulse fades between fetches rather than
// only when the next one lands.
func (m Model) entryPulse(path string, e introspect.MirrorEntry) (pulse, bool) {
	p, ok := m.pulses[pulseKey(path, e)]
	if !ok || m.now.Sub(p.at) >= pulseTTL {
		return pulse{}, false
	}
	return p, true
}

// mirrorGutter is the two-column gutter every mirror row carries: an active
// change pulse's mark, blank otherwise. The mark is warn-styled and one
// glyph, so it reads on mono terminals and never repaints the row itself.
func (m Model) mirrorGutter(path string, e introspect.MirrorEntry) string {
	if _, ok := m.entryPulse(path, e); ok {
		return styleWarn.Render("◆ ")
	}
	return "  "
}
