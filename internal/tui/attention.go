package tui

// The attention strip: one line of chrome that surfaces problems on the
// daemons the user is NOT looking at. The dashboard already tells the whole
// truth about the selected daemon; what it cannot do is say that lima:dev
// started refusing auth or lost a bind race while the user was watching
// colima. The strip is fleet-level triage: it names each other daemon with
// something wrong and the two or three words of what, and it renders nothing
// at all when the fleet is calm, so the calm default stays calm. Progressive
// disclosure still holds: the strip is a pointer, and the keys it implies
// (tab, r, d) are the ones the footer already advertises.

import (
	"fmt"
	"strings"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// attentionLines renders the strip, or nothing when no unselected daemon has
// anything wrong.
func (m Model) attentionLines(lo layout) []string {
	segs := m.attentionSegments()
	if len(segs) == 0 {
		return nil
	}
	w := lo.contentWidth() - 3
	line := strings.Join(segs, styleDim.Render("  ·  "))
	return []string{" " + styleWarn.Render("! elsewhere: ") + truncEnd(line, w-13)}
}

func (m Model) attentionSegments() []string {
	var segs []string
	for _, s := range m.snaps {
		if s.Path == m.selected {
			continue
		}
		items := m.attentionItems(s)
		if len(items) == 0 {
			continue
		}
		segs = append(segs, styleTitle.Render(m.attentionName(s))+" "+
			strings.Join(items, styleDim.Render(" · ")))
	}
	return segs
}

// attentionName is the segment's identity column. When two snapshots claim
// the same VM (the D8 fighting pair), the bare ref names both combatants at
// once, so the flavor tag disambiguates the same way the banner's "root pid
// X and user pid Y" does; a fleet of distinct refs stays untagged.
func (m Model) attentionName(s *introspect.Snapshot) string {
	name := orDash(s.State.VM.Ref)
	if key := vmKey(s); key != "" {
		shared := 0
		for _, o := range m.snaps {
			if vmKey(o) == key {
				shared++
			}
		}
		if shared > 1 {
			name += " (" + flavor(s.Path) + ")"
		}
	}
	return name
}

// attentionItems is the per-daemon triage vocabulary, worst first. Skewed and
// unreadable sockets are deliberately absent: their cards already render in
// every view's chrome, and saying it twice on one screen is noise.
func (m Model) attentionItems(s *introspect.Snapshot) []string {
	st := s.State
	var items []string
	if m.stale(s) {
		items = append(items, styleWarn.Render("not answering"))
	}
	if n := countEntries(st.Mirror.Entries, introspect.EntryBindFailed); n > 0 {
		items = append(items, styleErr.Render(fmt.Sprintf("%d bind-failed", n)))
	}
	if !st.Mirror.SessionUp {
		items = append(items, styleErr.Render("mirror down"))
	}
	if !st.Sync.SessionUp {
		items = append(items, styleWarn.Render("sync down"))
	}
	if st.Auth.Mode != introspect.AuthModeNone && st.Auth.SecretState != introspect.SecretOK {
		items = append(items, styleErr.Render("secret "+orUnknown(st.Auth.SecretState)))
	}
	if st.Version != "" && st.Version != m.version {
		items = append(items, styleWarn.Render("version skew"))
	}
	if n := m.unseenRefusals(s.Path); n > 0 {
		items = append(items, styleWarn.Render(fmt.Sprintf("%d refusals", n)))
	}
	return items
}

func countEntries(entries []introspect.MirrorEntry, state string) int {
	n := 0
	for _, e := range entries {
		if e.State == state {
			n++
		}
	}
	return n
}
