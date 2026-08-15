package tui

import (
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// A calm fleet renders no strip at all: the calm default stays calm, and the
// selected daemon's own problems never appear (the dashboard under the strip
// already tells that whole truth).
func TestAttentionCalmAndSelectedAreSilent(t *testing.T) {
	m := testModel(120, 40, healthySnap(), devSnap())
	if got := m.attentionLines(m.layout()); got != nil {
		t.Fatalf("a calm fleet rendered a strip: %v", got)
	}
	// healthySnap carries a bind-failed row, but it is the selected daemon.
	if strings.Contains(m.View(), "elsewhere") {
		t.Fatal("the selected daemon's trouble leaked into the strip")
	}
}

// Each troubled unselected daemon gets one segment with its triage items,
// worst first, severity-styled per item.
func TestAttentionItemsVocabulary(t *testing.T) {
	s := devSnap()
	s.State.Version = "v0.0.9"
	s.State.Auth.SecretState = introspect.SecretAbsent
	s.State.Sync.SessionUp = false
	s.State.Mirror.SessionUp = false
	s.State.Mirror.Entries = []introspect.MirrorEntry{
		{Proto: "tcp", Port: 3000, State: introspect.EntryBindFailed, Since: fixtureNow},
	}
	m := testModel(120, 40, healthySnap(), s)
	m.refusals = map[string][]introspect.Refusal{devSock: refusalRing()}

	items := m.attentionItems(s)
	want := []string{"1 bind-failed", "mirror down", "sync down", "secret absent", "version skew", "3 refusals"}
	if len(items) != len(want) {
		t.Fatalf("items = %v, want %d entries", items, len(want))
	}
	for i, w := range want {
		if !strings.Contains(items[i], w) {
			t.Fatalf("item %d = %q, want %q", i, items[i], w)
		}
	}
	if !strings.Contains(m.View(), "elsewhere: lima:dev") {
		t.Fatalf("the strip does not name the troubled daemon:\n%s", m.View())
	}
}

// The D8 fighting pair shares one VM ref, so the strip's segment carries the
// flavor tag the same way the banner's root pid / user pid wording does. A
// fleet of distinct refs stays untagged.
func TestAttentionFlavorDisambiguatesFightingPair(t *testing.T) {
	// Discover order selects the root combatant first, so the strip names
	// the user one; selecting the user side flips the tag to root.
	m := testModel(120, 40, healthySnap(), fightingSnap())
	segs := m.attentionSegments()
	if len(segs) != 1 || !strings.Contains(segs[0], "colima:colima (user)") {
		t.Fatalf("the user combatant is not flavor-tagged: %v", segs)
	}
	m = m.selectPath(userSock)
	rival := fightingSnap()
	rival.State.Mirror.Entries = []introspect.MirrorEntry{
		{Proto: "tcp", Port: 8080, State: introspect.EntryBindFailed, Since: fixtureNow},
	}
	m.snaps[0] = rival
	segs = m.attentionSegments()
	if len(segs) != 1 || !strings.Contains(segs[0], "colima:colima (root)") {
		t.Fatalf("the root combatant is not flavor-tagged: %v", segs)
	}

	distinct := devSnap()
	distinct.State.Sync.SessionUp = false
	m = testModel(120, 40, healthySnap(), distinct)
	segs = m.attentionSegments()
	if len(segs) != 1 || strings.Contains(segs[0], "(user)") {
		t.Fatalf("a distinct ref got a flavor tag: %v", segs)
	}
}
