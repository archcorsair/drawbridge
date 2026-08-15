package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// pulseSnap builds one usable snapshot with the given mirror entries.
func pulseSnap(path string, entries ...introspect.MirrorEntry) *introspect.Snapshot {
	return &introspect.Snapshot{
		Path:   path,
		Usable: true,
		State: introspect.State{
			Schema: introspect.Schema,
			Mirror: introspect.Mirror{SessionUp: true, Entries: entries},
		},
	}
}

func entry(proto string, port uint16, state string) introspect.MirrorEntry {
	return introspect.MirrorEntry{Proto: proto, Port: port, State: state, Since: fixtureNow}
}

func fetchAt(m Model, at time.Time, snaps ...*introspect.Snapshot) Model {
	next, _ := m.Update(snapshotsMsg{snaps: snaps, at: at})
	return next.(Model)
}

// A path's first-ever snapshot pulses nothing: attaching to a daemon is not
// an event on that daemon. An unchanged second fetch pulses nothing either.
func TestPulseFirstSnapshotIsQuiet(t *testing.T) {
	m := testModel(120, 40)
	m = fetchAt(m, fixtureNow, pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBound)))
	if len(m.pulses) != 0 {
		t.Fatalf("the first snapshot pulsed: %+v", m.pulses)
	}
	m = fetchAt(m, fixtureNow.Add(time.Second), pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBound)))
	if len(m.pulses) != 0 {
		t.Fatalf("an unchanged fetch pulsed: %+v", m.pulses)
	}
}

// A state flip pulses with the previous state recorded; a row that appears on
// a path already being watched pulses as new (from empty).
func TestPulseOnChangeAndArrival(t *testing.T) {
	m := testModel(120, 40)
	m = fetchAt(m, fixtureNow, pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBound)))
	m = fetchAt(m, fixtureNow.Add(time.Second),
		pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBindFailed), entry("tcp", 3000, introspect.EntryBound)))

	flipped, ok := m.entryPulse(userSock, entry("tcp", 8080, introspect.EntryBindFailed))
	if !ok || flipped.from != introspect.EntryBound {
		t.Fatalf("the flip did not pulse with its previous state: %+v ok=%v", flipped, ok)
	}
	arrived, ok := m.entryPulse(userSock, entry("tcp", 3000, introspect.EntryBound))
	if !ok || arrived.from != "" {
		t.Fatalf("the arrival did not pulse as new: %+v ok=%v", arrived, ok)
	}
	if !mirrorRowsContain(m, "◆") {
		t.Fatal("no gutter mark rendered for an active pulse")
	}
}

// A pulse survives unchanged fetches inside pulseTTL and dies at the TTL;
// entryPulse also expires against the render clock between fetches.
func TestPulseExpiry(t *testing.T) {
	m := testModel(120, 40)
	m = fetchAt(m, fixtureNow, pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBound)))
	m = fetchAt(m, fixtureNow.Add(time.Second), pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBindFailed)))
	e := entry("tcp", 8080, introspect.EntryBindFailed)

	m = fetchAt(m, fixtureNow.Add(3*time.Second), pulseSnap(userSock, e))
	if _, ok := m.entryPulse(userSock, e); !ok {
		t.Fatal("a live pulse did not survive an unchanged fetch inside the TTL")
	}
	m.now = fixtureNow.Add(1*time.Second + pulseTTL)
	if _, ok := m.entryPulse(userSock, e); ok {
		t.Fatal("the render clock did not expire a stale pulse")
	}
	m = fetchAt(m, fixtureNow.Add(2*time.Second+pulseTTL), pulseSnap(userSock, e))
	if len(m.pulses) != 0 {
		t.Fatalf("the fetch merge kept an expired pulse: %+v", m.pulses)
	}
}

// D7's grace window must never read as change: a daemon that stops answering
// and comes back with the same rows pulses nothing, and even a row that
// changed while it was away pulses nothing (there was no observed fetch to
// diff against).
func TestPulseIgnoresGraceWindowReappearance(t *testing.T) {
	m := testModel(120, 40)
	m = fetchAt(m, fixtureNow, pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBound)))
	// Three missed fetches: the snapshot is retained, last-known, dimmed.
	for i := 1; i <= 3; i++ {
		m = fetchAt(m, fixtureNow.Add(time.Duration(i)*time.Second))
	}
	if m.missedTicks[userSock] != 3 {
		t.Fatalf("fixture drift: missedTicks = %d", m.missedTicks[userSock])
	}
	m = fetchAt(m, fixtureNow.Add(4*time.Second),
		pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBindFailed)))
	if len(m.pulses) != 0 {
		t.Fatalf("a grace-window reappearance pulsed: %+v", m.pulses)
	}
}

// A retired path takes its pulses with it: nothing keyed to a vanished
// socket survives the merge.
func TestPulseDropsWithItsPath(t *testing.T) {
	m := testModel(120, 40)
	m = fetchAt(m, fixtureNow, pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBound)))
	m = fetchAt(m, fixtureNow.Add(time.Second), pulseSnap(userSock, entry("tcp", 8080, introspect.EntryBindFailed)))
	if len(m.pulses) != 1 {
		t.Fatalf("fixture drift: pulses = %+v", m.pulses)
	}
	m = fetchAt(m, fixtureNow.Add(2*time.Second))
	if len(m.pulses) != 0 {
		t.Fatalf("a vanished path kept its pulses: %+v", m.pulses)
	}
}

func mirrorRowsContain(m Model, want string) bool {
	return strings.Contains(m.View(), want)
}
