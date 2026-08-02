package mirror

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

func entryFor(snap introspect.Mirror, proto string, port uint16) (introspect.MirrorEntry, bool) {
	for _, e := range snap.Entries {
		if e.Proto == proto && e.Port == port {
			return e, true
		}
	}
	return introspect.MirrorEntry{}, false
}

// The three entry states are what makes the skip-visibility and coexistence
// checks exact instead of log-scraping: a skipped port and a lost bind are
// both reported, and neither is a mirror.
func TestSnapshotEntryStates(t *testing.T) {
	captureLog(t)
	ring := &introspect.Ring{}
	skipped := uint16(61111) // above the guest autobind range; nothing is bound
	bound := freeTCPPort(t)

	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	contested := uint16(held.Addr().(*net.TCPAddr).Port)

	c := &Client{
		MirrorIP: "127.0.0.1",
		mirrors:  map[mirrorKey]*mirrorEntry{},
		Skip:     map[uint16]bool{skipped: true},
		Refusals: ring,
	}
	c.add(listenerInfo{Proto: "tcp", Port: skipped, Addr: "0.0.0.0"})
	c.add(listenerInfo{Proto: "tcp", Port: bound, Addr: "0.0.0.0"})
	c.add(listenerInfo{Proto: "tcp", Port: contested, Addr: "0.0.0.0"})
	defer c.closeAll()

	snap := c.Snapshot()
	for _, tc := range []struct {
		port  uint16
		state string
	}{
		{skipped, introspect.EntrySkipped},
		{bound, introspect.EntryBound},
		{contested, introspect.EntryBindFailed},
	} {
		e, ok := entryFor(snap, "tcp", tc.port)
		if !ok {
			t.Fatalf("no entry for :%d (want %s): %+v", tc.port, tc.state, snap.Entries)
		}
		if e.State != tc.state {
			t.Fatalf(":%d state = %q, want %q", tc.port, e.State, tc.state)
		}
		if e.Since.IsZero() {
			t.Fatalf(":%d has no transition time", tc.port)
		}
	}
	if len(snap.Skip) != 1 || snap.Skip[0] != skipped {
		t.Fatalf("skip = %v, want [%d]", snap.Skip, skipped)
	}
	if snap.SessionUp {
		t.Fatal("sessionUp is true without a session")
	}

	// The skip reaches the ring with the line it logged, ID-tagged.
	got := ring.Snapshot()
	if len(got) != 1 || got[0].ID != introspect.IDMirrorSkip {
		t.Fatalf("ring = %+v", got)
	}
	if !strings.Contains(got[0].Line, fmt.Sprintf("skipping guest tcp :%d", skipped)) {
		t.Fatalf("ring line = %q", got[0].Line)
	}
}

// A bind that lost the race and later wins must stop reporting itself as
// failed: the observation is evidence, not a permanent verdict.
func TestBindFailedClearsOnceBound(t *testing.T) {
	captureLog(t)
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(held.Addr().(*net.TCPAddr).Port)

	c := &Client{MirrorIP: "127.0.0.1", mirrors: map[mirrorKey]*mirrorEntry{}}
	c.add(listenerInfo{Proto: "tcp", Port: port, Addr: "0.0.0.0"})
	if e, _ := entryFor(c.Snapshot(), "tcp", port); e.State != introspect.EntryBindFailed {
		t.Fatalf("state = %q, want %q", e.State, introspect.EntryBindFailed)
	}

	held.Close()
	c.add(listenerInfo{Proto: "tcp", Port: port, Addr: "0.0.0.0"})
	defer c.closeAll()
	snap := c.Snapshot()
	e, ok := entryFor(snap, "tcp", port)
	if !ok || e.State != introspect.EntryBound {
		t.Fatalf("state = %+v, want bound", e)
	}
	if n := len(snap.Entries); n != 1 {
		t.Fatalf("%d entries for one port: %+v", n, snap.Entries)
	}
}

// The session flag is live state, not a startup guess.
func TestSnapshotSessionLiveness(t *testing.T) {
	captureLog(t)
	port := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: port, Addr: "0.0.0.0"}})
	m := New(fa.ln.Addr().String(), "127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitFor(t, "the mirror", func() bool { return m.Mirrors("tcp", port) })
	snap := m.Snapshot()
	if !snap.SessionUp {
		t.Fatal("sessionUp is false while the session is up")
	}
	if snap.LastEventAt.IsZero() {
		t.Fatal("lastEventAt is unset after the snapshot event")
	}
	if e, ok := entryFor(snap, "tcp", port); !ok || e.State != introspect.EntryBound {
		t.Fatalf("entry = %+v, ok=%v", e, ok)
	}
}
