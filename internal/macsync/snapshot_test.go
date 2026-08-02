package macsync

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// The snapshot states what the guest may currently activate, how many
// reverse-stream conns are parked, and whether the 'M' session is up — the
// facts `status` used to reconstruct by inference.
func TestSnapshotReportsAdvertisedAndPool(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 2,
		UDPPorts: []uint16{5353},
		logf:     func(string, ...any) {},
	}

	// Before Run, nothing is advertised and no session exists: an unprimed
	// syncer must not claim otherwise.
	if snap := s.Snapshot(); snap.SessionUp || len(snap.Advertised) != 0 || snap.PoolParked != 0 {
		t.Fatalf("pre-Run snapshot = %+v", snap)
	}

	startSyncer(t, f, s)
	waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })

	waitSnapshot(t, s, "session up and both conns parked", func(snap introspect.Sync) bool {
		return snap.SessionUp && snap.PoolParked == 2
	})
	snap := s.Snapshot()
	if len(snap.Advertised) != 2 {
		t.Fatalf("advertised = %+v, want tcp 5432 and udp 5353", snap.Advertised)
	}
	if snap.Advertised[0] != (introspect.Advertised{Proto: "tcp", Port: 5432}) {
		t.Fatalf("advertised[0] = %+v", snap.Advertised[0])
	}
	if snap.Advertised[1] != (introspect.Advertised{Proto: "udp", Port: 5353}) {
		t.Fatalf("advertised[1] = %+v", snap.Advertised[1])
	}
	if len(snap.UDPPorts) != 1 || snap.UDPPorts[0] != 5353 {
		t.Fatalf("udpPorts = %v", snap.UDPPorts)
	}
}

// Row 7 lands in the ring, ID-tagged, with the same text it logs: that is
// what lets doctor match evidence by ID instead of scraping log prose, and
// it is the only auth-adjacent evidence a foreground daemon can offer.
func TestRefusedReverseDialReachesTheRing(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	ring := &introspect.Ring{}
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		Refusals: ring,
		logf:     func(string, ...any) {},
	}
	startSyncer(t, f, s)
	waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })

	c := <-f.dconns
	activate(t, c, 6, 9999, 0)
	expectClosed(t, c, "unadvertised port")

	deadline := time.Now().Add(3 * time.Second)
	for {
		got := ring.Snapshot()
		if len(got) > 0 {
			if got[0].ID != introspect.IDReverseDialRefused {
				t.Fatalf("ring ID = %q, want %q", got[0].ID, introspect.IDReverseDialRefused)
			}
			if !strings.Contains(got[0].Line, "not a port this Mac advertised") {
				t.Fatalf("ring line = %q", got[0].Line)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the refusal never reached the ring")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// An unset ring is the default everywhere but drawbridged: the refusal sites
// must stay nil-safe.
func TestRefusalWithoutARingIsSafe(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	s := &Syncer{Poll: p.poll, PoolSize: 1, logf: func(string, ...any) {}}
	startSyncer(t, f, s)
	waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })

	c := <-f.dconns
	activate(t, c, 6, 9999, 0)
	expectClosed(t, c, "unadvertised port, no ring configured")
}

// The non-empty→empty transition while the session is up is the alarm the
// 2026-08-01 `adv 0` incident asked for: an empty set refuses every reverse
// activation, so the transition earns one throttled line and a ring entry.
// Everything here runs on one goroutine, mirroring the real single writer
// (Run's goroutine is the only caller of setAdvertised).
func TestAdvertisedEmptiedTransitionIsLoggedAndRung(t *testing.T) {
	var lines []string
	ring := &introspect.Ring{}
	s := &Syncer{
		Refusals: ring,
		logf: func(format string, args ...any) {
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	one := map[Listener]struct{}{tl(8080, "127.0.0.1"): {}}

	// Session down (priming, reconnect gap): an empty store is expected.
	s.setAdvertised(one)
	s.setAdvertised(nil)
	if len(lines) != 0 {
		t.Fatalf("logged %q with the session down, want nothing", lines)
	}

	s.sessionUp.Store(true)
	s.setAdvertised(one)
	s.setAdvertised(nil)
	if len(lines) != 1 {
		t.Fatalf("logged %q, want exactly one line", lines)
	}
	if !strings.Contains(lines[0], "advertised set went 1 -> 0") {
		t.Fatalf("line = %q", lines[0])
	}
	got := ring.Snapshot()
	if len(got) != 1 || got[0].ID != introspect.IDAdvertisedEmptied {
		t.Fatalf("ring = %+v, want one %s entry", got, introspect.IDAdvertisedEmptied)
	}

	// Flapping inside the 30s window stays quiet…
	s.setAdvertised(one)
	s.setAdvertised(nil)
	if len(lines) != 1 {
		t.Fatalf("throttle failed: %q", lines)
	}
	// …and an empty→empty store is no edge at all.
	s.setAdvertised(nil)
	if len(lines) != 1 {
		t.Fatalf("empty→empty logged: %q", lines)
	}

	// Past the window, the next edge logs (and rings) again.
	s.lastEmptiedLog = time.Now().Add(-31 * time.Second)
	s.setAdvertised(one)
	s.setAdvertised(nil)
	if len(lines) != 2 {
		t.Fatalf("post-window edge: logged %q, want two lines", lines)
	}
	if got := ring.Snapshot(); len(got) != 2 {
		t.Fatalf("ring has %d entries, want 2", len(got))
	}
}

func waitSnapshot(t *testing.T, s *Syncer, what string, ok func(introspect.Sync) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if ok(s.Snapshot()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %+v", what, s.Snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The birth-empty shape: a session established advertising nothing never
// makes the non-empty→empty transition, so it has its own alarm — the shape
// the 2026-08-01 incident actually had (macOS 27.0b4 filters pcblist per
// responsible app; a terminal-launched daemon is empty from its first poll).
func TestEmptySessionIsLoggedAndRung(t *testing.T) {
	var lines []string
	ring := &introspect.Ring{}
	s := &Syncer{
		Refusals: ring,
		logf: func(format string, args ...any) {
			lines = append(lines, fmt.Sprintf(format, args...))
		},
	}
	s.noteEmptySession()
	if len(lines) != 1 || !strings.Contains(lines[0], "zero LISTEN sockets") {
		t.Fatalf("lines = %q, want one naming the zero-listener anomaly", lines)
	}
	if !strings.Contains(lines[0], "sudo drawbridge install") {
		t.Fatalf("line does not carry the exempt-posture remedy: %q", lines[0])
	}
	got := ring.Snapshot()
	if len(got) != 1 || got[0].ID != introspect.IDAdvertisedNone {
		t.Fatalf("ring = %+v, want one %s entry", got, introspect.IDAdvertisedNone)
	}
}

// Without a ring the birth-empty alarm still logs and does not panic.
func TestEmptySessionWithoutARingIsSafe(t *testing.T) {
	s := &Syncer{logf: func(string, ...any) {}}
	s.noteEmptySession()
}
