package agent

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns two ends of a real loopback TCP connection.
func tcpPair(t *testing.T) (local, peer net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			ch <- c
		}
	}()
	local, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer = <-ch
	t.Cleanup(func() { local.Close(); peer.Close() })
	return local, peer
}

func TestPopReturnsParkedConnUsable(t *testing.T) {
	p := newDialPool()
	local, peer := tcpPair(t)
	p.park(local)
	time.Sleep(20 * time.Millisecond) // let the watchdog block in its read

	c, err := p.pop(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hdr!")); err != nil {
		t.Fatalf("write after pop: %v", err)
	}
	buf := make([]byte, 4)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	// The watchdog must be fully detached: bytes from the peer belong to
	// the popped conn's reader, not the watchdog.
	if _, err := peer.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after pop (watchdog stole it?): %v", err)
	}
	if string(buf) != "data" {
		t.Fatalf("read %q, want data", buf)
	}
}

func TestDeadParkedConnIsDropped(t *testing.T) {
	p := newDialPool()
	local, peer := tcpPair(t)
	p.park(local)
	peer.Close() // Mac side went away while parked

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := len(p.conns)
		p.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dead parked conn never removed")
}

func TestJunkByteConnIsDropped(t *testing.T) {
	p := newDialPool()
	local, peer := tcpPair(t)
	p.park(local)
	peer.Write([]byte{0xff}) // protocol violation while parked

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		n := len(p.conns)
		p.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("junk-byte conn never removed")
}

func TestPopWaitsForPark(t *testing.T) {
	p := newDialPool()
	local, peer := tcpPair(t)
	_ = peer
	go func() {
		time.Sleep(100 * time.Millisecond)
		p.park(local)
	}()
	start := time.Now()
	c, err := p.pop(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c != local {
		t.Fatal("pop returned a different conn")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("pop took %v, should return as soon as park happens", time.Since(start))
	}
}

func TestPopTimesOutEmpty(t *testing.T) {
	p := newDialPool()
	if _, err := p.pop(50 * time.Millisecond); err == nil {
		t.Fatal("pop on empty pool should time out")
	}
}

func TestPopSkipsDeadPicksLive(t *testing.T) {
	p := newDialPool()
	deadLocal, deadPeer := tcpPair(t)
	liveLocal, livePeer := tcpPair(t)
	_ = livePeer
	p.park(deadLocal)
	p.park(liveLocal)
	deadPeer.Close()

	// FIN delivery is asynchronous; the test is about a pool holding a known-dead conn.
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		p.mu.Lock()
		n := len(p.conns)
		p.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("watchdog never dropped the dead conn (pool size %d)", n)
		}
	}

	c, err := p.pop(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c != liveLocal {
		t.Fatal("pop returned the dead conn")
	}
}

// TestPopSkipsDeadEntries covers pop's own skip, which the watchdog usually
// pre-empts: entries are inserted by hand with done already closed, so no
// watchdog runs. A is live but watchdog-flagged, B's peer has closed
// (found through probeLive), C is live. Map order picks the entry pop
// visits first, so the loop covers the orderings.
func TestPopSkipsDeadEntries(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := newDialPool()
		aLocal, aPeer := tcpPair(t)
		bLocal, bPeer := tcpPair(t)
		cLocal, cPeer := tcpPair(t)
		_, _ = aPeer, cPeer
		bPeer.Close()
		// FIN delivery is asynchronous; wait until the conn is known dead.
		for deadline := time.Now().Add(2 * time.Second); probeLive(bLocal); time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("FIN never reached the dead conn")
			}
		}
		entry := func(c net.Conn, bad bool) *parked {
			done := make(chan struct{})
			close(done)
			return &parked{c: c, bad: bad, done: done}
		}
		p.mu.Lock()
		p.conns[entry(aLocal, true)] = struct{}{}
		p.conns[entry(bLocal, false)] = struct{}{}
		p.conns[entry(cLocal, false)] = struct{}{}
		p.mu.Unlock()

		c, err := p.pop(2 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if c != cLocal {
			t.Fatalf("iteration %d: pop returned a flagged or dead conn", i)
		}
		// pop stops at the first live entry, so a skipped one the map
		// ordered after C is still pooled. A second pop visits the rest.
		if c, err := p.pop(10 * time.Millisecond); err == nil {
			t.Fatalf("iteration %d: second pop returned %v from a pool with no live conn", i, c)
		}
		for name, skipped := range map[string]net.Conn{"flagged": aLocal, "dead": bLocal} {
			if _, err := skipped.Write([]byte{0}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("iteration %d: skipped %s conn not closed: %v", i, name, err)
			}
		}
	}
}
