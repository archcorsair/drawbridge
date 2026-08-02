package agent

import (
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

	c, err := p.pop(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if c != liveLocal {
		t.Fatal("pop returned the dead conn")
	}
}
