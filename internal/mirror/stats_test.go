package mirror

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// The per-entry counters, end to end through an authenticated splice: a
// fresh mirror advertises the capability with real zeros, a live client
// counts as a conn, the echoed payload lands byte-exact on both directions
// (the auth hello, proofs and the 'S' header cross the same wire and must
// never reach a counter), and the conn count returns to zero on close with
// the byte counters intact.
func TestSpliceAccounting(t *testing.T) {
	captureLog(t)
	secret := newSecret(t)
	guestPort := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: guestPort, Addr: "0.0.0.0"}})
	fa.setSecret(secret)
	m := runClient(t, fa, macConfig(t, secret))
	waitFor(t, "the mirror", func() bool { return m.Mirrors("tcp", guestPort) })

	snap := m.Snapshot()
	if !snap.PerEntryCounters {
		t.Fatal("an accounting daemon does not advertise PerEntryCounters")
	}
	e, ok := entryFor(snap, "tcp", guestPort)
	if !ok {
		t.Fatalf("no entry for :%d", guestPort)
	}
	if e.Conns != 0 || e.RxBytes != 0 || e.TxBytes != 0 || !e.LastActiveAt.IsZero() {
		t.Fatalf("a fresh mirror is not at zero: %+v", e)
	}

	payload := []byte("hello guest counters")
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", guestPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("splice echo: %v", err)
	}

	waitFor(t, "the live conn and the byte-exact counters", func() bool {
		e, ok := entryFor(m.Snapshot(), "tcp", guestPort)
		return ok && e.Conns == 1 &&
			e.RxBytes == uint64(len(payload)) && e.TxBytes == uint64(len(payload)) &&
			!e.LastActiveAt.IsZero()
	})

	c.Close()
	waitFor(t, "the conn count to drain", func() bool {
		e, ok := entryFor(m.Snapshot(), "tcp", guestPort)
		return ok && e.Conns == 0
	})
	e, _ = entryFor(m.Snapshot(), "tcp", guestPort)
	if e.RxBytes != uint64(len(payload)) || e.TxBytes != uint64(len(payload)) {
		t.Fatalf("closing the conn moved the byte counters: %+v", e)
	}
}

// UDP mirrors count frame payloads (never the 21-byte headers) and report
// no conns: a datagram relay has no per-client connection to count.
func TestUDPAccounting(t *testing.T) {
	captureLog(t)
	port := freeUDPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "udp", Port: port, Addr: "0.0.0.0"}})
	m := runClient(t, fa, macConfig(t, nil))
	waitFor(t, "the udp mirror", func() bool { return m.Mirrors("udp", port) })

	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "PING" {
		t.Fatalf("udp echo = %q, %v", buf[:n], err)
	}

	waitFor(t, "the udp counters", func() bool {
		e, ok := entryFor(m.Snapshot(), "udp", port)
		return ok && e.TxBytes == 4 && e.RxBytes == 4 && e.Conns == 0 && !e.LastActiveAt.IsZero()
	})
}

// The wrapper must keep TCP half-close propagation alive: proxy.Splice
// half-closes through the CloseWrite interface, and a counting wrapper that
// swallowed it would strand every drain-after-FIN flow.
func TestCountingConnPropagatesCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan error, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			got <- err
			return
		}
		defer s.Close()
		_, err = io.ReadAll(s) // returns only when the peer's write half closes
		got <- err
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	w := countingConn{Conn: c, s: &entryStats{}}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("the peer never saw the half-close cleanly: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the peer never saw EOF: CloseWrite was swallowed")
	}
	if w.s.tx.Load() != 1 {
		t.Fatalf("tx = %d, want 1", w.s.tx.Load())
	}
}

// The accounting's cost on the copy hot path, measured two ways: the same
// pipe copy bare and counted (the delta is what a splice pays per 32 KiB
// write), and the accounting arithmetic alone.
func BenchmarkSpliceCopyPath(b *testing.B) {
	payload := make([]byte, 32<<10)
	run := func(b *testing.B, wrap func(net.Conn) net.Conn) {
		a, peer := net.Pipe()
		defer a.Close()
		defer peer.Close()
		go io.Copy(io.Discard, peer)
		w := wrap(a)
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := w.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("bare", func(b *testing.B) {
		run(b, func(c net.Conn) net.Conn { return c })
	})
	b.Run("counted", func(b *testing.B) {
		run(b, func(c net.Conn) net.Conn { return countingConn{Conn: c, s: &entryStats{}} })
	})
	b.Run("accounting-only", func(b *testing.B) {
		s := &entryStats{}
		b.SetBytes(int64(len(payload)))
		for i := 0; i < b.N; i++ {
			s.tx.Add(uint64(len(payload)))
			s.touch()
		}
	})
}
