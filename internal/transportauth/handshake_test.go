package transportauth

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// countWriter records every Write separately: the hello must reach the wire
// as exactly one segment (§3.3).
type countWriter struct {
	writes [][]byte
}

func (w *countWriter) Write(b []byte) (int, error) {
	w.writes = append(w.writes, append([]byte(nil), b...))
	return len(b), nil
}

func TestClientHelloIsOneWrite(t *testing.T) {
	s := testSecret()
	sHdr := []byte{6, 0x1f, 0x90, 0}

	t.Run("authenticated S", func(t *testing.T) {
		w := &countWriter{}
		frame, err := ClientHello(w, &s, 'S', sHdr)
		if err != nil {
			t.Fatal(err)
		}
		if len(w.writes) != 1 {
			t.Fatalf("%d writes, want 1", len(w.writes))
		}
		got := w.writes[0]
		if len(got) != 40 {
			t.Fatalf("hello is %d bytes, want 40", len(got))
		}
		want := append([]byte{'S', 1, 0, 0}, mustProof(s.MacProof(frame))...)
		want = append(want, sHdr...)
		if !bytes.Equal(got, want) {
			t.Fatalf("hello = %x, want %x", got, want)
		}
	})

	t.Run("authenticated D", func(t *testing.T) {
		w := &countWriter{}
		if _, err := ClientHello(w, &s, 'D', nil); err != nil {
			t.Fatal(err)
		}
		if len(w.writes) != 1 || len(w.writes[0]) != 36 {
			t.Fatalf("writes = %d, first %d bytes; want 1 write of 36", len(w.writes), len(w.writes[0]))
		}
	})

	// Unauthenticated mode must be byte-identical to today's wire (§6 row 5).
	t.Run("unauthenticated", func(t *testing.T) {
		w := &countWriter{}
		if _, err := ClientHello(w, nil, 'S', sHdr); err != nil {
			t.Fatal(err)
		}
		want := append([]byte{'S', 0, 0, 0}, sHdr...)
		if len(w.writes) != 1 || !bytes.Equal(w.writes[0], want) {
			t.Fatalf("hello = %x (%d writes), want %x in one write", w.writes, len(w.writes), want)
		}
	})
}

// tcpPair is a connected loopback pair. Real sockets, not net.Pipe: the
// handshake's whole point is what happens when one side writes and the other
// walks away, and a synchronous pipe cannot express a socket buffer.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { client.Close(); r.c.Close() })
	return client, r.c
}

// deadlineConn records deadline calls so the "dispatch inherits no deadline"
// rule can be asserted: a stale deadline would fire the dial pool's watchdog
// the instant a 'D' conn parks.
type deadlineConn struct {
	net.Conn
	lastDeadline     time.Time
	lastReadDeadline time.Time
}

func (c *deadlineConn) SetDeadline(t time.Time) error {
	c.lastDeadline = t
	c.lastReadDeadline = t
	return c.Conn.SetDeadline(t)
}

func (c *deadlineConn) SetReadDeadline(t time.Time) error {
	c.lastReadDeadline = t
	return c.Conn.SetReadDeadline(t)
}

// handshakePair runs a Mac hello + agent handshake over a pipe and reports
// what each side concluded.
func handshakePair(t *testing.T, macSec, agentSec *Secret, typ byte) (macErr, agentErr error, srv *deadlineConn) {
	t.Helper()
	cli, agt := tcpPair(t)
	srv = &deadlineConn{Conn: agt}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var frame [FrameLen]byte
		if _, err := io.ReadFull(srv, frame[:]); err != nil {
			agentErr = err
			return
		}
		agentErr = ServerHandshake(srv, agentSec, frame, time.Second)
		if agentErr != nil {
			srv.Close()
		}
	}()

	frame, err := ClientHello(cli, macSec, typ, nil)
	if err != nil {
		macErr = err
	} else {
		macErr = AwaitAgentProof(cli, macSec, frame, time.Second)
	}
	<-done
	return macErr, agentErr, srv
}

func wantCause(t *testing.T, err error, want Cause) {
	t.Helper()
	got, ok := CauseOf(err)
	if !ok {
		t.Fatalf("err = %v, want a *RefusedError with cause %s", err, want)
	}
	if got != want {
		t.Fatalf("cause = %s, want %s", got, want)
	}
}

func TestHandshakeModeMatrix(t *testing.T) {
	a := testSecret()
	b, _ := Generate()

	t.Run("both configured, same secret", func(t *testing.T) {
		macErr, agentErr, srv := handshakePair(t, &a, &a, 'D')
		if macErr != nil || agentErr != nil {
			t.Fatalf("mac=%v agent=%v, want mutual success", macErr, agentErr)
		}
		if !srv.lastDeadline.IsZero() {
			t.Fatalf("agent left a deadline of %v on the conn", srv.lastDeadline)
		}
	})

	t.Run("neither configured", func(t *testing.T) {
		macErr, agentErr, _ := handshakePair(t, nil, nil, 'D')
		if macErr != nil || agentErr != nil {
			t.Fatalf("mac=%v agent=%v, want today's wire to succeed", macErr, agentErr)
		}
	})

	// §6 row 2 / §7 row 2: the peer holds a different secret.
	t.Run("different secrets", func(t *testing.T) {
		macErr, agentErr, _ := handshakePair(t, &a, &b, 'M')
		wantCause(t, agentErr, CauseProofMismatch)
		wantCause(t, macErr, CauseIncomplete) // row 4's vantage point
	})

	// §6 row 3 / §7 rows 1 + 6: only the guest has a secret.
	t.Run("mac unconfigured", func(t *testing.T) {
		macErr, agentErr, _ := handshakePair(t, nil, &a, 'E')
		wantCause(t, agentErr, CausePeerUnauthenticated)
		if macErr != nil {
			t.Fatalf("mac err = %v; an auth=0 Mac awaits nothing", macErr)
		}
	})

	// §6 row 4 / §7 rows 3 + 4: only the Mac has a secret.
	t.Run("agent unconfigured", func(t *testing.T) {
		macErr, agentErr, _ := handshakePair(t, &a, nil, 'R')
		wantCause(t, agentErr, CauseNoLocalSecret)
		wantCause(t, macErr, CauseIncomplete)
	})
}

// A peer that presents a well-formed but wrong agent proof is the demonstrated
// failure (§7 row 5) — it must read as a mismatch, not as a broken conn.
func TestAwaitAgentProofRejectsWrongProof(t *testing.T) {
	a := testSecret()
	b, _ := Generate()
	cli, srv := tcpPair(t)

	frame := Frame('E', AuthStaticHMACv1)
	go func() {
		p := b.AgentProof(frame) // squatter's secret
		srv.Write(p[:])
	}()
	wantCause(t, AwaitAgentProof(cli, &a, frame, time.Second), CauseProofMismatch)
}

// A peer that accepts the conn and then says nothing must not pin us: the
// handshake read is deadline-bounded on both sides (§3.2).
func TestHandshakeDeadlines(t *testing.T) {
	a := testSecret()

	t.Run("mac awaiting a silent agent", func(t *testing.T) {
		cli, _ := tcpPair(t)
		start := time.Now()
		err := AwaitAgentProof(cli, &a, Frame('E', AuthStaticHMACv1), 100*time.Millisecond)
		wantCause(t, err, CauseIncomplete)
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("waited %v for a silent peer", d)
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("err = %v, want a timeout underneath", err)
		}
	})

	t.Run("agent awaiting a silent mac", func(t *testing.T) {
		_, srv := tcpPair(t)
		wrapped := &deadlineConn{Conn: srv}
		start := time.Now()
		err := ServerHandshake(wrapped, &a, Frame('D', AuthStaticHMACv1), 100*time.Millisecond)
		wantCause(t, err, CauseIncomplete)
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("waited %v for a silent peer", d)
		}
	})
}

// An 'S' hello carries its stream header in the same segment, and the agent
// must see that header intact after the handshake consumed the proof.
func TestServerHandshakeLeavesExtraOnTheWire(t *testing.T) {
	s := testSecret()
	cli, srv := tcpPair(t)
	sHdr := []byte{6, 0x1f, 0x90, 0}

	go func() {
		frame, err := ClientHello(cli, &s, 'S', sHdr)
		if err != nil {
			return
		}
		AwaitAgentProof(cli, &s, frame, time.Second)
	}()

	var frame [FrameLen]byte
	if _, err := io.ReadFull(srv, frame[:]); err != nil {
		t.Fatal(err)
	}
	if err := ServerHandshake(srv, &s, frame, time.Second); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	var hdr [4]byte
	srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(srv, hdr[:]); err != nil {
		t.Fatalf("stream header: %v", err)
	}
	if !bytes.Equal(hdr[:], sHdr) {
		t.Fatalf("stream header = %x, want %x", hdr, sHdr)
	}
}
