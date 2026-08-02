package mirror

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
)

// logSink captures the standard logger. The mirror logs from its session
// goroutine, so the buffer needs its own lock.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *logSink {
	t.Helper()
	s := &logSink{}
	old := log.Writer()
	log.SetOutput(s)
	t.Cleanup(func() { log.SetOutput(old) })
	return s
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return p
}

// A skipped guest listener is declined, out loud, and its neighbour on the
// same snapshot is mirrored regardless — the list is per-port policy, not a
// mode. The log assertion is part of the contract: filtering Mac-side is only
// defensible because the decision is announced (see Client.Skip).
func TestSkipListDeclinesGuestListener(t *testing.T) {
	sink := captureLog(t)
	skipped, kept := freeTCPPort(t), freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{
		{Proto: "tcp", Port: skipped, Addr: "0.0.0.0"},
		{Proto: "tcp", Port: kept, Addr: "0.0.0.0"},
	})

	m := New(fa.ln.Addr().String(), "127.0.0.1")
	m.Skip = map[uint16]bool{skipped: true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitFor(t, "the unskipped mirror", func() bool { return m.Mirrors("tcp", kept) })
	if m.Mirrors("tcp", skipped) {
		t.Fatalf("skipped port :%d was mirrored anyway", skipped)
	}
	// Not merely unregistered: the port is genuinely free on the Mac.
	ln, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", skipped))
	if err != nil {
		t.Fatalf("skipped port :%d is bound by something: %v", skipped, err)
	}
	ln.Close()

	want := fmt.Sprintf("skipping guest tcp :%d", skipped)
	if got := sink.String(); !strings.Contains(got, want) {
		t.Fatalf("log does not contain %q:\n%s", want, got)
	}
}

// The same listener with an empty skip-list is mirrored: `-skip ""` is a real
// off switch, not a no-op that leaves a hardcoded list behind.
func TestEmptySkipListMirrorsEverything(t *testing.T) {
	port := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: port, Addr: "0.0.0.0"}})

	m := New(fa.ln.Addr().String(), "127.0.0.1")
	m.Skip = map[uint16]bool{} // what -skip "" produces
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitFor(t, "mirror of the previously skipped port", func() bool { return m.Mirrors("tcp", port) })
}

// add events (a bind after the snapshot) are filtered too, and a skipped port
// is skipped for UDP as well — the list is a port list, not a TCP list.
func TestSkipListFiltersAddEvents(t *testing.T) {
	sink := captureLog(t)
	// Not freeTCPPort: macOS hands out ephemeral ports from 49152, and a UDP
	// add inside the guest autobind range (linuxEphemeralLo–Hi) is dropped
	// before the skip-list ever sees it — the "skipping guest udp" line this
	// test asserts would then never be logged. No socket is bound here (the
	// port is on the skip-list), so a fixed port above that range is safe.
	const port = uint16(61111)
	c := &Client{MirrorIP: "127.0.0.1", mirrors: map[mirrorKey]*mirrorEntry{}, Skip: map[uint16]bool{port: true}}

	c.add(listenerInfo{Proto: "tcp", Port: port, Addr: "0.0.0.0"})
	c.add(listenerInfo{Proto: "udp", Port: port, Addr: "0.0.0.0"})
	if c.Mirrors("tcp", port) || c.Mirrors("udp", port) {
		t.Fatalf("skipped port :%d mirrored from an add event", port)
	}
	got := sink.String()
	for _, want := range []string{
		fmt.Sprintf("skipping guest tcp :%d", port),
		fmt.Sprintf("skipping guest udp :%d", port),
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log does not contain %q:\n%s", want, got)
		}
	}

	// A del for a port that was never mirrored must stay a no-op (and must
	// not claim to be "skipping" anything).
	c.del(listenerInfo{Proto: "tcp", Port: port, Addr: "0.0.0.0"})
}

// Bind arbitration must take no interest in a skipped port. Without this the
// Mac would try the bind, and a Mac that holds the port itself — :22 with
// Remote Login on, the case the default list exists for — would answer
// "inuse" and refuse the guest's own bind with EADDRINUSE.
func TestSkipListReservationTakesNoInterest(t *testing.T) {
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	port := uint16(held.Addr().(*net.TCPAddr).Port)

	c := &Client{MirrorIP: "127.0.0.1", mirrors: map[mirrorKey]*mirrorEntry{}}
	if resp := c.handleReserve(reserveReq{Op: "reserve", Proto: "tcp", Port: port}); resp.OK || resp.Reason != "inuse" {
		t.Fatalf("control: reserve of a Mac-held port = %+v, want inuse", resp)
	}

	c.Skip = map[uint16]bool{port: true}
	resp := c.handleReserve(reserveReq{Op: "reserve", Proto: "tcp", Port: port})
	if !resp.OK || resp.Reason != "" {
		t.Fatalf("reserve of a skipped Mac-held port = %+v, want ok (guest decides)", resp)
	}
	if c.Mirrors("tcp", port) {
		t.Fatalf("reserve of a skipped port registered a mirror")
	}
}
