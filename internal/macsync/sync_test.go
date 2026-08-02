package macsync

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// fakeAgent accepts transport conns like the guest agent: 'M' conns are
// decoded into events, 'D' conns are parked for the test to activate.
type fakeAgent struct {
	ln     net.Listener
	events chan event
	dconns chan net.Conn
	mconns chan net.Conn

	// secret, when set, makes this agent demand the Mac proof and answer
	// with its own — the real agent's contract (docs/transport-auth.md §3.2).
	secret *transportauth.Secret
	// answerWith mints the agent proof when it differs from secret: a
	// squatter that verified nothing and answers with a secret of its own.
	answerWith *transportauth.Secret
	refusals   chan string
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAgent{
		ln:       ln,
		events:   make(chan event, 256),
		dconns:   make(chan net.Conn, 16),
		mconns:   make(chan net.Conn, 16),
		refusals: make(chan string, 16),
	}
	t.Cleanup(func() { ln.Close() })
	go f.acceptLoop()
	return f
}

// handshake is the agent half: verify the Mac proof, answer with ours.
// Reports false when the conn was refused (and closed).
func (f *fakeAgent) handshake(c net.Conn, frame [4]byte) bool {
	auth := frame[1]
	if f.secret == nil {
		if auth != transportauth.AuthNone {
			f.note("peer requires auth, this agent has no secret")
			c.Close()
			return false
		}
		return true
	}
	if auth != transportauth.AuthStaticHMACv1 {
		f.note("peer sent no authentication")
		c.Close()
		return false
	}
	var got [transportauth.ProofLen]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		c.Close()
		return false
	}
	if !transportauth.Verify(f.secret.MacProof(frame), got[:]) {
		f.note("invalid transport secret")
		c.Close()
		return false
	}
	answer := f.secret
	if f.answerWith != nil {
		answer = f.answerWith
	}
	p := answer.AgentProof(frame)
	if _, err := c.Write(p[:]); err != nil {
		c.Close()
		return false
	}
	return true
}

func (f *fakeAgent) note(why string) {
	select {
	case f.refusals <- why:
	default:
	}
}

func macConfig(t *testing.T, s *transportauth.Secret) transportauth.MacConfig {
	t.Helper()
	if s == nil {
		return transportauth.MacConfig{VM: "drawbridge"}
	}
	p := filepath.Join(t.TempDir(), "transport-secret")
	if err := os.WriteFile(p, []byte(s.Format()), 0o600); err != nil {
		t.Fatal(err)
	}
	return transportauth.MacConfig{SecretFile: p, VM: "drawbridge"}
}

func newSecret(t *testing.T) *transportauth.Secret {
	t.Helper()
	s, err := transportauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func (f *fakeAgent) addr() string { return f.ln.Addr().String() }

func (f *fakeAgent) acceptLoop() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			var frame [4]byte // type frame: {type, auth, 0, 0}
			if _, err := io.ReadFull(c, frame[:]); err != nil {
				c.Close()
				return
			}
			if frame[2] != 0 || frame[3] != 0 {
				c.Close()
				return
			}
			if !f.handshake(c, frame) {
				return
			}
			switch frame[0] {
			case 'M':
				f.mconns <- c
				dec := json.NewDecoder(c)
				for {
					var ev event
					if err := dec.Decode(&ev); err != nil {
						return
					}
					f.events <- ev
				}
			case 'D':
				f.dconns <- c
			default:
				c.Close()
			}
		}()
	}
}

func waitEvent(t *testing.T, f *fakeAgent, what string, pred func(event) bool) event {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case ev := <-f.events:
			if pred(ev) {
				return ev
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// pollSet is a mutable fake for Syncer.Poll.
type pollSet struct {
	mu sync.Mutex
	ls []Listener
}

func (p *pollSet) set(ls ...Listener) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ls = ls
}

func (p *pollSet) poll() ([]Listener, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Listener(nil), p.ls...), nil
}

func tl(port uint16, addr string) Listener {
	return Listener{Proto: "tcp", Port: port, Addr: netip.MustParseAddr(addr)}
}

func startSyncer(t *testing.T, f *fakeAgent, s *Syncer) {
	t.Helper()
	s.AgentAddr = f.addr()
	if s.Interval == 0 {
		s.Interval = 10 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Run(ctx)
}

func TestSnapshotThenAddDel(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	startSyncer(t, f, &Syncer{Poll: p.poll, PoolSize: 1})

	snap := waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })
	if len(snap.Listeners) != 1 || snap.Listeners[0].Port != 5432 {
		t.Fatalf("snapshot = %+v, want one 5432 listener", snap.Listeners)
	}

	p.set(tl(5432, "127.0.0.1"), tl(8080, "0.0.0.0"))
	waitEvent(t, f, "add 8080", func(e event) bool {
		return e.Op == "add" && e.Port == 8080 && e.Addr == "0.0.0.0"
	})

	p.set(tl(8080, "0.0.0.0"))
	waitEvent(t, f, "del 5432", func(e event) bool {
		return e.Op == "del" && e.Port == 5432 && e.Addr == "127.0.0.1"
	})
}

// The skip-list reaches this direction through Exclude — the seam
// drawbridged already uses for the agent port and its own mirrors — and it
// has to cover both what the poller finds (TCP) and what -udp configures,
// since a skipped port is a port, not a protocol. This is the direction where
// :22 matters: syncing the Mac's Remote Login would steer an in-guest
// `ssh localhost` at the Mac's sshd.
func TestExcludeKeepsSkippedPortsOutOfTheSnapshot(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(22, "0.0.0.0"), tl(5432, "127.0.0.1"))
	skip := map[uint16]bool{22: true, 5300: true}
	startSyncer(t, f, &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		Exclude:  func(l Listener) bool { return skip[l.Port] },
		UDPPorts: []uint16{5300, 5301},
	})

	snap := waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })
	for _, l := range snap.Listeners {
		if skip[l.Port] {
			t.Fatalf("snapshot = %+v, includes skipped port :%d", snap.Listeners, l.Port)
		}
	}
	if len(snap.Listeners) != 2 { // tcp 5432 + udp 5301
		t.Fatalf("snapshot = %+v, want the two unskipped listeners", snap.Listeners)
	}

	// And a bind that appears later on a skipped port never produces an add.
	p.set(tl(22, "0.0.0.0"), tl(5432, "127.0.0.1"), tl(8080, "0.0.0.0"))
	waitEvent(t, f, "add 8080", func(e event) bool { return e.Op == "add" && e.Port == 8080 })
	select {
	case ev := <-f.events:
		if ev.Op == "add" && skip[ev.Port] {
			t.Fatalf("add for skipped port :%d", ev.Port)
		}
	default:
	}
}

func TestNormalizationAndFiltering(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(
		tl(8080, "::"),          // dual-stack → synced as 0.0.0.0
		tl(9999, "::1"),         // v6-only loopback → skipped (Phase 3 is v4)
		tl(9998, "192.168.1.5"), // LAN-scoped → skipped
	)
	startSyncer(t, f, &Syncer{Poll: p.poll, PoolSize: 1})

	snap := waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })
	if len(snap.Listeners) != 1 {
		t.Fatalf("snapshot = %+v, want exactly one listener", snap.Listeners)
	}
	got := snap.Listeners[0]
	if got.Port != 8080 || got.Addr != netip.MustParseAddr("0.0.0.0") {
		t.Fatalf("listener = %+v, want 8080 on 0.0.0.0", got)
	}
}

func TestExcludeFlipEmitsDel(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(7070, "127.0.0.1"))
	var mu sync.Mutex
	excluded := false
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		Exclude: func(l Listener) bool {
			mu.Lock()
			defer mu.Unlock()
			return excluded && l.Port == 7070
		},
	}
	startSyncer(t, f, s)

	snap := waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })
	if len(snap.Listeners) != 1 {
		t.Fatalf("snapshot = %+v, want the 7070 listener", snap.Listeners)
	}
	mu.Lock()
	excluded = true
	mu.Unlock()
	waitEvent(t, f, "del 7070", func(e event) bool { return e.Op == "del" && e.Port == 7070 })
}

func TestDialPoolServesStreamAndReplenishes(t *testing.T) {
	f := newFakeAgent(t)

	// Local echo backend standing in for a Mac service.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()

	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1")) // advertised: handleStream dials nothing else
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 2,
		DialLocal: func(port uint16) (net.Conn, error) {
			if port != 5432 {
				t.Errorf("DialLocal port = %d, want 5432", port)
			}
			return net.Dial("tcp", echo.Addr().String())
		},
	}
	startSyncer(t, f, s)

	// Pool fills to PoolSize.
	first := <-f.dconns
	<-f.dconns

	// Activate one parked conn the way a gateway proxy does.
	var hdr [4]byte
	hdr[0] = 6
	binary.BigEndian.PutUint16(hdr[1:3], 5432)
	if _, err := first.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write([]byte("hello mac")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 9)
	first.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(first, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "hello mac" {
		t.Fatalf("echo = %q", buf)
	}

	// A replacement conn gets parked.
	select {
	case <-f.dconns:
	case <-time.After(3 * time.Second):
		t.Fatal("pool never replenished after activation")
	}
}

func TestReconnectSendsFreshSnapshot(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(6060, "127.0.0.1"))
	startSyncer(t, f, &Syncer{Poll: p.poll, PoolSize: 1})

	waitEvent(t, f, "first snapshot", func(e event) bool { return e.Op == "snapshot" })
	mc := <-f.mconns
	mc.Close()

	snap := waitEvent(t, f, "snapshot after reconnect", func(e event) bool { return e.Op == "snapshot" })
	if len(snap.Listeners) != 1 || snap.Listeners[0].Port != 6060 {
		t.Fatalf("reconnect snapshot = %+v, want the 6060 listener", snap.Listeners)
	}
}

// activate writes the 4-byte activation header a guest gateway proxy sends.
func activate(t *testing.T, c net.Conn, proto uint8, port uint16, reserved byte) {
	t.Helper()
	var hdr [4]byte
	hdr[0] = proto
	binary.BigEndian.PutUint16(hdr[1:3], port)
	hdr[3] = reserved
	if _, err := c.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
}

// expectClosed asserts the syncer closed a reverse-stream conn instead of
// splicing it: refusal is a closed conn, never a warning-and-continue.
func expectClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	if n, err := c.Read(b[:]); err == nil || n != 0 {
		t.Fatalf("%s: read n=%d err=%v, want the conn closed", what, n, err)
	}
}

// Q8 (c): the guest may only activate ports this Mac advertised. An
// authenticated-but-wrong peer is capped at what the syncer deliberately
// offered (docs/transport-auth.md §7 row 7).
func TestReverseDialBoundToAdvertisedPorts(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	var dialed atomic.Int32
	logs := make(chan string, 8)
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		DialLocal: func(port uint16) (net.Conn, error) {
			dialed.Add(1)
			return nil, fmt.Errorf("must not dial :%d", port)
		},
		DialLocalUDP: func(port uint16) (*net.UDPConn, error) {
			dialed.Add(1)
			return nil, fmt.Errorf("must not dial udp :%d", port)
		},
		logf: func(format string, args ...any) {
			select {
			case logs <- fmt.Sprintf(format, args...):
			default:
			}
		},
	}
	startSyncer(t, f, s)
	waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })

	// A port that was never advertised, on either proto.
	for _, tc := range []struct {
		proto uint8
		port  uint16
	}{{6, 9999}, {17, 5432}} {
		c := <-f.dconns
		activate(t, c, tc.proto, tc.port, 0)
		expectClosed(t, c, fmt.Sprintf("proto %d port %d", tc.proto, tc.port))
		select {
		case line := <-logs:
			if !strings.Contains(line, "not a port this Mac advertised") {
				t.Fatalf("log line = %q", line)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("refusal was not logged")
		}
	}
	if n := dialed.Load(); n != 0 {
		t.Fatalf("%d local dials for unadvertised ports", n)
	}
}

// The del-vs-activation race: the guest activates a port the same tick the
// Mac withdrew it. That resolves as a refusal — the Mac no longer offers the
// port, so it no longer dials it.
func TestDelThenActivateIsRefused(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(7070, "127.0.0.1"))
	dialed := make(chan uint16, 4)
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		DialLocal: func(port uint16) (net.Conn, error) {
			dialed <- port
			return nil, fmt.Errorf("no backend in this test")
		},
		logf: func(string, ...any) {},
	}
	startSyncer(t, f, s)
	waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })

	// While advertised, an activation is accepted (it reaches DialLocal).
	c := <-f.dconns
	activate(t, c, 6, 7070, 0)
	select {
	case got := <-dialed:
		if got != 7070 {
			t.Fatalf("dialed :%d, want :7070", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("advertised port was not dialed")
	}

	p.set()
	waitEvent(t, f, "del 7070", func(e event) bool { return e.Op == "del" && e.Port == 7070 })

	c2 := <-f.dconns
	activate(t, c2, 6, 7070, 0)
	expectClosed(t, c2, "activation after del")
	select {
	case got := <-dialed:
		t.Fatalf("dialed :%d after the port was withdrawn", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// The advertised set survives an 'M' session drop: parked conns outlive the
// blip, and clearing the set would refuse valid activations mid-reconnect.
func TestAdvertisedSetSurvivesSessionDrop(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(6060, "127.0.0.1"))
	dialed := make(chan uint16, 4)
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		DialLocal: func(port uint16) (net.Conn, error) {
			dialed <- port
			return nil, fmt.Errorf("no backend in this test")
		},
		logf: func(string, ...any) {},
	}
	startSyncer(t, f, s)
	waitEvent(t, f, "first snapshot", func(e event) bool { return e.Op == "snapshot" })

	mc := <-f.mconns
	mc.Close() // agent restart: the 'M' session dies, parked conns do not

	c := <-f.dconns
	activate(t, c, 6, 6060, 0)
	select {
	case got := <-dialed:
		if got != 6060 {
			t.Fatalf("dialed :%d, want :6060", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("activation refused after a session drop")
	}
}

// §7 row 9: the activation header's reserved byte is the framing-version
// escape hatch. The Mac side never enforced it; now it does.
func TestActivationReservedByteRejected(t *testing.T) {
	f := newFakeAgent(t)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	dialed := make(chan uint16, 4)
	logs := make(chan string, 8)
	s := &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		DialLocal: func(port uint16) (net.Conn, error) {
			dialed <- port
			return nil, fmt.Errorf("no backend in this test")
		},
		logf: func(format string, args ...any) {
			select {
			case logs <- fmt.Sprintf(format, args...):
			default:
			}
		},
	}
	startSyncer(t, f, s)
	waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })

	c := <-f.dconns
	activate(t, c, 6, 5432, 1) // advertised port, incompatible header
	expectClosed(t, c, "nonzero reserved byte")
	select {
	case line := <-logs:
		if !strings.Contains(line, "nonzero reserved byte in activation header") {
			t.Fatalf("log line = %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reserved-byte drop was not logged")
	}
	select {
	case got := <-dialed:
		t.Fatalf("dialed :%d despite an incompatible activation header", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// --- Phase 4.5: transport auth (docs/transport-auth.md §3.2, §7)

// Mutual success on both of this package's conn types: the 'M' session
// snapshots and the 'D' pool parks, activates, and splices — under auth the
// wire after the handshake is the wire it always was.
func TestMutualAuthSyncAndReverseDial(t *testing.T) {
	secret := newSecret(t)
	f := newFakeAgent(t)
	f.secret = secret

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()

	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	startSyncer(t, f, &Syncer{
		Poll:     p.poll,
		PoolSize: 2,
		Auth:     macConfig(t, secret),
		DialLocal: func(port uint16) (net.Conn, error) {
			return net.Dial("tcp", echo.Addr().String())
		},
		logf: func(string, ...any) {},
	})

	snap := waitEvent(t, f, "snapshot", func(e event) bool { return e.Op == "snapshot" })
	if len(snap.Listeners) != 1 || snap.Listeners[0].Port != 5432 {
		t.Fatalf("snapshot = %+v, want the 5432 listener", snap.Listeners)
	}

	c := <-f.dconns
	activate(t, c, 6, 5432, 0)
	if _, err := c.Write([]byte("hello mac")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 9)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != "hello mac" {
		t.Fatalf("echo = %q", buf)
	}
}

// §7 row 5, the demonstrated failure: the peer answers with a proof minted
// from a different secret. The syncer must refuse — no snapshot, no parked
// conn — and say which VM it was provisioned for and where the endpoint came
// from.
func TestSyncerRefusesWrongAgentProof(t *testing.T) {
	secret, squatter := newSecret(t), newSecret(t)
	f := newFakeAgent(t)
	f.secret, f.answerWith = secret, squatter

	auth := macConfig(t, secret)
	auth.Source = func() string { return "forwarder" }
	logs := make(chan string, 32)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	startSyncer(t, f, &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		Auth:     auth,
		logf: func(format string, args ...any) {
			select {
			case logs <- fmt.Sprintf(format, args...):
			default:
			}
		},
	})

	line := waitLogLine(t, logs, "invalid transport secret")
	for _, want := range []string{"NOT the agent", "drawbridge", "source=forwarder", "loopback forwarder"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
	// Refusal means refusal: nothing was advertised to the squatter.
	select {
	case ev := <-f.events:
		t.Fatalf("sent %+v to an unverified peer", ev)
	case <-time.After(300 * time.Millisecond):
	}
}

// §7 row 4, the other vantage point on a secret mismatch: our proof is
// rejected and the conn dies mid-handshake. EOF and ECONNRESET are the same
// condition, so the diagnosis must not depend on which one the kernel picked.
func TestSyncerDiagnosesMismatchOnClose(t *testing.T) {
	f := newFakeAgent(t)
	f.secret = newSecret(t) // a different secret than the Mac's

	logs := make(chan string, 32)
	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	startSyncer(t, f, &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		Auth:     macConfig(t, newSecret(t)),
		logf: func(format string, args ...any) {
			select {
			case logs <- fmt.Sprintf(format, args...):
			default:
			}
		},
	})

	line := waitLogLine(t, logs, "closed during transport authentication")
	if !strings.Contains(line, "drawbridge up") {
		t.Errorf("line %q does not name the convergence command", line)
	}
	if why := waitRefusal(t, f); !strings.Contains(why, "invalid transport secret") {
		t.Errorf("agent refused with %q, want an invalid-secret refusal", why)
	}
	select {
	case ev := <-f.events:
		t.Fatalf("sent %+v to a peer holding a different secret", ev)
	case <-time.After(300 * time.Millisecond):
	}
}

// A guest that has a secret refuses our unauthenticated hello (§6 row 3 /
// §7 row 1). Nothing is advertised, and the pool never fills.
func TestSyncerWithoutSecretIsRefusedBySecretfulAgent(t *testing.T) {
	f := newFakeAgent(t)
	f.secret = newSecret(t)

	p := &pollSet{}
	p.set(tl(5432, "127.0.0.1"))
	startSyncer(t, f, &Syncer{
		Poll:     p.poll,
		PoolSize: 1,
		logf:     func(string, ...any) {},
	})

	if why := waitRefusal(t, f); !strings.Contains(why, "no authentication") {
		t.Errorf("agent refused with %q", why)
	}
	select {
	case ev := <-f.events:
		t.Fatalf("sent %+v to a guest that refused us", ev)
	case <-time.After(300 * time.Millisecond):
	}
}

func waitLogLine(t *testing.T, logs <-chan string, want string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case line := <-logs:
			if strings.Contains(line, want) {
				return line
			}
		case <-deadline:
			t.Fatalf("no log line containing %q", want)
		}
	}
}

func waitRefusal(t *testing.T, f *fakeAgent) string {
	t.Helper()
	select {
	case why := <-f.refusals:
		return why
	case <-time.After(5 * time.Second):
		t.Fatal("the agent never refused a conn")
	}
	return ""
}
