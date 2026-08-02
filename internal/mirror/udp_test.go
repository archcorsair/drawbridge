package mirror

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/udpframe"
)

// fakeAgent speaks just enough of the transport protocol for mirror unit
// tests: 'E' replays a scripted snapshot then stays open; proto-17 'S'
// streams echo frames back uppercased with the peer preserved (playing the
// guest relay + server in one step); 'R' conns are parked silently.
type fakeAgent struct {
	ln        net.Listener
	listeners []listenerInfo

	// Phase 4.5 (docs/transport-auth.md §3.2): with secret set this agent
	// demands the Mac proof and answers with its own. answerWith mints the
	// answer from a different secret — a squatter that verified nothing.
	// closeAfterFrame hangs up the moment the hello lands, which is how a
	// secretful guest treats an unauthenticated peer (§7 row 1).
	secret          *transportauth.Secret
	answerWith      *transportauth.Secret
	closeAfterFrame bool

	refusals chan string   // why a conn was refused
	streams  chan *sConn   // accepted 'S' conns, post-handshake
	payloads chan []byte   // bytes an 'S' conn received after its header
	parked   chan net.Conn // 'R' and other parked conns
}

// sConn is an accepted 'S' conn and the header it opened with.
type sConn struct {
	c     net.Conn
	proto uint8
	port  uint16
}

func newFakeAgent(t *testing.T, listeners []listenerInfo) *fakeAgent {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAgent{
		ln:        ln,
		listeners: listeners,
		refusals:  make(chan string, 16),
		streams:   make(chan *sConn, 16),
		payloads:  make(chan []byte, 16),
		parked:    make(chan net.Conn, 16),
	}
	go a.serve()
	t.Cleanup(func() { ln.Close() })
	return a
}

// handshake is the agent half of the mutual proof. Reports false when the
// conn was refused (and closed).
func (a *fakeAgent) handshake(c net.Conn, frame [4]byte) bool {
	auth := frame[1]
	if a.secret == nil {
		if auth != transportauth.AuthNone {
			a.note("peer requires auth, this agent has no secret")
			c.Close()
			return false
		}
		return true
	}
	if auth != transportauth.AuthStaticHMACv1 {
		a.note("peer sent no authentication")
		c.Close()
		return false
	}
	var got [transportauth.ProofLen]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		c.Close()
		return false
	}
	if !transportauth.Verify(a.secret.MacProof(frame), got[:]) {
		a.note("invalid transport secret")
		c.Close()
		return false
	}
	answer := a.secret
	if a.answerWith != nil {
		answer = a.answerWith
	}
	p := answer.AgentProof(frame)
	if _, err := c.Write(p[:]); err != nil {
		c.Close()
		return false
	}
	return true
}

func (a *fakeAgent) note(why string) {
	select {
	case a.refusals <- why:
	default:
	}
}

func (a *fakeAgent) serve() {
	for {
		c, err := a.ln.Accept()
		if err != nil {
			return
		}
		go a.handle(c)
	}
}

func (a *fakeAgent) handle(c net.Conn) {
	var frame [4]byte // type frame: {type, auth, 0, 0}
	if _, err := io.ReadFull(c, frame[:]); err != nil {
		c.Close()
		return
	}
	if frame[2] != 0 || frame[3] != 0 {
		c.Close()
		return
	}
	if a.closeAfterFrame {
		a.note("closed right after the frame")
		c.Close()
		return
	}
	if !a.handshake(c, frame) {
		return
	}
	switch frame[0] {
	case 'E':
		enc := json.NewEncoder(c)
		enc.Encode(event{Op: "snapshot", Listeners: a.listeners})
		// Keep the session alive with pings; close on write error.
		for {
			time.Sleep(200 * time.Millisecond)
			if enc.Encode(event{Op: "ping"}) != nil {
				c.Close()
				return
			}
		}
	case 'S':
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[3] != 0 {
			c.Close()
			return
		}
		s := &sConn{c: c, proto: hdr[0], port: binary.BigEndian.Uint16(hdr[1:3])}
		select {
		case a.streams <- s:
		default:
		}
		if hdr[0] == 6 { // raw TCP splice: report what crosses, then echo it
			buf := make([]byte, 512)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					select {
					case a.payloads <- append([]byte(nil), buf[:n]...):
					default:
					}
					if _, err := c.Write(buf[:n]); err != nil {
						c.Close()
						return
					}
				}
				if err != nil {
					c.Close()
					return
				}
			}
		}
		var wmu sync.Mutex
		buf := make([]byte, udpframe.MaxPayload)
		for {
			peer, payload, err := udpframe.ReadFrame(c, buf)
			if err != nil {
				c.Close()
				return
			}
			if udpframe.WriteFrame(c, &wmu, peer, bytes.ToUpper(payload)) != nil {
				c.Close()
				return
			}
		}
	default: // 'R' etc: park silently
		select {
		case a.parked <- c:
		default:
		}
		io.Copy(io.Discard, c)
		c.Close()
	}
}

func waitFor(t *testing.T, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", desc)
}

// freeUDPPort finds a free port OUTSIDE the guest autobind range
// (32768-60999) — mirrors reject that range by design, and macOS hands out
// ephemeral ports from inside it, so :0 allocation won't do. The TCP side
// is checked too for the same-port coexistence test.
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	for p := 21001; p < 22000; p++ {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p})
		if err != nil {
			continue
		}
		ln, err := net.Listen("tcp4", udpAddr(uint16(p)))
		uc.Close()
		if err != nil {
			continue
		}
		ln.Close()
		return uint16(p)
	}
	t.Fatal("no free port outside the autobind range")
	return 0
}

func TestUDPMirrorRoundTripAndDemux(t *testing.T) {
	port := freeUDPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "udp", Port: port, Addr: "0.0.0.0"}})

	m := New(fa.ln.Addr().String(), "127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitFor(t, "udp mirror", func() bool { return m.Mirrors("udp", port) })

	dial := func() *net.UDPConn {
		t.Helper()
		c, err := net.Dial("udp4", udpAddr(port))
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UDPConn)
	}
	rt := func(c *net.UDPConn, msg, want string) {
		t.Helper()
		// The mirror's stream may still be dialing right after the bind:
		// retry, UDP-style.
		deadline := time.Now().Add(5 * time.Second)
		buf := make([]byte, 65536)
		for {
			if time.Now().After(deadline) {
				t.Fatalf("no %q echo", want)
			}
			c.Write([]byte(msg))
			c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, err := c.Read(buf); err == nil {
				if got := string(buf[:n]); got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
				return
			}
		}
	}

	c1, c2 := dial(), dial()
	defer c1.Close()
	defer c2.Close()
	rt(c1, "alpha", "ALPHA")
	rt(c2, "beta", "BETA")
	// Datagram boundaries survive: a multi-MTU payload comes back whole.
	// (8 kB, not 64 kB: macOS caps UDP sends at net.inet.udp.maxdgram,
	// 9216 by default — the codec's 65507 limit is proven in udpframe.)
	big := strings.Repeat("x", 8000)
	rt(c1, big, strings.ToUpper(big))
}

func TestUDPMirrorSkipsEphemeralRange(t *testing.T) {
	fa := newFakeAgent(t, []listenerInfo{
		{Proto: "udp", Port: 40000, Addr: "0.0.0.0"}, // autobind range
		{Proto: "udp", Port: 61010, Addr: "127.0.0.1"},
	})
	m := New(fa.ln.Addr().String(), "127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitFor(t, "non-ephemeral mirror", func() bool { return m.Mirrors("udp", 61010) })
	if m.Mirrors("udp", 40000) {
		t.Fatal("mirrored a port in the guest autobind range")
	}
}

func TestTCPAndUDPSamePortCoexist(t *testing.T) {
	port := freeUDPPort(t)
	fa := newFakeAgent(t, []listenerInfo{
		{Proto: "tcp", Port: port, Addr: "0.0.0.0"},
		{Proto: "udp", Port: port, Addr: "0.0.0.0"},
	})
	m := New(fa.ln.Addr().String(), "127.0.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)

	waitFor(t, "both mirrors", func() bool {
		return m.Mirrors("tcp", port) && m.Mirrors("udp", port)
	})
}

func udpAddr(port uint16) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port)))
}
