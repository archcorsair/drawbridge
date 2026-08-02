package proxy

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/udpframe"
)

// fakeMacEnd echoes frames back with "echo:" prepended, preserving the
// peer — the Mac-side flow handler's role, minus real sockets.
func fakeMacEnd(t *testing.T, c net.Conn) {
	t.Helper()
	go func() {
		var wmu sync.Mutex
		buf := make([]byte, udpframe.MaxPayload)
		for {
			peer, payload, err := udpframe.ReadFrame(c, buf)
			if err != nil {
				return
			}
			reply := append([]byte("echo:"), payload...)
			if err := udpframe.WriteFrame(c, &wmu, peer, reply); err != nil {
				return
			}
		}
	}()
}

func loopback(t *testing.T) netip.AddrPort {
	t.Helper()
	return netip.MustParseAddrPort("127.0.0.1:0")
}

func TestUDPStreamLazyActivationAndDemux(t *testing.T) {
	var dials atomic.Int32
	stats := &Stats{}
	p, err := NewUDPStream(loopback(t), func() (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		fakeMacEnd(t, b)
		return a, nil
	}, stats)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if dials.Load() != 0 {
		t.Fatal("stream dialed eagerly; must be lazy")
	}

	gw := p.Addr().String()
	send := func(c *net.UDPConn, msg string) {
		t.Helper()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	recv := func(c *net.UDPConn) string {
		t.Helper()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65536)
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		return string(buf[:n])
	}

	// Two clients on one port: replies must route back per-client.
	c1, err := net.Dial("udp", gw)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := net.Dial("udp", gw)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	send(c1.(*net.UDPConn), "one")
	send(c2.(*net.UDPConn), "two")
	if got := recv(c1.(*net.UDPConn)); got != "echo:one" {
		t.Fatalf("c1 got %q", got)
	}
	if got := recv(c2.(*net.UDPConn)); got != "echo:two" {
		t.Fatalf("c2 got %q", got)
	}
	if dials.Load() != 1 {
		t.Fatalf("dials = %d, want 1 (one muxed stream)", dials.Load())
	}
	if got := stats.UDPPackets.Load(); got != 2 {
		t.Fatalf("UDPPackets = %d, want 2", got)
	}
}

func TestUDPStreamReactivatesAfterStreamDeath(t *testing.T) {
	var mu sync.Mutex
	var ends []net.Conn
	var dials atomic.Int32
	p, err := NewUDPStream(loopback(t), func() (net.Conn, error) {
		dials.Add(1)
		a, b := net.Pipe()
		fakeMacEnd(t, b)
		mu.Lock()
		ends = append(ends, a)
		mu.Unlock()
		return a, nil
	}, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	c, err := net.Dial("udp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uc := c.(*net.UDPConn)

	uc.Write([]byte("a"))
	uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "echo:a" {
		t.Fatalf("first round-trip: %v %q", err, buf[:n])
	}

	// Kill the stream; the death is noticed by the reply pump.
	mu.Lock()
	ends[0].Close()
	mu.Unlock()

	// Datagrams may be dropped during the gap (UDP); retry until the
	// re-activated stream answers.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("no round-trip after stream death")
		}
		uc.Write([]byte("b"))
		uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, err := uc.Read(buf); err == nil && string(buf[:n]) == "echo:b" {
			break
		}
	}
	if dials.Load() < 2 {
		t.Fatalf("dials = %d, want >= 2 (re-activation)", dials.Load())
	}
}

func TestUDPStreamSurvivesDialFailure(t *testing.T) {
	fail := atomic.Bool{}
	fail.Store(true)
	p, err := NewUDPStream(loopback(t), func() (net.Conn, error) {
		if fail.Load() {
			return nil, fmt.Errorf("no parked conn")
		}
		a, b := net.Pipe()
		fakeMacEnd(t, b)
		return a, nil
	}, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	c, err := net.Dial("udp", p.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	uc := c.(*net.UDPConn)

	// Dropped, not an error, while the Mac is unreachable.
	uc.Write([]byte("void"))
	uc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	if _, err := uc.Read(buf); err == nil {
		t.Fatal("got a reply with no backend")
	}

	fail.Store(false)
	uc.Write([]byte("back"))
	uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != "echo:back" {
		t.Fatalf("after recovery: %v %q", err, buf[:n])
	}
}

func TestUDPRelayFlowExpiryAndCap(t *testing.T) {
	defer func(it, si time.Duration, mf int) {
		udpframe.FlowIdleTimeout, udpframe.FlowSweepInterval, udpframe.MaxFlows = it, si, mf
	}(udpframe.FlowIdleTimeout, udpframe.FlowSweepInterval, udpframe.MaxFlows)
	udpframe.FlowIdleTimeout = 150 * time.Millisecond
	udpframe.FlowSweepInterval = 50 * time.Millisecond
	udpframe.MaxFlows = 2

	// Backend echoes datagrams.
	be, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := be.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			be.WriteToUDPAddrPort(bytes.ToUpper(buf[:n]), from)
		}
	}()

	stats := &Stats{}
	p, err := NewUDP(loopback(t), be.LocalAddr().String(), stats)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	dial := func() *net.UDPConn {
		t.Helper()
		c, err := net.Dial("udp", p.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UDPConn)
	}
	rt := func(c *net.UDPConn, msg, want string) bool {
		t.Helper()
		c.Write([]byte(msg))
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		return err == nil && string(buf[:n]) == want
	}

	c1, c2, c3 := dial(), dial(), dial()
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()
	if !rt(c1, "a", "A") || !rt(c2, "b", "B") {
		t.Fatal("first two flows must round-trip")
	}
	if stats.UDPFlows.Load() != 2 {
		t.Fatalf("UDPFlows = %d, want 2", stats.UDPFlows.Load())
	}
	// Third client is over cap: dropped.
	if rt(c3, "c", "C") {
		t.Fatal("flow over cap served")
	}
	// After idle expiry the table drains and new flows are admitted again.
	deadline := time.Now().Add(3 * time.Second)
	for stats.UDPFlows.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("flows never expired: %d", stats.UDPFlows.Load())
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !rt(c3, "c", "C") {
		t.Fatal("new flow after expiry must round-trip")
	}
}
