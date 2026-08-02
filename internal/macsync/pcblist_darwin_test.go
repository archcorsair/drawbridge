package macsync

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func listen(t *testing.T, network, addr string) (net.Listener, uint16) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).AddrPort().Port()
}

func lookup(t *testing.T, port uint16) (Listener, bool) {
	t.Helper()
	ls, err := Listeners()
	if err != nil {
		t.Fatalf("Listeners: %v", err)
	}
	for _, l := range ls {
		if l.Port == port {
			return l, true
		}
	}
	return Listener{}, false
}

func TestFindsLoopbackV4Listener(t *testing.T) {
	_, port := listen(t, "tcp4", "127.0.0.1:0")
	l, ok := lookup(t, port)
	if !ok {
		t.Fatalf("listener on 127.0.0.1:%d not reported", port)
	}
	if want := netip.MustParseAddr("127.0.0.1"); l.Addr != want {
		t.Fatalf("addr = %s, want %s", l.Addr, want)
	}
	if l.Proto != "tcp" {
		t.Fatalf("proto = %q, want tcp", l.Proto)
	}
}

func TestFindsWildcardV4Listener(t *testing.T) {
	_, port := listen(t, "tcp4", "0.0.0.0:0")
	l, ok := lookup(t, port)
	if !ok {
		t.Fatalf("listener on 0.0.0.0:%d not reported", port)
	}
	if want := netip.MustParseAddr("0.0.0.0"); l.Addr != want {
		t.Fatalf("addr = %s, want %s", l.Addr, want)
	}
}

func TestFindsDualStackListener(t *testing.T) {
	_, port := listen(t, "tcp", ":0")
	l, ok := lookup(t, port)
	if !ok {
		t.Fatalf("dual-stack listener on :%d not reported", port)
	}
	v6any := netip.MustParseAddr("::")
	v4any := netip.MustParseAddr("0.0.0.0")
	if l.Addr != v6any && l.Addr != v4any {
		t.Fatalf("addr = %s, want %s or %s", l.Addr, v6any, v4any)
	}
	t.Logf("dual-stack listener reported as %s", l.Addr)
}

func TestFindsV6LoopbackListener(t *testing.T) {
	_, port := listen(t, "tcp6", "[::1]:0")
	l, ok := lookup(t, port)
	if !ok {
		t.Fatalf("listener on [::1]:%d not reported", port)
	}
	if want := netip.MustParseAddr("::1"); l.Addr != want {
		t.Fatalf("addr = %s, want %s", l.Addr, want)
	}
}

func TestListenerDisappearsOnClose(t *testing.T) {
	ln, port := listen(t, "tcp4", "127.0.0.1:0")
	if _, ok := lookup(t, port); !ok {
		t.Fatalf("listener on :%d not reported while open", port)
	}
	ln.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := lookup(t, port); !ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener on :%d still reported after close", port)
}

// --- synthetic pcblist_n fixtures ------------------------------------------
//
// The live tests above prove the struct offsets against the running kernel;
// these prove the walk's framing rules — above all that a buffer missing its
// trailing xinpgen (a read torn by socket churn) is an error, never a
// silently smaller listener set. That silent partial is how a healthy daemon
// once advertised an empty set for 28s (2026-08-01).

type fxSocket struct {
	port  uint16
	state int32
	addr  netip.Addr
}

func pcblistFixture(count uint32, socks []fxSocket, trailer bool) []byte {
	b := make([]byte, 24) // leading xinpgen
	binary.LittleEndian.PutUint32(b, 24)
	binary.LittleEndian.PutUint32(b[4:], count)
	for _, s := range socks {
		inp := make([]byte, inpLaddrOff+16)
		binary.LittleEndian.PutUint32(inp, uint32(len(inp)))
		binary.LittleEndian.PutUint32(inp[4:], xsoInpcb)
		binary.BigEndian.PutUint16(inp[inpLportOff:], s.port)
		if s.addr.Is4() {
			a := s.addr.As4()
			copy(inp[inpLaddrOff+12:], a[:])
		} else {
			inp[inpVflagOff] = inpIPv6
			a := s.addr.As16()
			copy(inp[inpLaddrOff:], a[:])
		}
		b = append(b, inp...)
		tcp := make([]byte, tcpStateOff+4)
		binary.LittleEndian.PutUint32(tcp, uint32(len(tcp)))
		binary.LittleEndian.PutUint32(tcp[4:], xsoTcpcb)
		binary.LittleEndian.PutUint32(tcp[tcpStateOff:], uint32(s.state))
		b = append(b, tcp...)
	}
	if trailer {
		tr := make([]byte, 24)
		binary.LittleEndian.PutUint32(tr, 24)
		b = append(b, tr...)
	}
	return b
}

func TestParsePcblistNFixture(t *testing.T) {
	b := pcblistFixture(3, []fxSocket{
		{port: 8080, state: tcpsListen, addr: netip.MustParseAddr("127.0.0.1")},
		{port: 55000, state: 4 /* ESTABLISHED */, addr: netip.MustParseAddr("127.0.0.1")},
		{port: 9090, state: tcpsListen, addr: netip.MustParseAddr("::")},
	}, true)
	ls, err := parsePcblistN(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []Listener{
		{Proto: "tcp", Port: 8080, Addr: netip.MustParseAddr("127.0.0.1")},
		{Proto: "tcp", Port: 9090, Addr: netip.MustParseAddr("::")},
	}
	if len(ls) != len(want) {
		t.Fatalf("listeners = %+v, want %+v", ls, want)
	}
	for i := range want {
		if ls[i] != want[i] {
			t.Fatalf("listener[%d] = %+v, want %+v", i, ls[i], want[i])
		}
	}
}

func TestParsePcblistNTruncatedIsAnError(t *testing.T) {
	full := pcblistFixture(2, []fxSocket{
		{port: 8080, state: tcpsListen, addr: netip.MustParseAddr("127.0.0.1")},
		{port: 9090, state: tcpsListen, addr: netip.MustParseAddr("127.0.0.1")},
	}, true)
	// Every shape churn can tear the buffer into: trailer gone, cut inside
	// a block, and nothing but the header left despite a nonzero count.
	cuts := map[string][]byte{
		"trailer missing": full[:len(full)-24],
		"cut mid-block":   full[:len(full)-24-13],
		"header only":     full[:24],
	}
	for name, b := range cuts {
		ls, err := parsePcblistN(b)
		if !errors.Is(err, errTruncated) {
			t.Errorf("%s: got %d listeners, err %v — want errTruncated", name, len(ls), err)
		}
	}
}

func TestParsePcblistNHeaderOnlyZeroCountIsEmpty(t *testing.T) {
	// n == 0 legitimately emits a lone xinpgen and no trailer: empty set,
	// not an error.
	ls, err := parsePcblistN(pcblistFixture(0, nil, false))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ls) != 0 {
		t.Fatalf("listeners = %+v, want none", ls)
	}
}

// A non-LISTEN socket must never be reported — guards the t_state offset.
func TestEstablishedConnNotReported(t *testing.T) {
	ln, port := listen(t, "tcp4", "127.0.0.1:0")
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	clientPort := c.LocalAddr().(*net.TCPAddr).AddrPort().Port()
	if clientPort == port {
		t.Fatalf("client picked the listener port?")
	}
	if _, ok := lookup(t, clientPort); ok {
		t.Fatalf("established client socket :%d reported as listener", clientPort)
	}
}
