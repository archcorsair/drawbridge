// Untagged on purpose (see listen.go): these run on the Mac via
// `go test ./internal/...`, where the BPF-carrying files of this package are
// excluded by build tag.

package agent

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad prefix %q: %v", s, err)
	}
	return p
}

// The live guest layout: lo, eth0 (usernet), lima0 (vzNAT), docker0.
func TestPickVZNATGuestLayout(t *testing.T) {
	in := []ifaceAddr{
		{Index: 2, Name: "eth0", Prefix: pfx(t, "192.168.5.15/24")},
		{Index: 3, Name: "lima0", Prefix: pfx(t, "192.168.64.2/24")},
		{Index: 4, Name: "docker0", Prefix: pfx(t, "172.17.0.1/16")},
	}
	got, ok := pickVZNAT(in)
	if !ok || got.Addr().String() != "192.168.64.2" {
		t.Fatalf("pickVZNAT = %v, %v; want 192.168.64.2/24", got, ok)
	}
	h, ok := firstHost(got)
	if !ok || h.String() != "192.168.64.1" {
		t.Fatalf("firstHost = %v, %v; want 192.168.64.1", h, ok)
	}
}

func TestPickVZNATRules(t *testing.T) {
	cases := []struct {
		name string
		in   []ifaceAddr
		want string // "" = none
	}{
		{"none", nil, ""},
		{"usernet only", []ifaceAddr{{Index: 2, Prefix: pfx(t, "192.168.5.15/24")}}, ""},
		{"loopback skipped", []ifaceAddr{{Index: 1, Prefix: pfx(t, "127.0.0.1/8")}}, ""},
		{"link-local skipped", []ifaceAddr{{Index: 2, Prefix: pfx(t, "169.254.3.4/16")}}, ""},
		{"public skipped", []ifaceAddr{{Index: 2, Prefix: pfx(t, "93.184.216.34/24")}}, ""},
		{"v6 skipped", []ifaceAddr{{Index: 2, Prefix: pfx(t, "fd00::2/64")}}, ""},
		{"docker bridge gateway skipped", []ifaceAddr{{Index: 4, Prefix: pfx(t, "172.17.0.1/16")}}, ""},
		{"user bridge gateway skipped", []ifaceAddr{{Index: 9, Prefix: pfx(t, "172.20.0.1/16")}}, ""},
		{"non-gateway private v4 kept", []ifaceAddr{{Index: 9, Prefix: pfx(t, "172.17.0.5/16")}}, "172.17.0.5"},
		{"lowest index wins", []ifaceAddr{
			{Index: 7, Prefix: pfx(t, "10.9.9.9/24")},
			{Index: 3, Prefix: pfx(t, "192.168.64.2/24")},
		}, "192.168.64.2"},
		{"4-in-6 unmapped", []ifaceAddr{{Index: 3, Prefix: netip.PrefixFrom(netip.MustParseAddr("::ffff:192.168.64.7"), 24)}}, "192.168.64.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := pickVZNAT(c.in)
			if c.want == "" {
				if ok {
					t.Fatalf("pickVZNAT = %v, want none", got)
				}
				return
			}
			if !ok || got.Addr().String() != c.want {
				t.Fatalf("pickVZNAT = %v, %v; want %s", got, ok, c.want)
			}
		})
	}
}

func TestSourceAllow(t *testing.T) {
	a := newSourceAllow(nil)
	a.add(hostPrefix(netip.MustParseAddr("192.168.64.1"))) // the Mac
	yes := []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "192.168.64.1"}
	for _, s := range yes {
		if !a.allowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed(%s) = false, want true", s)
		}
	}
	no := []string{"192.168.64.2", "192.168.64.9", "172.17.0.1", "172.17.0.4", "10.0.0.1"}
	for _, s := range no {
		if a.allowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed(%s) = true, want false", s)
		}
	}
	if a.allowed(netip.Addr{}) {
		t.Error("allowed(invalid) = true, want false")
	}
}

func TestSourceAllowExtraCIDRs(t *testing.T) {
	extra, err := parseAllowCIDRs("172.17.0.0/16, 10.1.2.3")
	if err != nil {
		t.Fatalf("parseAllowCIDRs: %v", err)
	}
	a := newSourceAllow(extra)
	for _, s := range []string{"172.17.0.4", "172.17.9.9", "10.1.2.3"} {
		if !a.allowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed(%s) = false, want true", s)
		}
	}
	for _, s := range []string{"10.1.2.4", "192.168.64.9"} {
		if a.allowed(netip.MustParseAddr(s)) {
			t.Errorf("allowed(%s) = true, want false", s)
		}
	}
	// add is idempotent (the auto loop may re-add the Mac address).
	p := hostPrefix(netip.MustParseAddr("192.168.64.1"))
	a.add(p)
	n := len(a.prefixes)
	a.add(p)
	if len(a.prefixes) != n {
		t.Errorf("add duplicated prefix: %d → %d", n, len(a.prefixes))
	}
}

func TestParseAllowCIDRsErrors(t *testing.T) {
	if got, err := parseAllowCIDRs(""); err != nil || len(got) != 0 {
		t.Fatalf("parseAllowCIDRs(\"\") = %v, %v; want empty, nil", got, err)
	}
	for _, s := range []string{"nonsense", "10.0.0.0/64", "10.0.0.0/"} {
		if _, err := parseAllowCIDRs(s); err == nil {
			t.Errorf("parseAllowCIDRs(%q) = nil error, want error", s)
		}
	}
}

func TestRejectLimiter(t *testing.T) {
	r := newRejectLimiter(time.Minute)
	a := netip.MustParseAddr("172.17.0.4")
	b := netip.MustParseAddr("172.17.0.5")
	t0 := time.Unix(1000, 0)
	if !r.allow(a, t0) {
		t.Fatal("first line suppressed")
	}
	if r.allow(a, t0.Add(59*time.Second)) {
		t.Fatal("second line within the window emitted")
	}
	if !r.allow(b, t0.Add(time.Second)) {
		t.Fatal("other source suppressed")
	}
	if !r.allow(a, t0.Add(61*time.Second)) {
		t.Fatal("line after the window suppressed")
	}
}

// fakeConn carries a chosen RemoteAddr; Close is observable.
type fakeConn struct {
	net.Conn
	remote net.Addr
	closed chan struct{}
	once   sync.Once
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c *fakeConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type fakeListener struct {
	conns chan net.Conn
}

func (l *fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, errors.New("closed")
	}
	return c, nil
}
func (l *fakeListener) Close() error { return nil }
func (l *fakeListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 168, 64, 2), Port: 4777}
}

func tcpConn(ip string) *fakeConn {
	return &fakeConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 55555}, closed: make(chan struct{})}
}

func TestGuardedListenerDropsDisallowedSources(t *testing.T) {
	allow := newSourceAllow(nil)
	allow.add(hostPrefix(netip.MustParseAddr("192.168.64.1")))
	fl := &fakeListener{conns: make(chan net.Conn, 8)}
	var (
		mu    sync.Mutex
		lines []string
	)
	g := guard(fl, allow, func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, f)
	})
	now := time.Unix(2000, 0)
	g.now = func() time.Time { return now }

	container := tcpConn("172.17.0.4")   // dropped
	container2 := tcpConn("172.17.0.4")  // dropped, same source → no 2nd line
	guestSelf := tcpConn("192.168.64.2") // dropped: the guest's own vzNAT addr
	mac := tcpConn("192.168.64.1")       // allowed
	fl.conns <- container
	fl.conns <- container2
	fl.conns <- guestSelf
	fl.conns <- mac

	got, err := g.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != net.Conn(mac) {
		t.Fatalf("Accept returned %v, want the Mac conn", got.RemoteAddr())
	}
	for i, c := range []*fakeConn{container, container2, guestSelf} {
		select {
		case <-c.closed:
		default:
			t.Errorf("rejected conn %d (%s) was not closed", i, c.remote)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 2 { // 172.17.0.4 once (rate-limited), 192.168.64.2 once
		t.Fatalf("logged %d reject lines, want 2: %v", len(lines), lines)
	}
}

// A conn with no IP source (unix) is not the transport's to police.
func TestGuardedListenerAllowsNonIPSources(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 1)}
	g := guard(fl, newSourceAllow(nil), nil)
	c := &fakeConn{remote: &net.UnixAddr{Name: "/run/x.sock", Net: "unix"}, closed: make(chan struct{})}
	fl.conns <- c
	got, err := g.Accept()
	if err != nil || got != net.Conn(c) {
		t.Fatalf("Accept = %v, %v; want the unix conn", got, err)
	}
}

// Explicit endpoints bind synchronously, are served, and close cleanly; the
// harness's bare "127.0.0.1:0" spelling must keep working.
func TestListenTransportExplicit(t *testing.T) {
	served := make(chan string, 4)
	tl, err := ListenTransport("127.0.0.1:0", "", func(ln net.Listener) { served <- ln.Addr().String() }, func(string, ...any) {})
	if err != nil {
		t.Fatalf("ListenTransport: %v", err)
	}
	defer tl.Close()
	addrs := tl.Addrs()
	if len(addrs) != 1 {
		t.Fatalf("Addrs = %v, want one", addrs)
	}
	select {
	case got := <-served:
		if got != addrs[0] {
			t.Fatalf("served %s, bound %s", got, addrs[0])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener never served")
	}
	c, err := net.Dial("tcp", addrs[0])
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
}

func TestListenTransportBadSpecs(t *testing.T) {
	noop := func(net.Listener) {}
	if _, err := ListenTransport("127.0.0.1:0", "garbage", noop, nil); err == nil {
		t.Error("bad -transport-allow accepted")
	}
	if _, err := ListenTransport("not-an-endpoint", "", noop, nil); err == nil {
		t.Error("bad endpoint accepted")
	}
	if _, err := ListenTransport(",", "", noop, nil); err == nil {
		t.Error("empty endpoint list accepted")
	}
}
