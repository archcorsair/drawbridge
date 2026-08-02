// Transport bind scope (docs/transport.md §2.4). Deliberately NOT
// linux-tagged, unlike the rest of this package: the interface-selection and
// source-allowlist logic is pure net/netip and its unit tests run in
// `go test ./internal/...` on the Mac, where the BPF-carrying files are
// excluded by build tag.

package agent

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/archcorsair/drawbridge/internal/transport"
)

// TransportAuto is the -transport value that binds the guest loopback
// immediately and the vzNAT interface as soon as it appears. It replaced a
// wildcard ":4777" default, which put the transport on every docker bridge
// gateway in the guest — any container could dial it and speak the protocol.
const TransportAuto = "auto"

// DefaultTransportPort is the port "auto" binds on both addresses.
const DefaultTransportPort = 4777

// vzNAT bind retry schedule: the interface is DHCP-configured and may not
// exist yet when the agent starts.
const (
	vznatFastDelay   = 2 * time.Second
	vznatFastRetries = 30 // ~1 min of fast attempts
	vznatSlowDelay   = 30 * time.Second
)

// rejectLogEvery rate-limits the "dropped conn" line, per source IP.
const rejectLogEvery = time.Minute

// usernet is Lima's outbound-only gvisor subnet (guest eth0). It is never the
// host-reachable address — the same skip limaaddr.guestIP applies Mac-side.
var usernet = netip.MustParsePrefix("192.168.5.0/24")

// ifaceAddr is one interface address considered for the vzNAT bind: the
// address together with its on-link prefix, plus the interface it came from.
type ifaceAddr struct {
	Index  int
	Name   string
	Prefix netip.Prefix
}

// pickVZNAT applies the guest-side twin of limaaddr.guestIP's rule: a private
// IPv4 that is not in Lima's usernet subnet. It adds one guest-only
// discriminator the Mac-side rule does not need: the guest runs docker, whose
// bridges (docker0 172.17.0.1, br-*) are private v4 outside 192.168.5.0/24
// and would otherwise qualify — binding the transport onto a bridge gateway
// is precisely the hole this file closes. A bridge holds the FIRST HOST
// ADDRESS of its own subnet; the vzNAT guest address never does, because
// macOS's side of the NAT holds it. Ties break on the lowest interface index
// (Lima's NICs predate any container bridge).
func pickVZNAT(addrs []ifaceAddr) (netip.Prefix, bool) {
	var best netip.Prefix
	bestIdx := 0
	for _, a := range addrs {
		if !a.Prefix.IsValid() {
			continue
		}
		ip := a.Prefix.Addr().Unmap()
		if !ip.Is4() || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if usernet.Contains(ip) {
			continue
		}
		if h, ok := firstHost(a.Prefix); ok && ip == h {
			continue // subnet gateway → a bridge we own, not a way to the Mac
		}
		if !best.IsValid() || a.Index < bestIdx {
			best, bestIdx = netip.PrefixFrom(ip, a.Prefix.Bits()), a.Index
		}
	}
	return best, best.IsValid()
}

// firstHost is the first usable address of p (network + 1): the Mac's side of
// the vzNAT NAT (the ".1"), and equally the address a linux bridge gives
// itself on the subnet it gateways.
func firstHost(p netip.Prefix) (netip.Addr, bool) {
	m := p.Masked()
	if !m.IsValid() {
		return netip.Addr{}, false
	}
	h := m.Addr().Next()
	if !h.IsValid() {
		return netip.Addr{}, false
	}
	return h, true
}

// hostPrefix is the single-address prefix for ip.
func hostPrefix(ip netip.Addr) netip.Prefix {
	return netip.PrefixFrom(ip, ip.BitLen())
}

// vznatPrefix discovers the guest's vzNAT address from the live interface
// list. Interfaces without addresses (or with unparsable ones) are skipped.
func vznatPrefix() (netip.Prefix, bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return netip.Prefix{}, false
	}
	var cands []ifaceAddr
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			ones, _ := n.Mask.Size()
			ip = ip.Unmap()
			if ip.Is4() && ones > 32 {
				ones -= 96 // 4-in-6 mask on a v4 address
			}
			cands = append(cands, ifaceAddr{Index: i.Index, Name: i.Name, Prefix: netip.PrefixFrom(ip, ones)})
		}
	}
	return pickVZNAT(cands)
}

// sourceAllow decides which peers may speak the transport protocol. Loopback
// is always allowed (Lima's SSH forward terminates at sshd, which dials
// 127.0.0.1); the vzNAT subnet's first host address — the Mac — is added when
// discovered; -transport-allow adds the rest.
//
// This is belt-and-suspenders on top of the bind scope: a later `bridged`
// network, or a second Lima VM on the same vmnet, would land inside the vzNAT
// subnet and reach the vzNAT listener.
type sourceAllow struct {
	mu       sync.RWMutex
	prefixes []netip.Prefix
}

func newSourceAllow(extra []netip.Prefix) *sourceAllow {
	return &sourceAllow{prefixes: append([]netip.Prefix(nil), extra...)}
}

func (s *sourceAllow) add(p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.prefixes {
		if e == p {
			return
		}
	}
	s.prefixes = append(s.prefixes, p)
}

func (s *sourceAllow) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *sourceAllow) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []string{"loopback"}
	for _, p := range s.prefixes {
		out = append(out, p.String())
	}
	return strings.Join(out, ",")
}

// parseAllowCIDRs parses the -transport-allow value: comma-separated CIDRs.
// A bare address is accepted as its single-address prefix.
func parseAllowCIDRs(spec string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(spec, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		ip, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("transport-allow %q: not a CIDR or address", f)
		}
		out = append(out, hostPrefix(ip.Unmap()))
	}
	return out, nil
}

// rejectLimiter rate-limits log lines per source IP. A scanner must not be
// able to fill the journal.
type rejectLimiter struct {
	mu    sync.Mutex
	every time.Duration
	last  map[netip.Addr]time.Time
}

func newRejectLimiter(every time.Duration) *rejectLimiter {
	return &rejectLimiter{every: every, last: map[netip.Addr]time.Time{}}
}

// allow reports whether a line should be emitted for ip at now, and records
// the decision.
func (r *rejectLimiter) allow(ip netip.Addr, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.last[ip]; ok && now.Sub(t) < r.every {
		return false
	}
	if len(r.last) > 1024 { // unbounded sources must not grow the map forever
		for k, t := range r.last {
			if now.Sub(t) >= r.every {
				delete(r.last, k)
			}
		}
	}
	r.last[ip] = now
	return true
}

// peerIP extracts the source address of an accepted conn. Non-IP conns (unix)
// report false and are allowed: their access control is the filesystem's.
func peerIP(c net.Conn) (netip.Addr, bool) {
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok || a == nil {
		return netip.Addr{}, false
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// guardedListener drops conns from disallowed sources immediately after
// accept, before any protocol byte is read. It is a net.Listener so the
// agent's dispatch (ServeTransport) is untouched.
type guardedListener struct {
	net.Listener
	allow *sourceAllow
	limit *rejectLimiter
	logf  func(string, ...any)
	now   func() time.Time
}

func guard(ln net.Listener, allow *sourceAllow, logf func(string, ...any)) *guardedListener {
	return &guardedListener{Listener: ln, allow: allow, limit: newRejectLimiter(rejectLogEvery), logf: logf, now: time.Now}
}

func (g *guardedListener) Accept() (net.Conn, error) {
	for {
		c, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, ok := peerIP(c)
		if !ok || g.allow.allowed(ip) {
			return c, nil
		}
		c.Close()
		if g.limit.allow(ip, g.now()) && g.logf != nil {
			g.logf("drawbridge-agent: transport: rejected conn from %s on %s (allowed: %s; widen with -transport-allow)",
				ip, g.Listener.Addr(), g.allow)
		}
	}
}

// TransportListeners is the set of bound transport listeners plus the
// background vzNAT bind retry.
type TransportListeners struct {
	allow *sourceAllow
	serve func(net.Listener)
	logf  func(string, ...any)

	mu     sync.Mutex
	lns    []net.Listener
	closed bool
	done   chan struct{}
}

// ListenTransport binds the agent's transport listeners for spec and serves
// each one with serve (normally Agent.ServeTransport, which already takes a
// listener — no protocol changes here).
//
// spec is either TransportAuto (loopback now + vzNAT when it appears) or a
// comma-separated list of endpoint strings, each bound synchronously;
// "-transport :4777" therefore restores the old wildcard for debugging, with
// the source allowlist still dropping strangers post-accept.
//
// allowSpec is the -transport-allow value (comma-separated CIDRs) added to
// the built-in allowlist: guest loopback, and the Mac's address on the vzNAT
// subnet.
func ListenTransport(spec, allowSpec string, serve func(net.Listener), logf func(string, ...any)) (*TransportListeners, error) {
	extra, err := parseAllowCIDRs(allowSpec)
	if err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	t := &TransportListeners{
		allow: newSourceAllow(extra),
		serve: serve,
		logf:  logf,
		done:  make(chan struct{}),
	}
	// Seed the Mac's source address for every mode, not just auto: an
	// explicit or wildcard -transport must stay reachable from the Mac.
	if p, ok := vznatPrefix(); ok {
		if h, ok := firstHost(p); ok {
			t.allow.add(hostPrefix(h))
		}
	}
	if strings.TrimSpace(spec) == TransportAuto {
		port := strconv.Itoa(DefaultTransportPort)
		ln, err := transport.Listen(net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			return nil, fmt.Errorf("loopback transport listen: %w", err)
		}
		t.start(ln, "loopback")
		go t.autoVZNAT(port)
		return t, nil
	}
	for _, ep := range strings.Split(spec, ",") {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		ln, err := transport.Listen(ep)
		if err != nil {
			t.Close()
			return nil, fmt.Errorf("transport listen %s: %w", ep, err)
		}
		t.start(ln, "explicit")
	}
	if len(t.Addrs()) == 0 {
		return nil, errors.New("transport: no endpoints in -transport")
	}
	return t, nil
}

// autoVZNAT binds the vzNAT address as soon as the interface exists: fast
// retries for the first minute, then a slow poll forever (the VM can gain the
// interface at any time; the loopback listener keeps the forwarder path
// working meanwhile).
func (t *TransportListeners) autoVZNAT(port string) {
	for i := 0; ; i++ {
		if p, ok := vznatPrefix(); ok {
			ep := net.JoinHostPort(p.Addr().String(), port)
			ln, err := transport.Listen(ep)
			if err == nil {
				if h, ok := firstHost(p); ok {
					t.allow.add(hostPrefix(h))
				}
				if !t.start(ln, "vzNAT") {
					ln.Close()
				}
				return
			}
			t.logf("drawbridge-agent: transport: vzNAT listen %s failed (%v), retrying", ep, err)
		}
		if i == vznatFastRetries {
			t.logf("drawbridge-agent: transport: still no vzNAT interface after %s — only the guest loopback listener is up (Mac reaches it via the Lima SSH forward)",
				time.Duration(vznatFastRetries)*vznatFastDelay)
		}
		d := vznatFastDelay
		if i >= vznatFastRetries {
			d = vznatSlowDelay
		}
		tm := time.NewTimer(d)
		select {
		case <-t.done:
			tm.Stop()
			return
		case <-tm.C:
		}
	}
}

// start records ln, logs it once, and serves it behind the source guard.
func (t *TransportListeners) start(ln net.Listener, why string) bool {
	g := guard(ln, t.allow, t.logf)
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	t.lns = append(t.lns, g)
	t.mu.Unlock()
	t.logf("drawbridge-agent: transport listening on %s (%s; sources: %s)", ln.Addr(), why, t.allow)
	go t.serve(g)
	return true
}

// Addrs reports the bound listener addresses (test/diagnostic helper).
func (t *TransportListeners) Addrs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.lns))
	for _, ln := range t.lns {
		out = append(out, ln.Addr().String())
	}
	return out
}

// Close stops the retry loop and closes every bound listener.
func (t *TransportListeners) Close() error {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		close(t.done)
	}
	lns := t.lns
	t.lns = nil
	t.mu.Unlock()
	var err error
	for _, ln := range lns {
		if e := ln.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}
