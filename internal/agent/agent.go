//go:build linux

// Package agent is the guest-side drawbridge daemon: it owns the BPF gateway
// programs, the decision maps, and the per-port gateway proxies, keeping the
// three consistent. In Phase 1 the map/proxy registry is driven by the test
// harness (or the control socket); Phases 2–3 replace those drivers with
// kernel listener tracking and the Mac-side sync over vsock.
package agent

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/archcorsair/drawbridge/internal/bpf"
	"github.com/archcorsair/drawbridge/internal/proxy"
)

type portID struct {
	proto uint8
	port  uint16
}

type macEntry struct {
	key   bpf.PortKey
	proxy proxy.Proxy
}

type Agent struct {
	gw    *bpf.Gateway
	tr    *bpf.Tracker
	trRd  *ringbuf.Reader
	Hub   *TrackerHub
	Stats *proxy.Stats
	pool  *dialPool // parked Mac reverse-stream ('D') conns

	// SecretFile is the transport secret's path (docs/transport-auth.md §5).
	// Empty, or a path with no file, means unauthenticated mode: today's
	// wire, and a loud startup line. Re-read per accepted conn so rotation
	// heals live.
	SecretFile string

	authMu   sync.Mutex
	authLast map[authLogKey]time.Time // refusal-log throttle, per (cause, source)

	logf func(string, ...any) // test seam; nil ⇒ log.Printf
	now  func() time.Time     // test seam; nil ⇒ time.Now

	mu        sync.Mutex
	mac       map[portID]*macEntry
	guest     map[portID]bpf.PortKey
	syncOwned map[portID]struct{} // mac entries owned by the 'M' sync session

	syncSession sync.Mutex // serializes 'M' sessions incl. their cleanup
	syncMu      sync.Mutex
	syncConn    net.Conn // active 'M' conn, closed when a new one arrives

	resMu   sync.Mutex
	resConn *reserveChan // parked 'R' conn for bind reservations
}

// New loads and attaches the BPF gateway + listener tracker on cgroupPath
// (normally /sys/fs/cgroup), then seeds pre-existing listeners from
// /proc/net. Attach-then-scan ordering avoids missing listeners created
// in between; put-if-absent avoids double counting.
func New(cgroupPath string) (*Agent, error) {
	gw, err := bpf.LoadAndAttach(cgroupPath)
	if err != nil {
		return nil, err
	}
	tr, err := bpf.LoadTracker(gw)
	if err != nil {
		gw.Close()
		return nil, err
	}
	rd, err := tr.EventReader()
	if err != nil {
		tr.Close()
		gw.Close()
		return nil, err
	}
	a := &Agent{
		gw:        gw,
		tr:        tr,
		trRd:      rd,
		Hub:       NewTrackerHub(),
		Stats:     &proxy.Stats{},
		pool:      newDialPool(),
		mac:       map[portID]*macEntry{},
		guest:     map[portID]bpf.PortKey{},
		syncOwned: map[portID]struct{}{},
	}
	go a.Hub.RunTracker(rd)
	a.seed()
	return a, nil
}

func (a *Agent) seed() {
	for _, l := range scanProcNet() {
		proto := bpf.ProtoTCP
		if l.Proto == "udp" {
			proto = bpf.ProtoUDP
		}
		k := bpf.KeyFor(proto, l.Addr, l.Port)
		var cnt uint32
		if err := a.gw.GuestPorts().Lookup(&k, &cnt); err != nil {
			a.gw.GuestPorts().Put(&k, uint32(1))
		}
		a.Hub.apply("add", l)
	}
}

// HasGuestPort reports whether the exact (proto, addr, port) key is present
// in guest_ports (test helper).
func (a *Agent) HasGuestPort(proto uint8, addr netip.Addr, port uint16) bool {
	k := bpf.KeyFor(proto, addr, port)
	var cnt uint32
	return a.gw.GuestPorts().Lookup(&k, &cnt) == nil
}

// AddMacPort registers a Mac-owned listener: it starts the gateway proxy for
// the port, then adds the mac_ports map entry. Proxy first, map second — the
// moment the map entry exists, connects get rewritten to the gateway.
// bindAddr is the (Mac-side) bind scope; Phase 1 harness uses 0.0.0.0/::.
// backend is where the proxy delivers traffic; empty means the real Mac —
// TCP flows then ride a parked reverse-stream conn (Phase 3). The harness
// and testctl pass an explicit in-guest dummy instead.
func (a *Agent) AddMacPort(proto uint8, port uint16, bindAddr netip.Addr, backend string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := portID{proto, port}
	if _, ok := a.mac[id]; ok {
		return fmt.Errorf("mac port %d/%d already registered", proto, port)
	}
	gwAddr := netip.AddrPortFrom(netip.MustParseAddr(bpf.GatewayV4), port)
	var (
		p   proxy.Proxy
		err error
	)
	switch proto {
	case bpf.ProtoTCP:
		dial := a.macDialer(proto, port)
		if backend != "" {
			dial = proxy.Backend("tcp", backend)
		}
		p, err = proxy.NewTCP(gwAddr, dial, a.Stats)
	case bpf.ProtoUDP:
		if backend == "" {
			// Real Mac backend: one framed stream per port over a parked
			// 'D' conn, activated lazily on the first datagram (docs/udp.md).
			p, err = proxy.NewUDPStream(gwAddr, a.macDialer(proto, port), a.Stats)
		} else {
			p, err = proxy.NewUDP(gwAddr, backend, a.Stats)
		}
	default:
		return fmt.Errorf("unknown proto %d", proto)
	}
	if err != nil {
		return fmt.Errorf("gateway listener %s: %w", gwAddr, err)
	}
	k := bpf.KeyFor(proto, bindAddr, port)
	if err := a.gw.MacPorts().Put(&k, uint32(1)); err != nil {
		p.Close()
		return fmt.Errorf("mac_ports put: %w", err)
	}
	a.mac[id] = &macEntry{key: k, proxy: p}
	return nil
}

// RemoveMacPort deletes the map entry first (stop steering traffic), then
// closes the proxy listener.
func (a *Agent) RemoveMacPort(proto uint8, port uint16) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := portID{proto, port}
	e, ok := a.mac[id]
	if !ok {
		return fmt.Errorf("mac port %d/%d not registered", proto, port)
	}
	err := a.gw.MacPorts().Delete(&e.key)
	e.proxy.Close()
	delete(a.mac, id)
	delete(a.syncOwned, id)
	return err
}

// AddGuestPort records a guest listener so loopback connects to it stay
// native. (Phase 2 populates this from fexit listener tracking.)
func (a *Agent) AddGuestPort(proto uint8, port uint16, bindAddr netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := portID{proto, port}
	if _, ok := a.guest[id]; ok {
		return fmt.Errorf("guest port %d/%d already registered", proto, port)
	}
	k := bpf.KeyFor(proto, bindAddr, port)
	if err := a.gw.GuestPorts().Put(&k, uint32(1)); err != nil {
		return fmt.Errorf("guest_ports put: %w", err)
	}
	a.guest[id] = k
	return nil
}

func (a *Agent) RemoveGuestPort(proto uint8, port uint16) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := portID{proto, port}
	k, ok := a.guest[id]
	if !ok {
		return fmt.Errorf("guest port %d/%d not registered", proto, port)
	}
	err := a.gw.GuestPorts().Delete(&k)
	delete(a.guest, id)
	return err
}

// Close tears down proxies, map entries, links, and programs.
func (a *Agent) Close() error {
	a.mu.Lock()
	for _, e := range a.mac {
		e.proxy.Close()
	}
	a.mac = map[portID]*macEntry{}
	a.guest = map[portID]bpf.PortKey{}
	a.syncOwned = map[portID]struct{}{}
	a.mu.Unlock()
	a.pool.close()
	a.resMu.Lock()
	if a.resConn != nil {
		a.resConn.c.Close()
		a.resConn = nil
	}
	a.resMu.Unlock()
	if a.trRd != nil {
		a.trRd.Close()
	}
	if a.tr != nil {
		a.tr.Close()
	}
	return a.gw.Close()
}
