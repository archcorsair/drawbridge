package proxy

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/archcorsair/drawbridge/internal/udpframe"
)

type udpFlow struct {
	relay    *net.UDPConn
	lastSeen time.Time
}

type udpProxy struct {
	ln      *net.UDPConn // gateway:port — also the reply source (same-port scheme)
	backend *net.UDPAddr
	stats   *Stats

	mu     sync.Mutex
	flows  map[netip.AddrPort]*udpFlow // client -> relay socket
	closed bool
	stop   chan struct{}
}

// NewUDP listens on the gateway address and relays datagrams to backend,
// one relay socket per client so backend replies find their way back.
// Replies are written from the gateway listener itself, so the client sees
// source gateway:port and the BPF recvmsg hook can un-rewrite it statelessly.
// Idle flows expire (udpframe.FlowIdleTimeout) and the table is capped
// (udpframe.MaxFlows) — UDP has no FIN.
func NewUDP(listen netip.AddrPort, backend string, stats *Stats) (Proxy, error) {
	ba, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return nil, err
	}
	p := &udpProxy{ln: ln, backend: ba, stats: stats,
		flows: map[netip.AddrPort]*udpFlow{}, stop: make(chan struct{})}
	go p.readLoop()
	go p.sweepLoop()
	return p, nil
}

func (p *udpProxy) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, client, err := p.ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // listener closed
		}
		p.stats.UDPPackets.Add(1)
		relay := p.flow(client)
		if relay != nil {
			relay.Write(buf[:n])
		}
	}
}

func (p *udpProxy) flow(client netip.AddrPort) *net.UDPConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if f, ok := p.flows[client]; ok {
		f.lastSeen = time.Now()
		return f.relay
	}
	if len(p.flows) >= udpframe.MaxFlows {
		return nil // at cap: drop new-client datagrams
	}
	relay, err := net.DialUDP("udp", nil, p.backend)
	if err != nil {
		return nil
	}
	f := &udpFlow{relay: relay, lastSeen: time.Now()}
	p.flows[client] = f
	p.stats.UDPFlows.Add(1)
	go func() {
		rbuf := make([]byte, 65535)
		for {
			n, err := relay.Read(rbuf)
			if err != nil {
				return
			}
			p.mu.Lock()
			f.lastSeen = time.Now()
			p.mu.Unlock()
			p.ln.WriteToUDPAddrPort(rbuf[:n], client)
		}
	}()
	return relay
}

func (p *udpProxy) sweepLoop() {
	t := time.NewTicker(udpframe.FlowSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-t.C:
		}
		cutoff := time.Now().Add(-udpframe.FlowIdleTimeout)
		p.mu.Lock()
		for client, f := range p.flows {
			if f.lastSeen.Before(cutoff) {
				f.relay.Close() // unblocks the reader goroutine
				delete(p.flows, client)
				p.stats.UDPFlows.Add(-1)
			}
		}
		p.mu.Unlock()
	}
}

func (p *udpProxy) Addr() net.Addr { return p.ln.LocalAddr() }

func (p *udpProxy) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.stop)
	}
	for _, f := range p.flows {
		f.relay.Close()
	}
	p.stats.UDPFlows.Add(-int64(len(p.flows)))
	p.flows = map[netip.AddrPort]*udpFlow{}
	p.mu.Unlock()
	return p.ln.Close()
}
