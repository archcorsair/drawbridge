package proxy

import (
	"net"
	"net/netip"
	"sync"

	"github.com/archcorsair/drawbridge/internal/udpframe"
)

// udpStreamProxy is the Mac-backed gateway UDP proxy (docs/udp.md,
// outbound): datagrams from guest clients are framed onto one muxed
// transport stream per port; reply frames carry the client's AddrPort and
// are written from the gateway listener socket, so the BPF recvmsg
// un-rewrite stays stateless. The guest side keeps NO per-flow sockets —
// flow state lives on the Mac, the side that dials the real backend.
type udpStreamProxy struct {
	ln    *net.UDPConn
	dial  DialFunc
	stats *Stats

	mu     sync.Mutex
	cur    *udpStream
	closed bool
}

type udpStream struct {
	conn net.Conn
	wmu  sync.Mutex
}

// NewUDPStream listens on the gateway address and relays datagrams over a
// framed stream obtained from dial — the same seam TCP's Phase 3 backend
// got, except one stream serves every flow on the port. Activation is lazy
// (first datagram); a dead stream is dropped and the next datagram
// re-activates. If dial fails (no parked conn, Mac gone) the datagram is
// dropped — honest UDP.
func NewUDPStream(listen netip.AddrPort, dial DialFunc, stats *Stats) (Proxy, error) {
	ln, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(listen))
	if err != nil {
		return nil, err
	}
	p := &udpStreamProxy{ln: ln, dial: dial, stats: stats}
	go p.readLoop()
	return p, nil
}

func (p *udpStreamProxy) readLoop() {
	buf := make([]byte, udpframe.MaxPayload)
	for {
		n, client, err := p.ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // listener closed
		}
		p.stats.UDPPackets.Add(1)
		s := p.ensure()
		if s == nil {
			continue
		}
		if err := udpframe.WriteFrame(s.conn, &s.wmu, client, buf[:n]); err != nil {
			p.drop(s)
		}
	}
}

func (p *udpStreamProxy) ensure() *udpStream {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.cur != nil {
		return p.cur
	}
	c, err := p.dial()
	if err != nil {
		return nil
	}
	s := &udpStream{conn: c}
	p.cur = s
	go p.replyPump(s)
	return s
}

func (p *udpStreamProxy) replyPump(s *udpStream) {
	buf := make([]byte, udpframe.MaxPayload)
	for {
		peer, payload, err := udpframe.ReadFrame(s.conn, buf)
		if err != nil {
			p.drop(s)
			return
		}
		// Written from the gateway listener: the client sees source
		// gateway:P, un-rewritten to 127.0.0.1:P by the recvmsg hook.
		p.ln.WriteToUDPAddrPort(payload, peer)
	}
}

func (p *udpStreamProxy) drop(s *udpStream) {
	p.mu.Lock()
	if p.cur == s {
		p.cur = nil
	}
	p.mu.Unlock()
	s.conn.Close()
}

func (p *udpStreamProxy) Addr() net.Addr { return p.ln.LocalAddr() }

func (p *udpStreamProxy) Close() error {
	p.mu.Lock()
	p.closed = true
	s := p.cur
	p.cur = nil
	p.mu.Unlock()
	if s != nil {
		s.conn.Close()
	}
	return p.ln.Close()
}
