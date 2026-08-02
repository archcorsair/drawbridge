package proxy

import (
	"net"
	"net/netip"
	"sync"
)

type tcpProxy struct {
	ln    *net.TCPListener
	dial  DialFunc
	stats *Stats
	wg    sync.WaitGroup
}

// NewTCP listens on the gateway address and relays each accepted connection
// to the backend dial gives. The listener must be up BEFORE the BPF map
// entry is added — otherwise a racing connect gets rewritten to a dead port.
func NewTCP(listen netip.AddrPort, dial DialFunc, stats *Stats) (Proxy, error) {
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(listen))
	if err != nil {
		return nil, err
	}
	p := &tcpProxy{ln: ln, dial: dial, stats: stats}
	p.wg.Add(1)
	go p.acceptLoop()
	return p, nil
}

func (p *tcpProxy) acceptLoop() {
	defer p.wg.Done()
	for {
		c, err := p.ln.AcceptTCP()
		if err != nil {
			return // listener closed
		}
		p.stats.TCPConns.Add(1)
		go p.handle(c)
	}
}

func (p *tcpProxy) handle(c *net.TCPConn) {
	b, err := p.dial()
	if err != nil {
		// Known Phase 1 semantics: backend down => connect-then-close,
		// not ECONNREFUSED. Documented trade-off of the rewrite scheme.
		c.Close()
		return
	}
	Splice(c, b)
}

func (p *tcpProxy) Addr() net.Addr { return p.ln.Addr() }

func (p *tcpProxy) Close() error {
	err := p.ln.Close()
	p.wg.Wait()
	return err
}
