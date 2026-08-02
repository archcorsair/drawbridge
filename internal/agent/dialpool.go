// Deliberately untagged: no BPF or linux dependencies, so the pool logic
// gets unit-tested on the Mac while the rest of the agent stays linux-only.
package agent

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// dialPool holds parked Mac reverse-stream ('D') connections. The Mac parks
// a few in advance; a gateway proxy pops one per accepted flow and writes
// the 4-byte {proto, port BE, reserved} header to activate it.
//
// A parked conn carries no legitimate bytes before we write the header, so
// each one gets a watchdog blocked in a 1-byte read: if the read returns
// while still parked, the conn is dead (Mac restart) or misbehaving (junk
// byte) and is dropped. Popping must stop the watchdog BEFORE the header is
// written — otherwise it would race the proxy splice for the first backend
// byte — so pop pokes a past read deadline and waits for the watchdog to
// hand off.
type dialPool struct {
	mu      sync.Mutex
	conns   map[*parked]struct{}
	waiters []chan net.Conn
	closed  bool
}

type parked struct {
	c       net.Conn
	handoff bool // set under mu when popped; watchdog then must not close
	bad     bool // watchdog saw EOF/junk instead of the deadline poke
	done    chan struct{}
}

const poolCap = 32

func newDialPool() *dialPool {
	return &dialPool{conns: map[*parked]struct{}{}}
}

// park adds a conn to the pool (or hands it straight to a waiting pop).
func (p *dialPool) park(c net.Conn) {
	p.mu.Lock()
	if p.closed || len(p.conns) >= poolCap {
		p.mu.Unlock()
		c.Close()
		return
	}
	if len(p.waiters) > 0 {
		w := p.waiters[0]
		p.waiters = p.waiters[1:]
		p.mu.Unlock()
		w <- c
		return
	}
	e := &parked{c: c, done: make(chan struct{})}
	p.conns[e] = struct{}{}
	p.mu.Unlock()
	go p.watch(e)
}

func (p *dialPool) watch(e *parked) {
	buf := make([]byte, 1)
	n, err := e.c.Read(buf)
	p.mu.Lock()
	handoff := e.handoff
	if !handoff {
		delete(p.conns, e)
	}
	var ne net.Error
	e.bad = n > 0 || !(errors.As(err, &ne) && ne.Timeout())
	close(e.done)
	p.mu.Unlock()
	if !handoff {
		e.c.Close()
	}
}

// pop returns a live parked conn, waiting up to timeout for the Mac to park
// one if none is available.
func (p *dialPool) pop(timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, errors.New("dial pool closed")
		}
		var e *parked
		for x := range p.conns {
			e = x
			break
		}
		if e != nil {
			e.handoff = true
			delete(p.conns, e)
			p.mu.Unlock()
			e.c.SetReadDeadline(time.Now()) // poke the watchdog out of its read
			<-e.done
			if e.bad || !probeLive(e.c) {
				e.c.Close()
				continue
			}
			e.c.SetReadDeadline(time.Time{})
			return e.c, nil
		}
		w := make(chan net.Conn, 1)
		p.waiters = append(p.waiters, w)
		p.mu.Unlock()
		select {
		case c := <-w:
			return c, nil
		case <-time.After(time.Until(deadline)):
			p.mu.Lock()
			for i, x := range p.waiters {
				if x == w {
					p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
					break
				}
			}
			p.mu.Unlock()
			select { // park may have delivered while we were timing out
			case c := <-w:
				return c, nil
			default:
			}
			return nil, fmt.Errorf("no Mac reverse-dial conn available after %v", timeout)
		}
	}
}

// probeLive closes the poke-vs-EOF race: an expired deadline makes Go's
// poll layer fail the watchdog's read without issuing it, masking a FIN
// already queued on the socket. A short future-deadline read surfaces that
// FIN as instant EOF; a live parked conn has nothing to read (the header
// hasn't been written) and just waits out the window.
func probeLive(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(200 * time.Microsecond))
	var b [1]byte
	n, err := c.Read(b[:])
	var ne net.Error
	return n == 0 && errors.As(err, &ne) && ne.Timeout()
}

func (p *dialPool) close() {
	p.mu.Lock()
	p.closed = true
	conns := p.conns
	p.conns = map[*parked]struct{}{}
	p.mu.Unlock()
	for e := range conns {
		e.c.Close()
	}
}
