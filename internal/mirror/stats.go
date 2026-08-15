package mirror

// Per-entry accounting (introspect.MirrorEntry's counter fields). One stats
// block lives on each live mirrorEntry, counted with atomics on the splice
// hot path and read by Snapshot without any lock beyond the entry table's.
// The counters describe the current binding: they are born with the mirror
// and die with it, exactly like the entry's Since.
//
// What is counted is payload only. The TCP wrapper is attached AFTER
// dialStream returns, so the transport-auth hello and proof bytes never
// touch a counter; the UDP path counts frame payloads, not the 21-byte
// headers. The parked 'D' reverse-dial pool belongs to macsync and is not a
// mirror path: nothing here can see a parked conn, let alone count one.

import (
	"net"
	"sync/atomic"
	"time"
)

type entryStats struct {
	conns      atomic.Int64
	rx, tx     atomic.Uint64
	lastActive atomic.Int64 // unix nanos; 0 means no payload yet
}

func (s *entryStats) touch() { s.lastActive.Store(time.Now().UnixNano()) }

// countingConn wraps the guest-side stream of one TCP splice. Every payload
// byte of the splice crosses this conn exactly once in each direction, so
// wrapping the one side counts the whole flow: reads are guest-to-Mac (rx),
// writes are Mac-to-guest (tx).
type countingConn struct {
	net.Conn
	s *entryStats
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.s.rx.Add(uint64(n))
		c.s.touch()
	}
	return n, err
}

func (c countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.s.tx.Add(uint64(n))
		c.s.touch()
	}
	return n, err
}

// CloseWrite keeps the splice's TCP half-close propagation working through
// the wrapper: proxy.Splice half-closes via this interface, and a wrapper
// that swallowed it would strand every drain-after-FIN flow.
func (c countingConn) CloseWrite() error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}
