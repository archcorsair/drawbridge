package proxy

import (
	"io"
	"net"
)

// Splice copies bidirectionally between two connections, propagating TCP
// half-closes, and closes both when done.
func Splice(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		closeWrite(b)
		close(done)
	}()
	io.Copy(a, b)
	closeWrite(a)
	<-done
	a.Close()
	b.Close()
}

func closeWrite(c net.Conn) {
	// Interface, not a *net.TCPConn assertion: *net.TCPConn and
	// *net.UnixConn both implement it, and so do counting wrappers (the
	// mirror's per-entry accounting) that would otherwise silently swallow
	// the half-close.
	type closeWriter interface{ CloseWrite() error }
	if t, ok := c.(closeWriter); ok {
		t.CloseWrite()
	}
}
