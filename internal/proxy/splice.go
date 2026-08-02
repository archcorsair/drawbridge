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
	if t, ok := c.(*net.TCPConn); ok {
		t.CloseWrite()
	}
}
