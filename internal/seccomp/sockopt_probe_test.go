//go:build linux

package seccomp

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// Socket classification must survive Multipath TCP: Go 1.24+ opens TCP
// listeners with IPPROTO_MPTCP (262), so any SO_PROTOCOL == IPPROTO_TCP
// check silently rejects real Go servers and the supervisor CONTINUEs
// every bind it should have arbitrated.
func TestClassifiesGoListenerAsStream(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	fd := sockFD(t, ln)

	pid := uint32(os.Getpid())
	stream, err := IsInetStream(pid, uint64(fd))
	if err != nil {
		t.Fatalf("IsInetStream: %v", err)
	}
	if !stream {
		t.Fatal("Go TCP listener not classified as an IP stream socket")
	}
	if proto, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL); err == nil {
		t.Logf("listener SO_PROTOCOL=%d (262 = IPPROTO_MPTCP, 6 = IPPROTO_TCP)", proto)
	}
}

func TestDoesNotClassifyUDPAsStream(t *testing.T) {
	uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	fd := sockFD(t, uc)

	stream, err := IsInetStream(uint32(os.Getpid()), uint64(fd))
	if err != nil {
		t.Fatalf("IsInetStream: %v", err)
	}
	if stream {
		t.Fatal("UDP socket classified as a stream socket")
	}
}

// sockFD borrows the raw descriptor of a net socket.
func sockFD(t *testing.T, x any) int {
	t.Helper()
	type rawer interface {
		SyscallConn() (interface {
			Control(func(uintptr)) error
		}, error)
	}
	var sc interface {
		Control(func(uintptr)) error
	}
	switch v := x.(type) {
	case *net.TCPListener:
		c, err := v.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		sc = c
	case *net.UDPConn:
		c, err := v.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		sc = c
	default:
		t.Fatalf("unsupported %T", x)
	}
	var fd int
	if err := sc.Control(func(f uintptr) { fd = int(f) }); err != nil {
		t.Fatal(err)
	}
	return fd
}
