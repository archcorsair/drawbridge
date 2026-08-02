//go:build linux

package seccomp

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// In-process ABI round trip: install the filter, supervise our own notify
// fd, deny one bind with EPERM (distinct from anything bind returns here
// naturally), and check the sockaddr we read from target memory.
//
// The filter is process-permanent, so after the assertion the supervisor
// switches to CONTINUE-everything for the rest of the test binary's life.
func TestBindNotifyRoundTrip(t *testing.T) {
	fd, err := InstallBindFilter()
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if st, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, "Seccomp") {
				t.Logf("%s (listener fd=%d)", l, fd)
			}
		}
	}

	type seen struct {
		nf  Notif
		ba  BindAddr
		err error
	}
	// Deny only the target port; CONTINUE everything else — Go's net
	// package issues internal capability-probe binds (::1 and
	// ::ffff:127.0.0.1, port 0) before the bind under test, exactly like a
	// real workload would. Matching by port is also what the agent does.
	got := make(chan seen, 1)
	go func() {
		for {
			nf, err := Recv(fd)
			if err != nil {
				select {
				case got <- seen{err: err}:
				default:
				}
				return
			}
			ba, aerr := ReadBindAddr(nf.PID, nf.Args[1], nf.Args[2])
			if aerr == nil && ba.Port == 45677 {
				// Go tries the v6-mapped address first, so the same port
				// is notified more than once: record the first, deny all.
				select {
				case got <- seen{nf: nf, ba: ba}:
				default:
				}
				if err := SendErrno(fd, nf.ID, unix.EPERM); err != nil {
					t.Errorf("SendErrno: %v", err)
				}
				continue
			}
			SendContinue(fd, nf.ID)
		}
	}()

	_, lerr := net.Listen("tcp4", "127.0.0.1:45677")
	if lerr == nil {
		t.Fatal("bind succeeded — filter never fired")
	}
	if !errors.Is(lerr, syscall.EPERM) {
		t.Fatalf("bind error = %v, want EPERM from supervisor", lerr)
	}

	select {
	case s := <-got:
		if s.err != nil {
			t.Fatalf("supervisor: %v", s.err)
		}
		if s.nf.Nr != nrBind {
			t.Fatalf("notified nr = %d, want %d", s.nf.Nr, nrBind)
		}
		// Unmap makes the v4 and v6-mapped forms indistinguishable here,
		// which is exactly what the agent's decision path wants.
		if s.ba.Port != 45677 || s.ba.Addr.String() != "127.0.0.1" {
			t.Fatalf("sockaddr = %+v, want 127.0.0.1:45677", s.ba)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no notification observed")
	}

	// SockProto against ourselves (the supervisor side does this cross-pid
	// in production; same syscalls).
	c, err := net.Listen("tcp4", "127.0.0.1:0") // supervisor CONTINUEs it
	if err != nil {
		t.Fatalf("post-assert bind (CONTINUE path): %v", err)
	}
	defer c.Close()
}
