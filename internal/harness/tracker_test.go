//go:build linux

package harness

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/bpf"
)

// Phase 2: kernel listener tracking. Creating/closing listeners must be
// reflected in guest_ports (via the fexit/fentry hooks, no userspace in the
// loop) and in the hub's event-driven listener set.
func TestPhase2Tracker(t *testing.T) {
	a, err := agent.New("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("load+attach: %v", err)
	}
	defer a.Close()

	// Reports map and hub state separately — they fail for different reasons
	// (BPF hook vs ringbuf/event plumbing).
	waitFor := func(desc string, cond func() bool, state func() string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %s (%s)", desc, state())
	}

	t.Run("TCP", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		addr := netip.MustParseAddr("127.0.0.1")
		l := agent.Listener{Proto: "tcp", Port: port, Addr: addr}

		state := func() string {
			return fmt.Sprintf("port=%d map=%v hub=%v", port,
				a.HasGuestPort(bpf.ProtoTCP, addr, port), a.Hub.Has(l))
		}
		waitFor("tcp listener tracked", func() bool {
			return a.HasGuestPort(bpf.ProtoTCP, addr, port) && a.Hub.Has(l)
		}, state)
		ln.Close()
		waitFor("tcp listener untracked", func() bool {
			return !a.HasGuestPort(bpf.ProtoTCP, addr, port) && !a.Hub.Has(l)
		}, state)
	})

	t.Run("UDP", func(t *testing.T) {
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(uc.LocalAddr().(*net.UDPAddr).Port)
		addr := netip.MustParseAddr("127.0.0.1")

		state := func() string {
			return fmt.Sprintf("port=%d map=%v", port, a.HasGuestPort(bpf.ProtoUDP, addr, port))
		}
		waitFor("udp socket tracked", func() bool {
			return a.HasGuestPort(bpf.ProtoUDP, addr, port)
		}, state)
		uc.Close()
		waitFor("udp socket untracked", func() bool {
			return !a.HasGuestPort(bpf.ProtoUDP, addr, port)
		}, state)
	})

	// The inverse of waitFor: the condition must hold continuously — tracker
	// hooks are async, so absence is only meaningful over a window.
	holdFor := func(desc string, d time.Duration, cond func() bool, state func() string) {
		t.Helper()
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if !cond() {
				t.Fatalf("%s violated (%s)", desc, state())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	t.Run("ForeignNetns", func(t *testing.T) {
		// Since the OCI integration put docker in the guest, the kernel-global
		// hooks also fire for bridged containers' netns. Simulate one with
		// unshare(CLONE_NEWNET): its listeners must never reach guest_ports
		// or the hub (which would make drawbridged mirror them on the Mac).
		wild := netip.MustParseAddr("0.0.0.0")

		fport, fclose := listenInForeignNetns(t, 0)
		defer fclose()
		fl := agent.Listener{Proto: "tcp", Port: fport, Addr: wild}
		holdFor("foreign listener untracked", 700*time.Millisecond, func() bool {
			return !a.HasGuestPort(bpf.ProtoTCP, wild, fport) && !a.Hub.Has(fl)
		}, func() string {
			return fmt.Sprintf("port=%d map=%v hub=%v", fport,
				a.HasGuestPort(bpf.ProtoTCP, wild, fport), a.Hub.Has(fl))
		})
		fclose()

		// Same-key collision: the two netns can hold 0.0.0.0:P at once, and
		// closing the foreign one must not decrement the host entry's
		// refcount (track_del's fill_key fallback would, if unfiltered).
		// tcp4, not tcp: Go turns a plain-tcp 0.0.0.0 listen into a
		// dual-stack [::] socket, which keys as :: instead of 0.0.0.0.
		ln, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		state := func() string {
			return fmt.Sprintf("port=%d map=%v hub=%v", port,
				a.HasGuestPort(bpf.ProtoTCP, wild, port), hubListeners(a))
		}
		waitFor("host wildcard listener tracked", func() bool {
			return a.HasGuestPort(bpf.ProtoTCP, wild, port)
		}, state)

		_, fclose2 := listenInForeignNetns(t, port)
		fclose2()
		holdFor("host entry survives foreign close", 700*time.Millisecond, func() bool {
			return a.HasGuestPort(bpf.ProtoTCP, wild, port)
		}, state)

		ln.Close()
		waitFor("host wildcard listener untracked", func() bool {
			return !a.HasGuestPort(bpf.ProtoTCP, wild, port)
		}, state)
	})

	t.Run("SeededFromProc", func(t *testing.T) {
		// The agent's own attach happened after sshd etc. existed; the seed
		// should have found at least one pre-existing TCP listener.
		//
		// Capability probe: the claim is "the seed found what the kernel
		// already had", which is only testable on a host that HAS a
		// pre-existing listener. The dev VM always does (sshd); a bare CI
		// runner is not guaranteed to, and "nothing to find" must not read
		// as "seeding is broken". Probing /proc directly keeps the
		// assertion live wherever it means anything.
		if n := procListenerCount(t); n == 0 {
			t.Skip("no pre-existing TCP listener in this netns — nothing for the /proc seed to find")
		}
		if len(hubListeners(a)) == 0 {
			t.Fatal("seed found no pre-existing listeners")
		}
	})
}

// listenInForeignNetns binds 0.0.0.0:port on a TCP listener inside a fresh
// network namespace (port 0 picks one) and returns the bound port plus a
// close func that also reaps the goroutine. The OS thread is locked and
// never unlocked so the runtime discards it — the unshared netns never
// leaks back into the thread pool.
func listenInForeignNetns(t *testing.T, port uint16) (uint16, func()) {
	t.Helper()
	type boundResult struct {
		port uint16
		err  error
	}
	bound := make(chan boundResult, 1)
	closeReq := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(done)
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			bound <- boundResult{err: fmt.Errorf("unshare(CLONE_NEWNET): %w", err)}
			return
		}
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			bound <- boundResult{err: err}
			return
		}
		bound <- boundResult{port: uint16(ln.Addr().(*net.TCPAddr).Port)}
		<-closeReq
		ln.Close()
	}()
	r := <-bound
	if r.err != nil {
		t.Fatalf("foreign netns listen: %v", r.err)
	}
	var once sync.Once
	return r.port, func() {
		once.Do(func() {
			close(closeReq)
			<-done
		})
	}
}

// procListenerCount counts TCP listeners in this netns straight from /proc,
// independent of the agent. Deliberately narrower than the seed (which also
// takes non-ephemeral UDP binds): a zero here is a strong statement that
// there was nothing for the seed to find, so the skip it gates cannot hide
// a real seeding regression.
func procListenerCount(t *testing.T) int {
	t.Helper()
	n := 0
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue // e.g. ipv6 disabled — the other file still counts
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			// "sl local_address rem_address st …"; st 0A is TCP_LISTEN.
			if fields := strings.Fields(sc.Text()); len(fields) >= 4 && fields[3] == "0A" {
				n++
			}
		}
		f.Close()
	}
	return n
}

func hubListeners(a *agent.Agent) []agent.Listener {
	// Subscribe returns a snapshot as the first event.
	ch, cancel := a.Hub.Subscribe()
	defer cancel()
	ev := <-ch
	return ev.Listeners
}
