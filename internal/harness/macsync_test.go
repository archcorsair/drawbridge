//go:build linux

package harness

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/macsync"
)

// Phase 3 in-guest integration: the real macsync.Syncer plays the Mac over
// the real transport ('M' + 'D'), with an in-guest 127.0.0.3 echo standing
// in for the Mac-local service. Proves: synced ports steer loopback
// connects through a reverse stream, getpeername stays un-rewritten, and
// del/session-loss restore native ECONNREFUSED.
func TestPhase3MacSync(t *testing.T) {
	a, err := agent.New("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("load+attach: %v", err)
	}
	defer a.Close()

	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tln.Close()
	go a.ServeTransport(tln)

	backend := startTCPEcho(t, "MAC:")
	port := freePort(t, "tcp")

	var mu sync.Mutex
	set := []macsync.Listener{{Proto: "tcp", Port: port, Addr: netip.MustParseAddr("127.0.0.1")}}
	s := &macsync.Syncer{
		AgentAddr: tln.Addr().String(),
		Interval:  20 * time.Millisecond,
		PoolSize:  2,
		Poll: func() ([]macsync.Listener, error) {
			mu.Lock()
			defer mu.Unlock()
			return append([]macsync.Listener(nil), set...), nil
		},
		DialLocal: func(p uint16) (net.Conn, error) {
			if p != port {
				return nil, fmt.Errorf("unexpected dial-local port %d", p)
			}
			return net.Dial("tcp", backend)
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitFor := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %s (sync-owned: %v)", desc, a.SyncOwnedPorts())
	}

	t.Run("SyncedPortRoundTrips", func(t *testing.T) {
		waitFor("port synced", func() bool {
			return slices.Contains(a.SyncOwnedPorts(), port)
		})
		c, err := net.DialTimeout("tcp", addr(port), 3*time.Second)
		if err != nil {
			t.Fatalf("dial synced port: %v", err)
		}
		defer c.Close()
		if got := c.RemoteAddr().String(); got != addr(port) {
			t.Fatalf("getpeername = %s, want %s (un-rewrite broken)", got, addr(port))
		}
		fmt.Fprintln(c, "over the bridge")
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if line != "MAC:over the bridge\n" {
			t.Fatalf("echo = %q", line)
		}
	})

	t.Run("DelRestoresNativeRefused", func(t *testing.T) {
		mu.Lock()
		set = nil
		mu.Unlock()
		waitFor("port unsynced", func() bool {
			return !slices.Contains(a.SyncOwnedPorts(), port)
		})
		_, err := net.DialTimeout("tcp", addr(port), time.Second)
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("want ECONNREFUSED after del, got %v", err)
		}
	})

	t.Run("SessionLossDropsSyncedPorts", func(t *testing.T) {
		mu.Lock()
		set = []macsync.Listener{{Proto: "tcp", Port: port, Addr: netip.MustParseAddr("127.0.0.1")}}
		mu.Unlock()
		waitFor("port re-synced", func() bool {
			return slices.Contains(a.SyncOwnedPorts(), port)
		})
		cancel() // Mac goes away entirely
		waitFor("sync-owned drained", func() bool {
			return len(a.SyncOwnedPorts()) == 0
		})
		_, err := net.DialTimeout("tcp", addr(port), time.Second)
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("want ECONNREFUSED after session loss, got %v", err)
		}
	})
}
