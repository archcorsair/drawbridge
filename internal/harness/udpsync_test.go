//go:build linux

package harness

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/macsync"
)

// UDP outbound (docs/udp.md U3): the real macsync.Syncer offers explicitly
// configured UDP ports over 'M'; guest datagrams to 127.0.0.1:P are steered
// by the sendmsg hook into the gateway, ride a framed parked 'D' stream,
// and reach the "Mac" service — an in-guest echo on 127.0.0.3 behind the
// DialLocalUDP seam. The Phase 1 assertion-4 guarantees (unconnected
// demux across two ports, stateless reply un-rewrite) now hold against a
// real transport instead of in-guest dummies.
func TestUDPMacSync(t *testing.T) {
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

	echo1 := startUDPEcho(t, "M1:")
	echo2 := startUDPEcho(t, "M2:")
	p1 := freePort(t, "udp")
	p2 := freePort(t, "udp")
	for p2 == p1 {
		p2 = freePort(t, "udp")
	}
	backends := map[uint16]string{p1: echo1, p2: echo2}

	s := &macsync.Syncer{
		AgentAddr: tln.Addr().String(),
		Interval:  20 * time.Millisecond,
		PoolSize:  2,
		Poll:      func() ([]macsync.Listener, error) { return nil, nil },
		UDPPorts:  []uint16{p1, p2},
		DialLocalUDP: func(p uint16) (*net.UDPConn, error) {
			be, ok := backends[p]
			if !ok {
				return nil, fmt.Errorf("unexpected udp dial port %d", p)
			}
			ra, err := net.ResolveUDPAddr("udp", be)
			if err != nil {
				return nil, err
			}
			return net.DialUDP("udp", nil, ra)
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
	waitFor("both udp ports synced", func() bool {
		owned := a.SyncOwnedPorts()
		return slices.Contains(owned, p1) && slices.Contains(owned, p2)
	})

	t.Run("UnconnectedTwoPortDemux", func(t *testing.T) {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		// First datagrams race stream activation; retry, UDP-style.
		got := map[uint16]string{}
		deadline := time.Now().Add(10 * time.Second)
		buf := make([]byte, 2048)
		for len(got) < 2 {
			if time.Now().After(deadline) {
				t.Fatalf("demux incomplete: %v", got)
			}
			c.WriteToUDPAddrPort([]byte("q1"), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p1))
			c.WriteToUDPAddrPort([]byte("q2"), netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p2))
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			for {
				n, from, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					break
				}
				// Reply source must be un-rewritten to 127.0.0.1:P — the
				// recvmsg hook's stateless transform.
				if from.Addr() != netip.MustParseAddr("127.0.0.1") {
					t.Fatalf("reply source %v not un-rewritten", from)
				}
				got[from.Port()] = string(buf[:n])
			}
		}
		if got[p1] != "M1:q1" || got[p2] != "M2:q2" {
			t.Fatalf("demux wrong: %v", got)
		}
	})

	t.Run("ConnectedRoundTrip", func(t *testing.T) {
		c, err := net.Dial("udp", addr(p1)) // connect4 hook path
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		deadline := time.Now().Add(5 * time.Second)
		buf := make([]byte, 2048)
		for {
			if time.Now().After(deadline) {
				t.Fatal("no echo on connected socket")
			}
			c.Write([]byte("ping"))
			c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n, err := c.Read(buf); err == nil {
				if got := string(buf[:n]); got != "M1:ping" {
					t.Fatalf("echo = %q", got)
				}
				return
			}
		}
	})

	t.Run("SessionLossDropsSyncedPorts", func(t *testing.T) {
		cancel() // Mac goes away entirely
		waitFor("sync-owned drained", func() bool {
			return len(a.SyncOwnedPorts()) == 0
		})
	})
}
