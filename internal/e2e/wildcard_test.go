package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/macsync"
)

// Audit H1 / NEW-A1 (P0-2): a Mac port held on a WILDCARD address must refuse
// a guest bind exactly like a Mac 127.0.0.1 holder does. Every older
// EADDRINUSE leg holds the Mac port on 127.0.0.1, which the mirror's own bind
// already caught; on XNU, SO_REUSEADDR lets a 127.0.0.1:P bind succeed beside
// 0.0.0.0:P or dual-stack [::]:P and then take their loopback traffic.
//
// Two layers, each run alone so a green leg is attributable to one of them:
//
//   - agent: the syncer runs, so the Mac's port lands in the agent's mac set
//     and ReservePort answers inuse without a round trip. The mirror carries
//     no MacHolder hook, so the Mac could not have refused.
//   - mac-backstop: no syncer, so the agent knows nothing and asks the Mac;
//     only the mirror's fresh listener read (macsync.HolderCheck) can refuse.
//
// For every case the verdict is EADDRINUSE, no reservation exists afterwards
// (NEW-A1: the old flow held Mac 127.0.0.1:P for ReserveTTL behind a guest
// wildcard bind that then failed natively), and Mac 127.0.0.1:P still reaches
// the native holder.

var wildcardHolders = []struct{ name, network, addr string }{
	{"dual-stack-v6any", "tcp", ":0"},
	{"tcp4-any", "tcp4", "0.0.0.0:0"},
}

var guestWildcardBinds = []struct{ name, network, host string }{
	{"loopback", "tcp4", "127.0.0.1"},
	{"v4-any", "tcp4", "0.0.0.0"},
	{"dual-stack-v6any", "tcp", "::"},
}

func TestGuestBindBesideMacWildcardHolder(t *testing.T) {
	requireE2E(t)

	t.Run("agent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := newMirror(agentAddr) // no MacHolder: only the agent can refuse here
		s := &macsync.Syncer{
			AgentAddr: agentAddr,
			Auth:      macAuth,
			Exclude: func(l macsync.Listener) bool {
				return l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
			},
		}
		go m.Run(ctx)
		go s.Run(ctx)
		waitBindArbitrationLive(t)

		for _, h := range wildcardHolders {
			t.Run(h.name, func(t *testing.T) {
				port := macWildcardHolder(t, h.network, h.addr)
				waitGuestGateway(t, port, true)
				for _, b := range guestWildcardBinds {
					requireRefusedWithoutReservation(t, m, b.network, b.host, port)
				}
			})
		}
	})

	t.Run("mac-backstop", func(t *testing.T) {
		if ls, err := macsync.Listeners(); err != nil || len(ls) == 0 {
			t.Skipf("Mac listener enumeration unavailable or filtered for this process (%d, %v): the backstop answers unknown by design — run as root or from an exempt app", len(ls), err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := newMirror(agentAddr)
		m.MacHolder = macsync.HolderCheck("127.0.0.1", nil)
		go m.Run(ctx) // no syncer: the agent must not know the port
		waitBindArbitrationLive(t)

		for _, h := range wildcardHolders {
			t.Run(h.name, func(t *testing.T) {
				port := macWildcardHolder(t, h.network, h.addr)
				// Attribution: a gateway for the port means something else
				// (an installed daemon, a leaked syncer) synced it, and the
				// agent would answer instead of the backstop.
				waitGuestGateway(t, port, false)
				for _, b := range guestWildcardBinds {
					requireRefusedWithoutReservation(t, m, b.network, b.host, port)
				}
			})
		}
	})
}

// macWildcardHolder is a native Mac service on a wildcard: it answers "MAC"
// so a later dial can tell it from a mirror.
func macWildcardHolder(t *testing.T, network, addr string) int {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("MAC"))
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// waitGuestGateway waits for the agent's 127.0.0.2:port gateway listener to
// be present (the Mac port is synced) or absent (it is not).
func waitGuestGateway(t *testing.T, port int, present bool) {
	t.Helper()
	want := fmt.Sprintf("127.0.0.2:%d", port)
	deadline := time.Now().Add(15 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		out, _ = guest(t, fmt.Sprintf("ss -Hltn 'sport = :%d'", port))
		if strings.Contains(out, want) == present {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("guest gateway %s present=%v never held (ss: %q) — is an installed daemon syncing? (`sudo launchctl bootout system/com.archcorsair.drawbridged`)", want, present, out)
}

func requireRefusedWithoutReservation(t *testing.T, m interface{ Mirrors(string, uint16) bool }, network, host string, port int) {
	t.Helper()
	r, err := guestBindProbeAt(t, network, host, port)
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	if r.Errno != linuxEADDRINUSE {
		t.Fatalf("guest %s bind %s beside a Mac wildcard holder = errno %d (%s), want EADDRINUSE(%d)",
			network, addr, r.Errno, r.Error, linuxEADDRINUSE)
	}
	if m.Mirrors("tcp", uint16(port)) {
		t.Fatalf("guest %s bind %s was refused but a mirror/reservation for :%d exists (NEW-A1)", network, addr, port)
	}
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("Mac 127.0.0.1:%d after the refusal: %v", port, err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 3)
	if _, err := c.Read(b); err != nil || string(b) != "MAC" {
		t.Fatalf("Mac 127.0.0.1:%d answered %q (%v), want the native holder", port, b, err)
	}
	t.Logf("guest %s bind %s refused with EADDRINUSE; no reservation; Mac holder still answers 127.0.0.1", network, addr)
}

// guestBindProbeAt is guestBindProbe for any network and bind address. The
// address is single-quoted: `[::]:P` is a bash glob.
func guestBindProbeAt(t *testing.T, network, host string, port int) (seccompProbeResult, error) {
	t.Helper()
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	out, err := guest(t, fmt.Sprintf("%s bindprobe -network %s -addr '%s' -hold 0s", guestAgentBin(t), network, addr))
	if err != nil {
		return seccompProbeResult{}, fmt.Errorf("%v: %s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "{") {
			var r seccompProbeResult
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return r, fmt.Errorf("bad probe JSON %q: %w", line, err)
			}
			return r, nil
		}
	}
	return seccompProbeResult{}, fmt.Errorf("no probe result in %q", out)
}
