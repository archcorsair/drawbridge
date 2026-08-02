// Privileged-port e2e (docs/privileged-daemon.md §10 Phase 3): the two flows
// that only exist when the process doing the mirror/reserve binds holds
// privilege. macOS reserves ports <1024 for root and has no `reservedhigh`
// sysctl, so unprivileged drawbridged logs-and-skips a `:80` mirror bind and
// answers `"unknown"` (→ CONTINUE, async degrade) for a `:80` reservation.
// As root both become the real thing, and these tests assert exactly that.
//
// The gate is a capability probe, not a euid check: the suite tries a real
// loopback bind below 1024 and skips with instructions when it is denied, so
// an ordinary `just e2e` stays green and a root runner gets the coverage. No
// installed LaunchDaemon is needed either way — the suite runs its own
// in-process mirror client, exactly like every other test here.
package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/macsync"
)

// privilegedPort is the port both privileged legs use — the MVP demo port
// (`docker run --network host nginx` → `curl localhost:80`).
const privilegedPort = 80

// lowPortProbes are the loopback ports the capability gate tries, in order.
// 80 is the one the tests need; 1023 is a second, rarely-occupied low port
// that disambiguates "this machine already has something on :80" (EADDRINUSE,
// inconclusive) from "this process may not bind <1024" (EACCES/EPERM).
var lowPortProbes = []int{privilegedPort, 1023}

// probeLoopbackBind is the real capability probe: bind and immediately
// release a loopback port. It is the only impure half of the gate — the
// decision logic below is a pure function over its errors so it can be
// unit-tested both ways without root.
func probeLoopbackBind(port int) error {
	ln, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return ln.Close()
}

// privPortCapability classifies probe results into "this process can bind
// privileged loopback ports" plus a reason in words. A port that is merely
// occupied proves nothing either way, so it moves on to the next candidate;
// only a denial is a verdict, and running out of candidates is an explicit
// "cannot tell" rather than a silent false.
func privPortCapability(probe func(int) error, ports []int) (bool, string) {
	var busy []string
	for _, p := range ports {
		err := probe(p)
		switch {
		case err == nil:
			return true, fmt.Sprintf("bound 127.0.0.1:%d", p)
		case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
			return false, fmt.Sprintf("bind 127.0.0.1:%d denied (%v) — macOS reserves ports <1024 for root", p, err)
		case errors.Is(err, syscall.EADDRINUSE):
			busy = append(busy, strconv.Itoa(p))
		default:
			return false, fmt.Sprintf("bind 127.0.0.1:%d failed: %v", p, err)
		}
	}
	return false, fmt.Sprintf("every probe port is already in use (:%s) — cannot tell whether this process may bind <1024",
		strings.Join(busy, ", :"))
}

// requirePrivilegedPorts skips, actionably, unless this test binary can bind
// below 1024. The message is the whole point of the phase: an unprivileged
// `just e2e` must say exactly how to get this coverage.
func requirePrivilegedPorts(t *testing.T) {
	t.Helper()
	ok, reason := privPortCapability(probeLoopbackBind, lowPortProbes)
	if ok {
		t.Logf("privileged-port capability present (euid=%d, %s)", os.Geteuid(), reason)
		return
	}
	t.Skipf("no privileged-port capability (euid=%d): %s. "+
		"Run this leg as root: `just e2e-root` — i.e. "+
		"`sudo -E env \"PATH=$PATH\" DRAWBRIDGE_E2E=1 go test -count=1 -v -run TestPrivileged ./internal/e2e/`. "+
		"No installed daemon is required (the suite runs its own in-process mirror client); "+
		"the guest still needs `just vm-up && just agent-up`.", os.Geteuid(), reason)
}

// TestPrivilegedPortCapabilityDecision pins the gate's classification table.
// It needs no VM, no root and no e2e flag — it is the both-ways coverage of
// the probe that the privileged legs themselves can only exercise one way per
// run.
func TestPrivilegedPortCapabilityDecision(t *testing.T) {
	tests := []struct {
		name     string
		probe    func(int) error
		ports    []int
		wantOK   bool
		wantWord string
	}{
		{
			name:     "root binds the first candidate",
			probe:    func(int) error { return nil },
			ports:    []int{80, 1023},
			wantOK:   true,
			wantWord: "bound 127.0.0.1:80",
		},
		{
			name:     "unprivileged is denied",
			probe:    func(int) error { return syscall.EACCES },
			ports:    []int{80, 1023},
			wantOK:   false,
			wantWord: "reserves ports <1024 for root",
		},
		{
			name:     "EPERM counts as denied too",
			probe:    func(int) error { return syscall.EPERM },
			ports:    []int{80},
			wantOK:   false,
			wantWord: "reserves ports <1024 for root",
		},
		{
			name: "a busy first port does not mask capability",
			probe: func(p int) error {
				if p == 80 {
					return syscall.EADDRINUSE
				}
				return nil
			},
			ports:    []int{80, 1023},
			wantOK:   true,
			wantWord: "bound 127.0.0.1:1023",
		},
		{
			name: "a busy first port does not mask denial",
			probe: func(p int) error {
				if p == 80 {
					return syscall.EADDRINUSE
				}
				return syscall.EACCES
			},
			ports:    []int{80, 1023},
			wantOK:   false,
			wantWord: "reserves ports <1024 for root",
		},
		{
			name:     "all candidates busy is inconclusive, not capable",
			probe:    func(int) error { return syscall.EADDRINUSE },
			ports:    []int{80, 1023},
			wantOK:   false,
			wantWord: "cannot tell",
		},
		{
			name:     "an unexpected error never claims capability",
			probe:    func(int) error { return errors.New("boom") },
			ports:    []int{80},
			wantOK:   false,
			wantWord: "boom",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := privPortCapability(tc.probe, tc.ports)
			if ok != tc.wantOK {
				t.Fatalf("capability = %v, want %v (reason %q)", ok, tc.wantOK, reason)
			}
			if !strings.Contains(reason, tc.wantWord) {
				t.Fatalf("reason %q does not mention %q", reason, tc.wantWord)
			}
		})
	}
	// Wrapped errors must classify the same way: net.Listen returns an
	// *OpError around the syscall errno, never the bare errno.
	ok, reason := privPortCapability(
		func(p int) error {
			return &net.OpError{Op: "listen", Net: "tcp4", Err: os.NewSyscallError("bind", syscall.EACCES)}
		}, []int{80})
	if ok || !strings.Contains(reason, "reserves ports <1024 for root") {
		t.Fatalf("wrapped EACCES classified as ok=%v reason=%q", ok, reason)
	}
}

// TestPrivilegedMirror is the inbound <1024 leg: a guest listener on :80
// becomes a real Mac-loopback mirror. Unprivileged this bind is the
// logs-and-skips path in mirror.logBindError, so there is nothing on Mac
// 127.0.0.1:80 to fetch at all.
func TestPrivilegedMirror(t *testing.T) {
	requireE2E(t)
	requirePrivilegedPorts(t)

	// The mirror is about to want :80 specifically; if this machine already
	// has a listener there, say so rather than failing on a timeout.
	if err := probeLoopbackBind(privilegedPort); err != nil {
		t.Skipf("127.0.0.1:%d is not bindable by this process (%v) — free it and re-run", privilegedPort, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	go m.Run(ctx)

	unit := unitName + "-priv"
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", unit, unit))
	if out, err := guest(t, fmt.Sprintf(
		"systemd-run --unit=%s --collect python3 -m http.server %d --bind 0.0.0.0", unit, privilegedPort)); err != nil {
		t.Fatalf("start guest :%d http server: %v: %s", privilegedPort, err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", unit)) })

	deadline := time.Now().Add(20 * time.Second)
	for !m.Mirrors("tcp", privilegedPort) {
		if time.Now().After(deadline) {
			t.Fatalf("guest :%d never mirrored — privileged bind refused? (check the drawbridged log lines)", privilegedPort)
		}
		time.Sleep(200 * time.Millisecond)
	}

	deadline = time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", privilegedPort))
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "Directory listing") {
				t.Logf("guest :%d served on Mac localhost:%d — privileged mirror bind (%d bytes)",
					privilegedPort, privilegedPort, len(body))
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("guest :%d never became reachable on Mac localhost: %v", privilegedPort, lastErr)
}

// TestPrivilegedReserve is the arbitration leg: with the Mac holding :80, a
// guest bind to :80 must fail synchronously with Linux EADDRINUSE.
// Unprivileged, mirror.handleReserve cannot bind the port to find out and
// answers "unknown" → CONTINUE, so the guest bind *succeeds* and the conflict
// only ever surfaces as a missing mirror. Under root the answer is
// definitive, which is the whole point of the privileged daemon.
func TestPrivilegedReserve(t *testing.T) {
	requireE2E(t)
	requirePrivilegedPorts(t)

	// A real Mac-native listener on the privileged port.
	held, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", privilegedPort))
	if err != nil {
		t.Skipf("cannot hold 127.0.0.1:%d for the test (%v) — free it and re-run", privilegedPort, err)
	}
	defer held.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		Auth:      macAuth,
		Exclude: func(l macsync.Listener) bool {
			return l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
		},
	}
	go m.Run(ctx)
	go s.Run(ctx)

	// The verdict only means something once the reservation RPC is live.
	waitBindArbitrationLive(t)

	r, err := guestBindProbe(t, privilegedPort)
	if err != nil {
		t.Fatal(err)
	}
	if r.Errno != linuxEADDRINUSE {
		t.Fatalf("guest bind to Mac-held :%d = errno %d (%s), want EADDRINUSE(%d) — "+
			"errno 0 means the reserve answered \"unknown\"/CONTINUE, i.e. the bind was not privileged",
			privilegedPort, r.Errno, r.Error, linuxEADDRINUSE)
	}
	t.Logf("guest bind to Mac-held :%d refused synchronously with EADDRINUSE — privileged reserve is definitive", privilegedPort)
}
