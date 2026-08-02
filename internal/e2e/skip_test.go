// Skip-list legs (docs/ergonomics.md §7): drawbridged's -skip list is
// Mac-side policy applied in both directions — a guest listener on a skipped
// port is declined (audibly) instead of mirrored, and a Mac listener on a
// skipped port is never synced into the guest's mac_ports.
//
// The default list is {22}, but :22 is the one port these legs cannot use:
// the guest's real sshd holds it and the harness itself reaches the VM over
// SSH, so a test that fought it would be testing the fixture, not the
// mechanism. Every leg below therefore runs the daemon's own wiring with an
// explicit -skip list naming a test port — which is also the override path
// (`-skip` replaces the list), so the flag and the mechanism are covered
// together. That the default list is exactly {22} is pinned by unit tests in
// cmd/drawbridged and internal/install.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/macsync"
)

// skipPort stands in for :22 in the guest→Mac legs: same 479xx block as the
// other suites, outside the guest autobind range.
const skipPort = 47997

// logSink captures the standard logger; the mirror logs from its session
// goroutine, so the buffer carries its own lock.
type logSink struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureLog(t *testing.T) *logSink {
	t.Helper()
	s := &logSink{}
	old := log.Writer()
	log.SetOutput(s)
	t.Cleanup(func() { log.SetOutput(old) })
	return s
}

// startGuestHTTP runs python3's http server in the guest on port, under a
// transient unit torn down with the test.
//
// --bind 127.0.0.1, unlike the other legs' 0.0.0.0: these two legs assert on
// what is (and is not) listening on Mac localhost, and until 2026-07-31 the
// dev template's `ignore` rule matched guestIP 127.0.0.1 only, so Lima's
// hostagent forwarded guest *wildcard* binds onto Mac loopback itself. The
// template is fixed (and the mirror legs now carry requireAttributableMirror),
// but a guest-loopback bind stays the right choice here: these legs' *absence*
// assertions must hold on any instance regardless of its forwarding config,
// and a loopback listener is the one no provider forwarder ever republishes.
func startGuestHTTP(t *testing.T, unit string, port int) {
	t.Helper()
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", unit, unit))
	if out, err := guest(t, fmt.Sprintf(
		"systemd-run --unit=%s --collect python3 -m http.server %d --bind 127.0.0.1", unit, port)); err != nil {
		t.Fatalf("start guest http server: %v: %s", err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", unit)) })
}

// Leg 1: a guest listener on a skipped port is declined out loud and never
// appears on Mac localhost. The log line doubles as the liveness proof — it
// can only be written by an 'E' event that arrived and was evaluated, so
// "no mirror" here cannot be a not-yet-connected client.
func TestSkipListDeclinesGuestListener(t *testing.T) {
	requireE2E(t)
	sink := captureLog(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	m.Skip = map[uint16]bool{skipPort: true}
	go m.Run(ctx)

	startGuestHTTP(t, unitName+"-skip", skipPort)

	want := fmt.Sprintf("skipping guest tcp :%d", skipPort)
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(sink.String(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("no %q in drawbridged's log:\n%s", want, sink.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	if m.Mirrors("tcp", skipPort) {
		t.Fatalf("guest :%d was mirrored despite the skip-list", skipPort)
	}
	// And nothing is listening on the Mac: the decline is a bind that never
	// happened, not a bookkeeping detail.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", skipPort), 2*time.Second)
	if err == nil {
		c.Close()
		t.Fatalf("127.0.0.1:%d answered — the skipped guest listener was mirrored after all", skipPort)
	}
	t.Logf("guest :%d declined by the skip-list, logged, and absent from Mac localhost", skipPort)
}

// Leg 2: the same guest listener with the skip-list emptied IS mirrored —
// `-skip ""` is a real off switch and the port carries no hardcoded policy.
func TestEmptySkipListMirrorsTheSamePort(t *testing.T) {
	requireE2E(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	m.Skip = map[uint16]bool{} // what -skip "" produces
	go m.Run(ctx)

	startGuestHTTP(t, unitName+"-skip", skipPort)

	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", skipPort))
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "Directory listing") {
				t.Logf("with an empty skip-list, guest :%d is served on Mac localhost", skipPort)
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("guest :%d was not mirrored with an empty skip-list: %v", skipPort, lastErr)
}

// Leg 3, the sync direction — the one that matters for :22: a Mac listener on
// a skipped port must not reach the guest's mac_ports, or an in-guest
// `ssh localhost` would land on the Mac's sshd. Asserted through the existing
// reverse-path helper (a guest fetch of 127.0.0.1:port), with a second,
// unskipped Mac listener as the positive control: the negative only means
// something once the same pipeline has demonstrably carried a port through.
func TestSkipListKeepsMacListenerOutOfTheGuest(t *testing.T) {
	requireE2E(t)

	serve := func(body string) uint16 {
		t.Helper()
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		})}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
		return uint16(ln.Addr().(*net.TCPAddr).Port)
	}
	const controlBody, skippedBody = "drawbridge-skip-control-ok", "drawbridge-skip-leak"
	controlPort := serve(controlBody)
	skippedPort := serve(skippedBody)
	skip := map[uint16]bool{skippedPort: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	m.Skip = skip
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		Auth:      macAuth,
		// cmd/drawbridged's newExclude, inlined the way the other reverse-path
		// legs inline the production exclusion rule.
		Exclude: func(l macsync.Listener) bool {
			return skip[l.Port] || l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
		},
	}
	go m.Run(ctx)
	go s.Run(ctx)

	fetch := func(port uint16) (string, error) {
		return guest(t, fmt.Sprintf(
			`python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:%d/', timeout=5).read().decode())"`, port))
	}

	// Positive control first: the poll → 'M' → mac_ports → gateway path is up.
	deadline := time.Now().Add(20 * time.Second)
	for {
		out, err := fetch(controlPort)
		if err == nil && strings.Contains(out, controlBody) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("control Mac listener :%d never reachable from the guest: %v: %s", controlPort, err, out)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// The skipped port stays unreachable. Sustained, because the syncer polls
	// every 75ms — a single refused connect could just be an early sample.
	for i := 0; i < 6; i++ {
		out, err := fetch(skippedPort)
		if err == nil && strings.Contains(out, skippedBody) {
			t.Fatalf("skipped Mac listener :%d was synced into the guest and answered there", skippedPort)
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("Mac :%d served inside the guest; skipped Mac :%d absent from mac_ports", controlPort, skippedPort)
}
