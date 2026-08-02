// OCI integration e2e (docs/oci-hook.md, Phase D), run from the Mac against
// the live dev VM: real docker containers under the drawbridge-runc default
// runtime get Phase 4 bind arbitration with zero cooperation from the
// workload — bindtry is a plain net.Listen. Requires `just vm-docker` once
// (and `just agent-up`); skips with instructions otherwise.
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
	"github.com/archcorsair/drawbridge/internal/mirror"
)

// requireDocker skips (actionably) unless the guest has docker provisioned
// with drawbridge-runc as the default runtime and the offline test image.
func requireDocker(t *testing.T) {
	t.Helper()
	out, err := guest(t, "docker image inspect drawbridge/bindtest >/dev/null && docker info --format '{{.DefaultRuntime}}'")
	if err != nil || !strings.Contains(out, "drawbridge") {
		t.Skipf("guest docker not provisioned for OCI e2e — run `just vm-docker` (%v: %s)", err, out)
	}
}

// containerBind runs bindtry inside a bindtest container and parses its
// JSON verdict. extraArgs picks the network mode.
func containerBind(t *testing.T, extraArgs, addr string, hold time.Duration) (seccompProbeResult, error) {
	t.Helper()
	out, err := guest(t, fmt.Sprintf(
		"docker run --rm %s drawbridge/bindtest /drawbridge-agent bindtry -addr %s -hold %s",
		extraArgs, addr, hold))
	if err != nil {
		return seccompProbeResult{}, fmt.Errorf("%v: %s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "{") {
			var r seccompProbeResult
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return r, fmt.Errorf("bad bindtry JSON %q: %w", line, err)
			}
			return r, nil
		}
	}
	return seccompProbeResult{}, fmt.Errorf("no bindtry result in %q", out)
}

// startDrawbridged wires the production mirror+syncer in-process and
// waits until a container bind on a free port round-trips (the 'R'
// reservation session is live and the wrapper chain works).
func startDrawbridged(t *testing.T) *mirror.Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
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

	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()
	deadline := time.Now().Add(45 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("container bind on free :%d never succeeded — wrapper chain broken?", freePort)
		}
		r, err := containerBind(t, "--network host", fmt.Sprintf("127.0.0.1:%d", freePort), 0)
		if err == nil && r.Errno == 0 {
			return m
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// A host-network container's bind onto a Mac-held port fails synchronously
// with Linux EADDRINUSE — Phase 4 semantics for a real, uncooperative
// docker workload. This is the feature.
func TestContainerBindGetsSynchronousEADDRINUSE(t *testing.T) {
	requireE2E(t)
	requireDocker(t)
	startDrawbridged(t)

	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	heldPort := held.Addr().(*net.TCPAddr).Port

	r, err := containerBind(t, "--network host", fmt.Sprintf("127.0.0.1:%d", heldPort), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Errno != linuxEADDRINUSE {
		t.Fatalf("container bind to Mac-held :%d = errno %d (%s), want EADDRINUSE(%d)",
			heldPort, r.Errno, r.Error, linuxEADDRINUSE)
	}
	t.Logf("container bind to Mac-held :%d refused synchronously with EADDRINUSE", heldPort)
}

// A host-network container's listener is mirrored onto Mac localhost — the
// Phase 2 inbound path end to end from a real container, with the mirror
// reserve-adopted rather than event-created.
func TestHostNetContainerListenerMirrored(t *testing.T) {
	requireE2E(t)
	requireDocker(t)
	m := startDrawbridged(t)

	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()

	// Detached container holds the listener while the Mac side connects.
	name := fmt.Sprintf("dbg-e2e-hold-%d", port)
	if out, err := guest(t, fmt.Sprintf(
		"docker run -d --rm --name %s --network host drawbridge/bindtest /drawbridge-agent bindtry -addr 127.0.0.1:%d -hold 30s",
		name, port)); err != nil {
		t.Fatalf("start holder container: %v: %s", err, out)
	}
	t.Cleanup(func() { guest(t, "docker rm -f "+name) })

	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if m.Mirrors("tcp", uint16(port)) {
			c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
			if err == nil {
				c.Close()
				t.Logf("container listener :%d mirrored and dialable on Mac localhost", port)
				return
			}
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("container listener :%d never mirrored on Mac localhost: %v", port, lastErr)
}

// A bridged container binding the same Mac-held port succeeds locally: the
// wrapper skips private-netns containers and the agent's netns backstop
// CONTINUEs anything that slips through — the scoping guarantee.
func TestBridgedContainerNotArbitrated(t *testing.T) {
	requireE2E(t)
	requireDocker(t)
	startDrawbridged(t)

	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	heldPort := held.Addr().(*net.TCPAddr).Port

	r, err := containerBind(t, "", fmt.Sprintf("0.0.0.0:%d", heldPort), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Errno != 0 {
		t.Fatalf("bridged container bind to :%d arbitrated: errno %d (%s), want 0",
			heldPort, r.Errno, r.Error)
	}
	t.Logf("bridged container bound :%d locally despite Mac holding it", heldPort)
}
