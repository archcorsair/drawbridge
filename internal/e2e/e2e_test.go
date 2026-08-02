// End-to-end suites, run from the Mac against the live dev VM. Phase 2:
// guest listener → fexit tracker → agent events → drawbridged mirror on Mac
// localhost → 'S' stream splice → guest loopback. Phase 3: Mac listener →
// pcblist_n poll → 'M' sync → mac_ports rewrite → gateway proxy → 'D'
// reverse stream → Mac loopback. Requires the dev VM running with the agent
// installed (`just agent-up`). Gated: set DRAWBRIDGE_E2E=1 (use `just e2e`).
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/benchtool"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/macsync"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// vmRef is which VM the suite drives. DRAWBRIDGE_VM takes drawbridged's own
// -vm grammar (`colima:colima`, `lima:myvm`, or a bare Lima instance name),
// which is what makes docs/verify-colima.md a repeatable recipe rather than
// a set of instructions to edit this file: CI never has a Colima VM, so the
// written recipe is the verification artifact and it has to actually run.
var (
	vmRef  = parseVMRef()
	vmName = vmRef.Instance
)

// macAuth is the suite's Mac-side transport-auth config, loaded once by
// requireE2E: DRAWBRIDGE_SECRET_FILE (the sibling of DRAWBRIDGE_AGENT) wins,
// then the per-VM default `drawbridge up` writes, and an absent file means
// unauthenticated — which is the mode the dev flow (`just agent-up`, no `up`)
// runs in (docs/transport-auth.md §6).
var macAuth transportauth.MacConfig

// newMirror is the seam every test builds its mirror client through (the
// syncers carry `Auth: macAuth` at their literals), so no leg can quietly run
// unauthenticated against a provisioned guest.
func newMirror(addr string) *mirror.Client {
	m := mirror.New(addr, "127.0.0.1")
	m.Auth = macAuth
	return m
}

func loadMacAuth(t *testing.T) transportauth.MacConfig {
	t.Helper()
	cfg := transportauth.MacConfig{VM: vmRef.Spec}
	if p := os.Getenv("DRAWBRIDGE_SECRET_FILE"); p != "" {
		cfg.SecretFile = p
	} else if p, err := transportauth.PathForRef(vmRef); err == nil {
		cfg.SecretFile = p
	}
	sec, err := cfg.Secret()
	if err != nil {
		t.Fatalf("transport secret: %v", err)
	}
	if sec == nil {
		t.Logf("transport auth: none (no secret at %q) — the agent must be unprovisioned too", cfg.SecretFile)
	} else {
		t.Logf("transport auth: enabled (%s)", cfg.SecretFile)
	}
	return cfg
}

func parseVMRef() vmprovider.Ref {
	spec := os.Getenv("DRAWBRIDGE_VM")
	if spec == "" {
		spec = defaultVM
	}
	r, err := vmprovider.ParseRef(spec)
	if err != nil {
		panic("DRAWBRIDGE_VM=" + spec + ": " + err.Error())
	}
	return r
}

const (
	defaultVM = "drawbridge"
	agentPort = 4777
	httpPort  = 47999
	// sinkPort must sit outside the guest autobind range (32768–60999 is
	// UDP-only in the mirror, but keep both suites in the same 479xx block).
	sinkPort = 47998
	unitName = "dbg-e2e-http"
	// forwardedPort is the Lima-forwarded agent port on Mac loopback — the
	// fallback transport TestForwarderHalfClose pins.
	forwardedPort = "4777"
)

// agentAddr is resolved by requireE2E: vzNAT direct TCP when reachable,
// else the SSH-forwarded loopback.
var agentAddr string

func limactl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// limactl refuses to run as root, and root's $LIMA_HOME isn't the
	// user's anyway. Under `just e2e-root` (sudo) drop back to the invoking
	// user for every limactl call; the transport itself stays root-side.
	argv := append([]string{"limactl"}, args...)
	// A colima instance lives in colima's own LIMA_HOME; prefix `env` rather
	// than set cmd.Env so the override survives the sudo re-exec below, which
	// scrubs the environment.
	if vmRef.LimaHome != "" {
		argv = append([]string{"env", "LIMA_HOME=" + vmRef.LimaHome}, argv...)
	}
	if os.Geteuid() == 0 {
		su := os.Getenv("SUDO_USER")
		if su == "" || su == "root" {
			return "", fmt.Errorf("running as root without SUDO_USER; run via sudo from your user account")
		}
		argv = append([]string{"sudo", "-u", su, "-H", "--"}, argv...)
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func guest(t *testing.T, script string) (string, error) {
	t.Helper()
	return limactl(t, "shell", vmName, "--", "sudo", "bash", "-c", script)
}

// requireE2E gates on the env flag and a running VM with a reachable agent.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("DRAWBRIDGE_E2E") == "" {
		t.Skip("set DRAWBRIDGE_E2E=1 (or run `just e2e`)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not on PATH")
	}
	if out, err := limactl(t, "list", "--format", "{{.Status}}", vmName); err != nil || out != "Running" {
		t.Skipf("VM %s not running (%q, %v) — run `just vm-up && just agent-up`", vmName, out, err)
	}
	macAuth = loadMacAuth(t)
	agentAddr = resolveAgent(t)
	c, err := transport.Dial(agentAddr)
	if err != nil {
		t.Fatalf("agent transport not reachable at %s — run `just agent-up`: %v", agentAddr, err)
	}
	c.Close()
}

// resolveAgent picks the endpoint the suite runs against, and says so: a
// green run must be attributable to the path it actually tested. The
// DRAWBRIDGE_AGENT override skips resolution entirely — it is how the
// forwarder gets a full-suite run on demand now that vznat-direct is the
// resolved default (docs/transport.md §2.5).
func resolveAgent(t *testing.T) string {
	t.Helper()
	if ep := os.Getenv("DRAWBRIDGE_AGENT"); ep != "" {
		e, err := transport.Parse(ep)
		if err != nil {
			t.Fatalf("DRAWBRIDGE_AGENT=%q: %v", ep, err)
		}
		t.Logf("agent transport: %s source=override:%s", e.String(), ep)
		return e.String()
	}
	r := limaaddr.ResolveTarget(limaaddr.Target{VM: vmRef.Instance, LeaseName: vmRef.LeaseName, LimaHome: vmRef.LimaHome}, agentPort)
	t.Logf("agent transport: %s source=%s", r.Endpoint, r.Source)
	if r.Note != "" {
		t.Logf("agent transport note: %s", r.Note)
	}
	return r.Endpoint
}

// requireAttributableMirror skips a mirror leg when the provider's own port
// forwarder would republish the guest listener on Mac loopback: reachability
// then proves nothing about drawbridge. Not hypothetical — the dev template's
// ignore rule matched guestIP 127.0.0.1 only until 2026-07-31, so Lima's
// hostagent satisfied the wildcard-bind legs with drawbridged stopped
// (docs/ergonomics.md §8, Phase 2 results), and colima's stock instances
// forward everything. guestBind is the address the guest listener binds,
// which picks the detector's answer set. Detection is user-scoped limactl
// (ErrRootScoped under euid 0), so under `just e2e-root` the guard defers to
// the user-run suite that covers the same legs.
func requireAttributableMirror(t *testing.T, guestBind string, port int) {
	t.Helper()
	if os.Geteuid() == 0 {
		return
	}
	fwd, err := vmprovider.ForRef(vmRef).Forwarding(vmName)
	if err != nil {
		t.Fatalf("provider forwarding detection: %v", err)
	}
	claimed := fwd.Wildcard
	if guestBind == "127.0.0.1" {
		claimed = fwd.Loopback
	}
	if fwd.HostAgent && claimed.Contains(port) {
		t.Skipf("%s forwards guest %s:%d itself — green here would not be attributable to drawbridge (%s); widen the instance's ignore rule (lima/drawbridge-dev.yaml)",
			vmRef.Provider, guestBind, port, fwd)
	}
	t.Logf("attribution: %s", fwd)
}

func TestGuestListenerReachableOnMacLocalhost(t *testing.T) {
	requireE2E(t)
	requireAttributableMirror(t, "0.0.0.0", httpPort)

	// Start drawbridged (mirror client) in-process.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go newMirror(agentAddr).Run(ctx)

	// Start an HTTP server inside the guest.
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", unitName, unitName))
	if out, err := guest(t, fmt.Sprintf(
		"systemd-run --unit=%s --collect python3 -m http.server %d --bind 0.0.0.0", unitName, httpPort)); err != nil {
		t.Fatalf("start guest http server: %v: %s", err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", unitName)) })

	// The full path: fexit event → agent → drawbridged mirror → splice.
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", httpPort))
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 && strings.Contains(string(body), "Directory listing") {
				t.Logf("guest :%d served on Mac localhost via drawbridge (%d bytes)", httpPort, len(body))
				return
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("guest listener never became reachable on Mac localhost:%d: %v", httpPort, lastErr)
}

// TestForwarderHalfClose guards the one property that made `just vm-up` pin
// LIMA_SSH_PORT_FORWARDER=true: a half-close must survive the forwarded
// transport, or every upload-then-ack flow dies. Since the Local Network
// grant every other test rides vznat-direct, so without this the fallback
// path would go untested until the day it is needed. It forces the
// forwarder explicitly and runs the upload-then-ack body — the same
// property TestUploadThroughSpliceChain covers in-process, here across the
// real 'S' stream (docs/transport.md §2.5; a full duplicate matrix was
// rejected, this is the one forced-forwarder smoke).
func TestForwarderHalfClose(t *testing.T) {
	requireE2E(t)

	const fwdAddr = "tcp://127.0.0.1:" + forwardedPort
	c, err := transport.Dial(fwdAddr)
	if err != nil {
		t.Skipf("forwarded agent port not answering at %s (Lima forward down?): %v", fwdAddr, err)
	}
	c.Close()
	t.Logf("agent transport: %s source=forced-forwarder", fwdAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(fwdAddr)
	go m.Run(ctx)

	// A guest sink: discards until the client's FIN, then writes a 1-byte
	// ack. The ack only ever arrives if the half-close crossed the
	// transport.
	unit := unitName + "-sink"
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", unit, unit))
	if out, err := guest(t, fmt.Sprintf(
		"systemd-run --unit=%s --collect %s benchserve -listen :%d -mode sink", unit, guestAgentBin(t), sinkPort)); err != nil {
		t.Fatalf("start guest sink: %v: %s", err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", unit)) })

	deadline := time.Now().Add(20 * time.Second)
	for !m.Mirrors("tcp", sinkPort) {
		if time.Now().After(deadline) {
			t.Fatalf("guest sink :%d never mirrored", sinkPort)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Warm-up: a zero-byte upload is the same half-close handshake with no
	// payload, so it retries cheaply while the splice chain settles.
	mirrorAddr := fmt.Sprintf("127.0.0.1:%d", sinkPort)
	deadline = time.Now().Add(20 * time.Second)
	var lastErr error
	for {
		if _, lastErr = benchtool.Upload(mirrorAddr, 0); lastErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest sink :%d never acked through the forwarder: %v", sinkPort, lastErr)
		}
		time.Sleep(300 * time.Millisecond)
	}

	const n = 16 << 20
	d, err := benchtool.Upload(mirrorAddr, n)
	if err != nil {
		t.Fatalf("upload-then-ack through the forwarder: %v", err)
	}
	t.Logf("%d MiB uploaded through the SSH forwarder, half-close acked in %v", n>>20, d)
}

// UDP outbound (docs/udp.md U3): real Mac UDP echo services on loopback
// are reachable from inside the guest at the same 127.0.0.1:port —
// unconnected demux across two ports, a connected round trip, and two
// concurrent guest clients on one port.
func TestMacUDPServiceReachableFromGuest(t *testing.T) {
	requireE2E(t)

	startEcho := func(prefix string) uint16 {
		t.Helper()
		uc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { uc.Close() })
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := uc.ReadFromUDPAddrPort(buf)
				if err != nil {
					return
				}
				uc.WriteToUDPAddrPort(append([]byte(prefix), buf[:n]...), from)
			}
		}()
		return uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	}
	p1, p2 := startEcho("E1:"), startEcho("E2:")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		Auth:      macAuth,
		Exclude: func(l macsync.Listener) bool {
			return l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
		},
		UDPPorts: []uint16{p1, p2},
	}
	go m.Run(ctx)
	go s.Run(ctx)

	// Retry-from-the-guest helper: the first datagrams race sync + stream
	// activation, and drops are legal UDP.
	tryGuest := func(desc, script, want string) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		var last string
		for time.Now().Before(deadline) {
			out, err := guest(t, script)
			if err == nil && strings.Contains(out, want) {
				t.Logf("%s: ok", desc)
				return
			}
			last = fmt.Sprintf("%v: %s", err, out)
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s never succeeded: %s", desc, last)
	}

	tryGuest("unconnected two-port demux", fmt.Sprintf(`python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(b'q1', ('127.0.0.1', %d))
s.sendto(b'q2', ('127.0.0.1', %d))
got = {}
for _ in range(2):
    d, a = s.recvfrom(65535)
    got[a[1]] = d.decode()
print(got.get(%d), got.get(%d))
"`, p1, p2, p1, p2), "E1:q1 E2:q2")

	tryGuest("connected round trip", fmt.Sprintf(`python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('127.0.0.1', %d))
s.settimeout(2)
s.send(b'ping')
print(s.recv(65535).decode())
"`, p1), "E1:ping")

	tryGuest("two concurrent guest clients", fmt.Sprintf(`python3 -c "
import socket
a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
a.settimeout(2); b.settimeout(2)
a.sendto(b'ca', ('127.0.0.1', %d))
b.sendto(b'cb', ('127.0.0.1', %d))
print(a.recvfrom(65535)[0].decode(), b.recvfrom(65535)[0].decode())
"`, p1, p1), "E1:ca E1:cb")
}

// UDP inbound (docs/udp.md U2): a guest UDP echo server is reachable on
// Mac localhost with datagram boundaries and per-client reply routing
// preserved across the framed proto-17 stream.
func TestGuestUDPListenerReachableOnMacLocalhost(t *testing.T) {
	requireE2E(t)

	// UDP echo inside the guest. Port must be outside the guest autobind
	// range (mirrors skip 32768-60999 by design).
	const udpPort = 25999
	requireAttributableMirror(t, "0.0.0.0", udpPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	go m.Run(ctx)
	unit := unitName + "-udp"
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", unit, unit))
	echo := fmt.Sprintf(`python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', %d))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d.upper(), a)
"`, udpPort)
	if out, err := guest(t, fmt.Sprintf("systemd-run --unit=%s --collect %s", unit, echo)); err != nil {
		t.Fatalf("start guest udp echo: %v: %s", err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", unit)) })

	deadline := time.Now().Add(15 * time.Second)
	for !m.Mirrors("udp", udpPort) {
		if time.Now().After(deadline) {
			t.Fatalf("guest udp :%d never mirrored", udpPort)
		}
		time.Sleep(200 * time.Millisecond)
	}

	dial := func() *net.UDPConn {
		t.Helper()
		c, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", udpPort))
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UDPConn)
	}
	rt := func(c *net.UDPConn, msg string) {
		t.Helper()
		want := strings.ToUpper(msg)
		dl := time.Now().Add(10 * time.Second)
		buf := make([]byte, 65536)
		for {
			if time.Now().After(dl) {
				t.Fatalf("no echo for %d-byte datagram", len(msg))
			}
			c.Write([]byte(msg))
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if n, err := c.Read(buf); err == nil {
				if got := string(buf[:n]); got != want {
					t.Fatalf("echo mismatch: %d bytes got, %d want", len(got), len(want))
				}
				return
			}
		}
	}

	// Three concurrent clients each get their own replies…
	c1, c2, c3 := dial(), dial(), dial()
	defer c1.Close()
	defer c2.Close()
	defer c3.Close()
	rt(c1, "client-one")
	rt(c2, "client-two")
	rt(c3, "client-three")
	// …and a multi-MTU datagram survives with its boundary intact (8 kB:
	// macOS caps UDP sends at net.inet.udp.maxdgram, 9216 by default).
	rt(c1, strings.Repeat("m", 8000))
	t.Logf("guest udp :%d served on Mac localhost via drawbridge (3 clients + 8kB datagram)", udpPort)
}

// Phase 4: a guest bind to a port the Mac already owns fails synchronously
// with EADDRINUSE — Linux-correct semantics across the VM boundary, which
// async mirroring cannot provide. The bind probe stands in for a container
// process under the OCI hook; the agent supervises its seccomp notify fd.
func TestGuestBindGetsSynchronousEADDRINUSE(t *testing.T) {
	requireE2E(t)

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

	// A real Mac listener the guest must not be allowed to bind over.
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	heldPort := held.Addr().(*net.TCPAddr).Port

	// The reservation RPC must be live before the verdict means anything;
	// the free-port probe there also proves the CONTINUE path works.
	waitBindArbitrationLive(t)

	r, err := guestBindProbe(t, heldPort)
	if err != nil {
		t.Fatal(err)
	}
	// The errno crosses the VM boundary as a number from the guest's
	// kernel, so it is Linux's EADDRINUSE (98) — not this test binary's
	// darwin syscall.EADDRINUSE (48).
	if r.Errno != linuxEADDRINUSE {
		t.Fatalf("guest bind to Mac-held :%d = errno %d (%s), want EADDRINUSE(%d)",
			heldPort, r.Errno, r.Error, linuxEADDRINUSE)
	}
	t.Logf("guest bind to Mac-held :%d refused synchronously with EADDRINUSE", heldPort)
}

// guestBindProbe runs the agent's `bindprobe` in the guest and parses its
// JSON verdict — a seccomp-supervised bind whose errno crosses the VM
// boundary as a number from the guest kernel. Shared with the privileged-port
// legs in privileged_test.go.
func guestBindProbe(t *testing.T, port int) (seccompProbeResult, error) {
	t.Helper()
	out, err := guest(t, fmt.Sprintf("%s bindprobe -addr 127.0.0.1:%d -hold 0s", guestAgentBin(t), port))
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

// waitBindArbitrationLive blocks until a guest bind onto a known-free port
// round-trips with errno 0 — proof that the 'R' reservation session is up (and
// that the CONTINUE path works), so a later refusal is a real verdict rather
// than a not-yet-connected supervisor.
func waitBindArbitrationLive(t *testing.T) {
	t.Helper()
	free, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	free.Close()

	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("guest bind to free port :%d never succeeded — is the agent's notify socket up?", freePort)
		}
		r, err := guestBindProbe(t, freePort)
		if err == nil && r.Errno == 0 {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type seccompProbeResult struct {
	Errno int    `json:"errno"`
	Error string `json:"error,omitempty"`
}

// linuxEADDRINUSE is the guest kernel's EADDRINUSE value (asm-generic).
const linuxEADDRINUSE = 98

// guestAgentBin is the agent binary path, identical on both sides of the
// rw mount.
func guestAgentBin(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../bin/drawbridge-agent-linux-arm64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("guest binary missing (run `just build`): %v", err)
	}
	return p
}

// Phase 3: a native Mac loopback service becomes reachable from inside the
// guest at the same 127.0.0.1:port — the milestone flow (container reaches
// Mac Postgres), with an ephemeral HTTP server standing in for Postgres.
func TestMacListenerReachableFromGuest(t *testing.T) {
	requireE2E(t)

	// Mac-side HTTP server on loopback, ephemeral port.
	const body = "drawbridge-phase3-ok"
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	port := ln.Addr().(*net.TCPAddr).Port

	// drawbridged wiring, in-process: mirror + syncer with the production
	// exclusion rule.
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

	// The full path: pcblist_n poll → 'M' sync → connect4 rewrite →
	// gateway proxy → 'D' reverse stream → Mac loopback dial.
	fetch := fmt.Sprintf(
		`python3 -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:%d/', timeout=5).read().decode())"`, port)
	deadline := time.Now().Add(20 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out, err := guest(t, fetch)
		if err == nil && strings.Contains(out, body) {
			t.Logf("Mac 127.0.0.1:%d served inside the guest via drawbridge", port)
			return
		}
		last = fmt.Sprintf("%v: %s", err, out)
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("Mac listener 127.0.0.1:%d never became reachable from the guest: %s", port, last)
}
