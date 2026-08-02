package mirror

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// Phase 4.5 (docs/transport-auth.md): the Mac side of the mutual proof, seen
// through the mirror client. Every test here answers one question — does a
// payload byte ever cross to a peer we did not verify?

func newSecret(t *testing.T) *transportauth.Secret {
	t.Helper()
	s, err := transportauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func macConfig(t *testing.T, s *transportauth.Secret) transportauth.MacConfig {
	t.Helper()
	cfg := transportauth.MacConfig{VM: "colima:default", Source: func() string { return "forwarder" }}
	if s == nil {
		return cfg
	}
	p := filepath.Join(t.TempDir(), "transport-secret")
	if err := os.WriteFile(p, []byte(s.Format()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.SecretFile = p
	return cfg
}

func runClient(t *testing.T, fa *fakeAgent, auth transportauth.MacConfig) *Client {
	t.Helper()
	m := New(fa.ln.Addr().String(), "127.0.0.1")
	m.Auth = auth
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go m.Run(ctx)
	return m
}

func waitRefusal(t *testing.T, fa *fakeAgent, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case why := <-fa.refusals:
			if strings.Contains(why, want) {
				return
			}
		case <-deadline:
			t.Fatalf("the agent never refused a conn with %q", want)
		}
	}
}

func waitLogContains(t *testing.T, sink *logSink, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := sink.String(); strings.Contains(got, want) {
			return got
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("log never contained %q:\n%s", want, sink.String())
	return ""
}

// Mutual success across every conn type this client opens: 'E' (the session
// that drives mirroring), 'S' (the splice), and 'R' (the parked reservation
// RPC). Under auth the streams behave exactly as they did unauthenticated.
func TestMutualAuthAllConnTypes(t *testing.T) {
	secret := newSecret(t)
	guestPort := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: guestPort, Addr: "0.0.0.0"}})
	fa.secret = secret

	m := runClient(t, fa, macConfig(t, secret))

	// 'E': the snapshot arrived and the mirror is open.
	waitFor(t, "the mirror", func() bool { return m.Mirrors("tcp", guestPort) })

	// 'R': the reservation conn parked.
	select {
	case <-fa.parked:
	case <-time.After(5 * time.Second):
		t.Fatal("the reservation conn never parked")
	}

	// 'S': a client of the mirror round-trips through an authenticated splice.
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", guestPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello guest")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("hello guest"))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("splice echo: %v", err)
	}
	if string(buf) != "hello guest" {
		t.Fatalf("echo = %q", buf)
	}
	select {
	case s := <-fa.streams:
		if s.proto != 6 || s.port != guestPort {
			t.Fatalf("stream header = proto %d port %d, want 6/%d", s.proto, s.port, guestPort)
		}
	default:
		t.Fatal("no 'S' conn recorded")
	}
}

// §7 row 5, the demonstrated failure: something that is not our agent answers
// the probe and proves a secret we do not share. Nothing may be trusted from
// it — no mirror opens off its snapshot — and the line must name the VM and
// the resolution source, because a forwarder-fallback attach is exactly how
// this happens.
func TestSessionRefusesWrongAgentProof(t *testing.T) {
	sink := captureLog(t)
	secret, squatter := newSecret(t), newSecret(t)
	guestPort := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: guestPort, Addr: "0.0.0.0"}})
	fa.secret, fa.answerWith = secret, squatter

	m := runClient(t, fa, macConfig(t, secret))

	line := waitLogContains(t, sink, "invalid transport secret")
	for _, want := range []string{"NOT the agent", "colima:default", "source=forwarder", "loopback forwarder"} {
		if !strings.Contains(line, want) {
			t.Errorf("log missing %q:\n%s", want, line)
		}
	}
	if m.Mirrors("tcp", guestPort) {
		t.Fatal("mirrored a listener announced by an unverified peer")
	}
}

// The 'S' gate: not one client byte crosses before proof_agent verifies.
// This is the leak the phase exists to close — a splice to a squatter would
// hand it whatever the client sent first.
func TestSpliceGatesClientBytesOnProof(t *testing.T) {
	captureLog(t)
	secret, squatter := newSecret(t), newSecret(t)
	guestPort := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: guestPort, Addr: "0.0.0.0"}})
	fa.secret = secret

	m := runClient(t, fa, macConfig(t, secret))
	waitFor(t, "the mirror", func() bool { return m.Mirrors("tcp", guestPort) })

	// The peer turns hostile between the session and the splice: from now on
	// it answers with a proof it minted from its own secret.
	fa.answerWith = squatter

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", guestPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("PASSWORD hunter2")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-fa.payloads:
		t.Fatalf("client bytes %q crossed to an unverified peer", got)
	case <-time.After(500 * time.Millisecond):
	}
	// And the client is dropped rather than left hanging on a dead splice.
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	if n, err := c.Read(b[:]); n != 0 || err == nil {
		t.Fatalf("client conn still open: n=%d err=%v", n, err)
	}
}

// §7 row 4: our proof is rejected and the conn dies mid-handshake. The
// diagnosis must not depend on whether the kernel reported EOF or
// ECONNRESET — both mean the same thing.
func TestSessionDiagnosesMismatchOnClose(t *testing.T) {
	sink := captureLog(t)
	guestPort := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: guestPort, Addr: "0.0.0.0"}})
	fa.secret = newSecret(t) // not the Mac's

	m := runClient(t, fa, macConfig(t, newSecret(t)))

	line := waitLogContains(t, sink, "closed during transport authentication")
	if !strings.Contains(line, "drawbridge up colima:default") {
		t.Errorf("log does not name the convergence command:\n%s", line)
	}
	waitRefusal(t, fa, "invalid transport secret")
	if m.Mirrors("tcp", guestPort) {
		t.Fatal("mirrored a listener we never authenticated")
	}
}

// §7 row 6: we have no secret, and the guest hangs up the moment our
// unauthenticated hello lands. The likeliest cause is a provisioned guest, so
// the line names the file this daemon would have used and how to get one.
func TestUnauthenticatedClientDiagnosesEarlyClose(t *testing.T) {
	sink := captureLog(t)
	fa := newFakeAgent(t, nil)
	fa.closeAfterFrame = true

	auth := macConfig(t, nil)
	auth.SecretFile = filepath.Join(t.TempDir(), "transport-secret-colima-colima")
	runClient(t, fa, auth)

	line := waitLogContains(t, sink, "closed the connection immediately")
	for _, want := range []string{auth.SecretFile, "drawbridge up", "drawbridge install"} {
		if !strings.Contains(line, want) {
			t.Errorf("log missing %q:\n%s", want, line)
		}
	}
}

// A malformed secret file fails closed on every dial: configured-but-unusable
// must never degrade into trusting whoever answers (§5, §7 row 8).
func TestMalformedSecretRefusesToDial(t *testing.T) {
	sink := captureLog(t)
	guestPort := freeTCPPort(t)
	fa := newFakeAgent(t, []listenerInfo{{Proto: "tcp", Port: guestPort, Addr: "0.0.0.0"}})

	bad := filepath.Join(t.TempDir(), "transport-secret")
	if err := os.WriteFile(bad, []byte("nonsense\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	auth := macConfig(t, nil)
	auth.SecretFile = bad
	m := runClient(t, fa, auth)

	waitLogContains(t, sink, "transport secret is unusable")
	if m.Mirrors("tcp", guestPort) {
		t.Fatal("mirrored despite an unusable secret")
	}
	select {
	case s := <-fa.streams:
		t.Fatalf("opened an 'S' conn (proto %d) with an unusable secret", s.proto)
	case <-time.After(300 * time.Millisecond):
	}
}
