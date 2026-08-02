//go:build linux

package agent

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// serveDispatch runs the real accept/dispatch path against a pool-only Agent
// (no BPF, so this stays runnable without the maps loaded) and returns the
// Mac-side dialer. secretFile is the agent's -secret-file value: "" (or a
// path with no file) is unauthenticated mode.
func serveDispatch(t *testing.T, secretFile string) (*Agent, func(t *testing.T) net.Conn, <-chan string) {
	return serveDispatchAt(t, secretFile, nil)
}

// serveDispatchAt is serveDispatch with the throttle's clock under test
// control. The clock is installed before the accept loop starts: the field is
// read from conn goroutines.
func serveDispatchAt(t *testing.T, secretFile string, now func() time.Time) (*Agent, func(t *testing.T) net.Conn, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	logs := make(chan string, 32)
	a := &Agent{pool: newDialPool(), SecretFile: secretFile, now: now}
	a.logf = func(format string, args ...any) {
		select {
		case logs <- fmt.Sprintf(format, args...):
		default:
		}
	}
	t.Cleanup(func() { a.pool.close() })
	go a.ServeTransport(ln)
	return a, func(t *testing.T) net.Conn {
		t.Helper()
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}, logs
}

// writeSecret drops a secret file in a temp dir and returns its path.
func writeSecret(t *testing.T, s transportauth.Secret) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "transport-secret")
	if err := os.WriteFile(p, []byte(s.Format()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newSecret(t *testing.T) transportauth.Secret {
	t.Helper()
	s, err := transportauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// waitLog returns the first captured log line containing want.
func waitLog(t *testing.T, logs <-chan string, want string) string {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case line := <-logs:
			if strings.Contains(line, want) {
				return line
			}
		case <-deadline:
			t.Fatalf("no log line containing %q", want)
		}
	}
}

// expectClosed asserts the agent closed the conn: refusal is a closed conn,
// never a warning-and-continue. EOF or ECONNRESET both qualify — a refusal
// that leaves the peer's unread hello bytes in the receive buffer (rows 3
// and 8 close without draining the 32 proof bytes) surfaces as a reset, not
// a clean FIN. Only a timeout — i.e. a conn still open — is a failure.
func expectClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil || isTimeout(err) {
		t.Fatalf("%s: read n=%d err=%v, want the conn closed", what, n, err)
	}
}

func poolLen(a *Agent) int {
	a.pool.mu.Lock()
	defer a.pool.mu.Unlock()
	return len(a.pool.conns)
}

func waitPoolLen(t *testing.T, a *Agent, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if poolLen(a) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pool holds %d conns, want %d", poolLen(a), want)
}

// A framed 'D' conn must park exactly as a lone type byte did: frame and
// handshake are consumed pre-dispatch, the watchdog stays armed on a
// byte-silent conn, and the popped conn's stream starts at the activation
// header. Under auth the silence is asserted *after* the mutual exchange —
// the whole handshake happens in the pre-park dispatch phase, so the parked
// wire is byte-identical to the unauthenticated one
// (docs/transport-auth.md §3.3).
func TestFramedDialConnParksSilent(t *testing.T) {
	secret := newSecret(t)
	for _, tc := range []struct {
		name       string
		secretFile string
		sec        *transportauth.Secret
	}{
		{"unauthenticated", "", nil},
		{"authenticated", writeSecret(t, secret), &secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, dial, _ := serveDispatch(t, tc.secretFile)
			c := dial(t)
			frame, err := transportauth.ClientHello(c, tc.sec, 'D', nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := transportauth.AwaitAgentProof(c, tc.sec, frame, 2*time.Second); err != nil {
				t.Fatalf("agent proof: %v", err)
			}
			waitPoolLen(t, a, 1)

			// Byte-silent while parked: after the handshake the agent must
			// write nothing at all before activation.
			c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			var b [1]byte
			if n, err := c.Read(b[:]); n != 0 || !isTimeout(err) {
				t.Fatalf("parked conn not byte-silent: n=%d err=%v", n, err)
			}
			c.SetReadDeadline(time.Time{})

			// Poppable and activatable: the watchdog hands off (it must not
			// have been tripped by a leftover handshake deadline) and the Mac
			// sees the 4-byte activation header as the next bytes on the conn.
			got, err := a.pool.pop(time.Second)
			if err != nil {
				t.Fatalf("pop: %v", err)
			}
			hdr := []byte{6, 0x1f, 0x90, 0}
			if _, err := got.Write(hdr); err != nil {
				t.Fatalf("activate: %v", err)
			}
			var rd [4]byte
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(c, rd[:]); err != nil {
				t.Fatalf("read activation header: %v", err)
			}
			if string(rd[:]) != string(hdr) {
				t.Fatalf("activation header %v, want %v", rd, hdr)
			}
		})
	}
}

// Frame byte 1 is the auth-scheme byte (0 or 1); bytes 2–3 stay the
// reserved-zero version escape hatch. Anything else must close the conn
// before park/dispatch, never degrade into a stream.
func TestFrameNonzeroReservedRejected(t *testing.T) {
	for _, frame := range [][]byte{
		{'D', 0, 1, 0},
		{'D', 0, 0, 1},
		{'D', 1, 1, 0},
		{'D', 2, 0, 0}, // unknown auth scheme (a future auth=2 peer)
		{'D', 0xff, 0, 0},
	} {
		a, dial, _ := serveDispatch(t, "")
		c := dial(t)
		if _, err := c.Write(frame); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, fmt.Sprintf("frame %v", frame))
		if got := poolLen(a); got != 0 {
			t.Fatalf("frame %v: pool holds %d conns, want 0", frame, got)
		}
	}
}

// §6/§7 mode matrix, from the agent's vantage point. Every refusal is a
// closed conn plus a line naming the condition, the likeliest cause, and the
// command that fixes it.
func TestAuthModeMatrixDispatch(t *testing.T) {
	secret := newSecret(t)
	other := newSecret(t)
	secretFile := writeSecret(t, secret)

	// Row 1: this guest has a secret, the peer sent auth=0.
	t.Run("peer unauthenticated", func(t *testing.T) {
		a, dial, logs := serveDispatch(t, secretFile)
		c := dial(t)
		if _, err := transportauth.ClientHello(c, nil, 'D', nil); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, "auth=0 against a secretful guest")
		if got := poolLen(a); got != 0 {
			t.Fatalf("pool holds %d conns, want 0", got)
		}
		line := waitLog(t, logs, "peer sent no authentication")
		for _, want := range []string{"refused 'D' conn from", "drawbridge install"} {
			if !strings.Contains(line, want) {
				t.Errorf("log line %q missing %q", line, want)
			}
		}
	})

	// Row 2: both sides configured, different secrets.
	t.Run("proof mismatch", func(t *testing.T) {
		a, dial, logs := serveDispatch(t, secretFile)
		c := dial(t)
		frame, err := transportauth.ClientHello(c, &other, 'M', nil)
		if err != nil {
			t.Fatal(err)
		}
		// The Mac's own view of the same failure: the conn dies before the
		// agent proof arrives (§7 row 4).
		if err := transportauth.AwaitAgentProof(c, &other, frame, 3*time.Second); err == nil {
			t.Fatal("agent answered a proof minted from the wrong secret")
		}
		if got := poolLen(a); got != 0 {
			t.Fatalf("pool holds %d conns, want 0", got)
		}
		line := waitLog(t, logs, "invalid transport secret")
		if !strings.Contains(line, "drawbridge up") {
			t.Errorf("log line %q does not name the convergence command", line)
		}
	})

	// Row 3: the peer requires auth, this guest has no secret.
	t.Run("guest missing secret", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "transport-secret")
		a, dial, logs := serveDispatch(t, missing)
		c := dial(t)
		if _, err := transportauth.ClientHello(c, &secret, 'S', []byte{6, 0x1f, 0x90, 0}); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, "auth=1 against a secretless guest")
		if got := poolLen(a); got != 0 {
			t.Fatalf("pool holds %d conns, want 0", got)
		}
		line := waitLog(t, logs, "this guest has no transport secret")
		if !strings.Contains(line, missing) {
			t.Errorf("log line %q does not name the missing file", line)
		}
	})

	// Row 8: a configured secret that cannot be parsed fails closed on every
	// conn, exactly like a wrong one — never a degrade to trusting everyone.
	t.Run("malformed secret", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "transport-secret")
		if err := os.WriteFile(bad, []byte("not-a-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, dial, logs := serveDispatch(t, bad)
		c := dial(t)
		if _, err := transportauth.ClientHello(c, &secret, 'E', nil); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, "malformed guest secret")
		waitLog(t, logs, "transport secret is unusable")
	})

	// Mutual success still dispatches: the 'D' conn parks (covered above),
	// and an 'S' conn's stream header survives the handshake intact.
	t.Run("mutual success keeps the stream header", func(t *testing.T) {
		backend, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		go func() {
			b, err := backend.Accept()
			if err != nil {
				return
			}
			io.Copy(b, b)
		}()
		port := uint16(backend.Addr().(*net.TCPAddr).Port)

		_, dial, _ := serveDispatch(t, secretFile)
		c := dial(t)
		hdr := []byte{6, byte(port >> 8), byte(port), 0}
		frame, err := transportauth.ClientHello(c, &secret, 'S', hdr)
		if err != nil {
			t.Fatal(err)
		}
		if err := transportauth.AwaitAgentProof(c, &secret, frame, 3*time.Second); err != nil {
			t.Fatalf("agent proof: %v", err)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		var echo [4]byte
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(c, echo[:]); err != nil {
			t.Fatalf("splice echo: %v", err)
		}
		if string(echo[:]) != "ping" {
			t.Fatalf("echo = %q, want \"ping\"", echo)
		}
	})
}

// Refusal lines are throttled to one per (cause, source) per 30s: the Mac
// retries every second, and journal spam would bury the diagnosis (§7).
func TestRefusalLogThrottle(t *testing.T) {
	secretFile := writeSecret(t, newSecret(t))
	now := time.Now()
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}
	_, dial, logs := serveDispatchAt(t, secretFile, clock)

	refuse := func() {
		t.Helper()
		c := dial(t)
		if _, err := transportauth.ClientHello(c, nil, 'D', nil); err != nil {
			t.Fatal(err)
		}
		expectClosed(t, c, "unauthenticated peer")
	}

	refuse()
	waitLog(t, logs, "peer sent no authentication")
	for i := 0; i < 5; i++ { // same cause, same source, inside the window
		refuse()
	}
	advance(authLogEvery - time.Second)
	refuse()
	select {
	case line := <-logs:
		t.Fatalf("throttle leaked a line inside the window: %q", line)
	case <-time.After(300 * time.Millisecond):
	}

	// A different cause is a different key, so it is never suppressed by an
	// unrelated flood.
	c := dial(t)
	other := newSecret(t)
	if _, err := transportauth.ClientHello(c, &other, 'D', nil); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "invalid transport secret")

	// And the window eventually reopens.
	advance(2 * time.Second)
	refuse()
	waitLog(t, logs, "peer sent no authentication")
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
