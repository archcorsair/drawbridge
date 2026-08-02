package transportauth

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMacConfigSecretClassifiesFailures(t *testing.T) {
	dir := t.TempDir()
	good := testSecret()
	path := filepath.Join(dir, "transport-secret")
	if err := os.WriteFile(path, []byte(good.Format()), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Configured and readable.
	if s, err := (MacConfig{SecretFile: path}).Secret(); err != nil || s == nil || *s != good {
		t.Fatalf("Secret() = %v, %v", s, err)
	}
	// Unconfigured, and configured-but-absent, are the same mode.
	for _, p := range []string{"", filepath.Join(dir, "missing")} {
		if s, err := (MacConfig{SecretFile: p}).Secret(); err != nil || s != nil {
			t.Fatalf("Secret(%q) = %v, %v; want nil, nil", p, s, err)
		}
	}
	// Malformed is a refusal, so it reaches the log as row 8's diagnosis.
	_, err := (MacConfig{SecretFile: bad}).Secret()
	if cause, ok := CauseOf(err); !ok || cause != CauseSecretUnreadable {
		t.Fatalf("Secret(malformed) cause = %v (%v), want %s", cause, err, CauseSecretUnreadable)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Secret(malformed) = %v, want it to wrap ErrMalformed", err)
	}
}

func TestDiagnoseRows(t *testing.T) {
	m := MacConfig{
		SecretFile: "/Users/x/Library/Application Support/drawbridge/transport-secret-colima-colima",
		VM:         "colima:default",
		Source:     func() string { return "forwarder" },
	}
	ep := "127.0.0.1:4777"

	// Row 5: the wrong-peer line must name the VM and the resolution source —
	// that is what makes a forwarder-fallback attach self-explaining.
	row5 := m.Diagnose(refuse(CauseProofMismatch, nil), ep)
	for _, want := range []string{ep, "NOT the agent", "colima:default", "source=forwarder", "loopback forwarder"} {
		if !strings.Contains(row5, want) {
			t.Errorf("row 5 %q missing %q", row5, want)
		}
	}

	// Row 4: EOF and ECONNRESET are one condition, so both render the same
	// line — the diagnosis keys on the cause, never on the errno.
	eof := m.Diagnose(refuse(CauseIncomplete, io.EOF), ep)
	reset := m.Diagnose(refuse(CauseIncomplete, errors.New("read: connection reset by peer")), ep)
	if eof != reset {
		t.Errorf("row 4 differs by errno:\n%q\n%q", eof, reset)
	}
	for _, want := range []string{"closed during transport authentication", "drawbridge up colima:default"} {
		if !strings.Contains(eof, want) {
			t.Errorf("row 4 %q missing %q", eof, want)
		}
	}

	// Row 6 names the file this daemon would have used.
	row6 := m.ClosedEarly(ep)
	for _, want := range []string{"closed the connection immediately", m.SecretFile, "drawbridge up", "drawbridge install"} {
		if !strings.Contains(row6, want) {
			t.Errorf("row 6 %q missing %q", row6, want)
		}
	}

	// An ordinary I/O error is not a refusal: callers must keep handling it
	// as one, rather than mislabel a dead VM as an auth failure.
	if got := m.Diagnose(io.EOF, ep); got != "" {
		t.Errorf("Diagnose(io.EOF) = %q, want \"\"", got)
	}
	if got := m.Wrap(io.EOF, ep); !errors.Is(got, io.EOF) {
		t.Errorf("Wrap(io.EOF) = %v, want it to pass through", got)
	}

	// Wrap's message is the diagnosis; the cause stays reachable.
	wrapped := m.Wrap(refuse(CauseProofMismatch, nil), ep)
	if wrapped.Error() != row5 {
		t.Errorf("Wrap message = %q, want the row 5 line", wrapped.Error())
	}
	if cause, ok := CauseOf(wrapped); !ok || cause != CauseProofMismatch {
		t.Errorf("Wrap lost the cause: %v", cause)
	}

	// Missing context degrades to placeholders rather than to an empty
	// sentence — a line with a hole in it is still actionable.
	bare := MacConfig{}
	if got := bare.Diagnose(refuse(CauseProofMismatch, nil), ep); !strings.Contains(got, "<vm>") || !strings.Contains(got, "source=unknown") {
		t.Errorf("bare diagnosis = %q", got)
	}
	if got := bare.ClosedEarly(ep); !strings.Contains(got, "no path derived") {
		t.Errorf("bare row 6 = %q", got)
	}
}

func TestThrottle(t *testing.T) {
	now := time.Now()
	tr := NewThrottle(RefusalLogEvery)
	tr.now = func() time.Time { return now }

	if !tr.Allow("a") {
		t.Fatal("first line suppressed")
	}
	if tr.Allow("a") {
		t.Fatal("second line inside the window was allowed")
	}
	if !tr.Allow("b") {
		t.Fatal("an unrelated key was suppressed by another key's flood")
	}
	now = now.Add(RefusalLogEvery)
	if !tr.Allow("a") {
		t.Fatal("the window never reopened")
	}

	// A nil throttle is "no throttling", so a client built without one still
	// says everything it has to say.
	var nilT *Throttle
	for i := 0; i < 3; i++ {
		if !nilT.Allow("a") {
			t.Fatal("nil throttle suppressed a line")
		}
	}

	// AllowLine keys on cause and endpoint together.
	m := MacConfig{Throttle: NewThrottle(RefusalLogEvery)}
	err := refuse(CauseProofMismatch, nil)
	if !m.AllowLine(err, "ep1") || m.AllowLine(err, "ep1") {
		t.Fatal("AllowLine does not throttle per endpoint")
	}
	if !m.AllowLine(err, "ep2") {
		t.Fatal("one endpoint muted another")
	}
	if !m.AllowLine(refuse(CauseIncomplete, nil), "ep1") {
		t.Fatal("one cause muted another")
	}
}
