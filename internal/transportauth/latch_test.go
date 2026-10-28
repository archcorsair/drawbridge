package transportauth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Every test here uses its own t.TempDir path: the latch is process-wide and
// keyed by path, so a shared path would carry one test's latch into another.

func writeSecretFile(t *testing.T, path string, s Secret) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s.Format()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func otherSecret() Secret {
	s := testSecret()
	for i := range s {
		s[i] ^= 0xa5
	}
	return s
}

// The whole lifecycle on one path: unauthenticated while the process has
// never had a secret there, then sticky. Absence after a load is a refusal
// that must not read as ErrAbsent (every ErrAbsent check means "no auth");
// a replaced file is simply the new secret; malformed stays malformed.
func TestLoadLatchedLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-secret")

	if s, err := LoadLatched(path); s != nil || err != nil {
		t.Fatalf("never configured: LoadLatched = %v, %v; want nil, nil", s, err)
	}
	if Configured(path) {
		t.Fatal("an absent file latched the path")
	}

	good := testSecret()
	writeSecretFile(t, path, good)
	if s, err := LoadLatched(path); err != nil || s == nil || *s != good {
		t.Fatalf("present: LoadLatched = %v, %v", s, err)
	}
	if !Configured(path) {
		t.Fatal("a successful load did not latch the path")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s, err := LoadLatched(path)
	if s != nil || !errors.Is(err, ErrConfiguredMissing) {
		t.Fatalf("loaded then deleted: LoadLatched = %v, %v; want ErrConfiguredMissing", s, err)
	}
	if errors.Is(err, ErrAbsent) {
		t.Fatalf("vanished secret wraps ErrAbsent (%v): callers would read it as unauthenticated mode", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file", err)
	}

	rotated := otherSecret()
	writeSecretFile(t, path, rotated)
	if s, err := LoadLatched(path); err != nil || s == nil || *s != rotated {
		t.Fatalf("replaced: LoadLatched = %v, %v; want the new secret", s, err)
	}

	if err := os.WriteFile(path, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLatched(path); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed: LoadLatched err = %v, want ErrMalformed", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLatched(path); !errors.Is(err, ErrConfiguredMissing) {
		t.Fatalf("malformed then deleted: err = %v, want ErrConfiguredMissing (the latch outlives a bad file)", err)
	}
}

// A present file latches even when it does not parse: it is evidence a
// secret was configured. Absent at boot, then a malformed file appears (a
// refusal, as always), then it is deleted: that must stay a refusal, not
// drop back to unauthenticated mode.
func TestLoadLatchedMalformedLatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-secret")
	if s, err := LoadLatched(path); s != nil || err != nil {
		t.Fatalf("absent: LoadLatched = %v, %v; want nil, nil", s, err)
	}
	if err := os.WriteFile(path, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadLatched(path); s != nil || !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed: LoadLatched = %v, %v; want ErrMalformed", s, err)
	}
	if !Configured(path) {
		t.Fatal("a present-but-malformed file did not latch the path")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if s, err := LoadLatched(path); s != nil || !errors.Is(err, ErrConfiguredMissing) {
		t.Fatalf("absent → malformed → deleted: LoadLatched = %v, %v; want ErrConfiguredMissing", s, err)
	}
	if _, err := (MacConfig{SecretFile: path}).Secret(); !isUnreadable(err) {
		t.Fatalf("absent → malformed → deleted: Secret() err = %v, want a %s refusal", err, CauseSecretUnreadable)
	}
}

// An explicit -secret-file states intent before any file exists: absence is
// a refusal from the first read, and the file appearing heals it.
func TestRequireWithoutFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-secret")
	Require(path)
	if !Configured(path) {
		t.Fatal("Require did not latch")
	}
	if s, err := LoadLatched(path); s != nil || !errors.Is(err, ErrConfiguredMissing) {
		t.Fatalf("required, never present: LoadLatched = %v, %v; want ErrConfiguredMissing", s, err)
	}
	m := MacConfig{SecretFile: path}
	if _, err := m.Secret(); !isUnreadable(err) {
		t.Fatalf("required, never present: Secret() err = %v, want a %s refusal", err, CauseSecretUnreadable)
	}
	good := testSecret()
	writeSecretFile(t, path, good)
	if s, err := m.Secret(); err != nil || s == nil || *s != good {
		t.Fatalf("file appeared: Secret() = %v, %v", s, err)
	}
}

func TestLatchEdges(t *testing.T) {
	Require("") // must not latch the "not configured" spelling
	if Configured("") {
		t.Fatal(`Require("") latched the empty path`)
	}
	if s, err := LoadLatched(""); s != nil || err != nil {
		t.Fatalf(`LoadLatched("") = %v, %v; want nil, nil`, s, err)
	}
	dir := t.TempDir()
	Require(dir + "//sub/../transport-secret")
	if !Configured(filepath.Join(dir, "transport-secret")) {
		t.Fatal("the latch is keyed on the raw spelling, not the cleaned path")
	}
}

func isUnreadable(err error) bool {
	c, ok := CauseOf(err)
	return ok && c == CauseSecretUnreadable
}

// The M6 scenario at the seam every Mac dial goes through. MacConfig is a
// value copied into each client before either dials, so the copy taken
// before the first load must still see the latch afterwards. Once latched, a
// deleted file is a row-8 refusal (so callers return before ClientHello and
// auth=0 never reaches the wire), and its line names the real remedy.
func TestMacConfigVanishedSecretRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-secret-colima-colima")
	good := testSecret()
	writeSecretFile(t, path, good)

	ring := &fakeRecorder{}
	base := MacConfig{SecretFile: path, VM: "colima:default", Throttle: NewThrottle(RefusalLogEvery), Refusals: ring}
	early := base // copied before any load, like mirror.Client and macsync.Syncer
	if s, err := base.Secret(); err != nil || s == nil || *s != good {
		t.Fatalf("Secret() = %v, %v", s, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	for name, m := range map[string]MacConfig{"original": base, "early copy": early, "fresh value": {SecretFile: path}} {
		s, err := m.Secret()
		if s != nil || !isUnreadable(err) {
			t.Fatalf("%s: Secret() = %v, %v; want a %s refusal, never nil-and-nil (auth=0)", name, s, err, CauseSecretUnreadable)
		}
	}

	_, err := base.Secret()
	ep := "127.0.0.1:4777"
	line := base.Diagnose(err, ep)
	for _, want := range []string{"transport secret is unusable", path, "drawbridge up colima:default", "refuses to dial", "no restart"} {
		if !strings.Contains(line, want) {
			t.Errorf("vanished-secret line %q missing %q", line, want)
		}
	}
	if strings.Contains(line, "64 hex") {
		t.Errorf("vanished-secret line %q prescribes the malformed-file fix", line)
	}
	if strings.Contains(line, good.Format()[:16]) {
		t.Fatalf("refusal line leaks secret bytes: %q", line)
	}
	if id := base.CheckID(err); id != CheckAuthFilePerms {
		t.Errorf("CheckID = %q, want %q", id, CheckAuthFilePerms)
	}
	if got := base.Report(err, ep); got != line {
		t.Errorf("Report = %q, want the diagnosis", got)
	}
	if len(ring.ids) != 1 || ring.ids[0] != CheckAuthFilePerms {
		t.Errorf("ring recorded %v, want one %s entry", ring.ids, CheckAuthFilePerms)
	}

	// Rotation heals without a restart.
	rotated := otherSecret()
	writeSecretFile(t, path, rotated)
	if s, err := early.Secret(); err != nil || s == nil || *s != rotated {
		t.Fatalf("after rotation: Secret() = %v, %v; want the new secret", s, err)
	}
}

type fakeRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (r *fakeRecorder) Record(id, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
}

// Concurrent dials against a file being deleted and rewritten (the rotation
// window, and down's rm under a running process): once latched, no read may
// ever come back as nil-and-nil. Torn reads of a file mid-rewrite are allowed
// to fail (they are refusals too); a returned secret must be one of the two
// that were written. Run with -race.
func TestLoadLatchedConcurrentNeverDowngrades(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-secret")
	a, b := testSecret(), otherSecret()
	writeSecretFile(t, path, a)
	if _, err := LoadLatched(path); err != nil {
		t.Fatal(err)
	}

	m := MacConfig{SecretFile: path}
	var stop atomic.Bool
	var downgrades, refusals, loads atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				s, err := m.Secret()
				switch {
				case err == nil && s == nil:
					downgrades.Add(1)
				case err != nil:
					if !isUnreadable(err) {
						t.Errorf("unexpected error shape: %v", err)
						return
					}
					refusals.Add(1)
				case *s != a && *s != b:
					t.Errorf("read a secret nobody wrote")
					return
				default:
					loads.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 300; i++ {
		os.Remove(path)
		next := a
		if i%2 == 1 {
			next = b
		}
		if err := os.WriteFile(path, []byte(next.Format()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	os.Remove(path)
	// At least one read is guaranteed to see the deleted state.
	if s, err := m.Secret(); s == nil && err == nil {
		downgrades.Add(1)
	}
	stop.Store(true)
	wg.Wait()
	if n := downgrades.Load(); n != 0 {
		t.Fatalf("%d reads downgraded to unauthenticated after the secret was loaded", n)
	}
	t.Logf("%d loads, %d refusals, 0 downgrades", loads.Load(), refusals.Load())
}
