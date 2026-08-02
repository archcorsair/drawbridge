package introspect

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sample is a snapshot with something in every branch of the payload, so a
// round-trip proves the whole document survives and not just its head.
func sample() State {
	return State{
		Schema:     Schema,
		Version:    "v0.1.0",
		PID:        4242,
		EUID:       501,
		StartedAt:  time.Date(2026, 8, 1, 18, 0, 0, 0, time.UTC),
		VM:         VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
		MirrorIP:   "127.0.0.1",
		Resolution: Resolution{Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct", ResolvedAt: time.Date(2026, 8, 1, 18, 0, 1, 0, time.UTC)},
		Auth:       Auth{Mode: AuthModeStaticHMACv1, SecretPath: "/Users/x/secret", SecretState: SecretOK},
		Mirror: Mirror{
			SessionUp: true,
			Entries:   []MirrorEntry{{Proto: "tcp", Port: 8080, State: EntryBound}, {Proto: "tcp", Port: 22, State: EntrySkipped}},
			Skip:      []uint16{22},
		},
		Sync: Sync{
			SessionUp:  true,
			Advertised: []Advertised{{Proto: "tcp", Port: 5432}},
			UDPPorts:   []uint16{5353},
			PoolParked: 4,
		},
		RecentRefusals: []Refusal{{At: time.Date(2026, 8, 1, 18, 22, 0, 0, time.UTC), ID: "auth-mismatch", Line: "agent closed during transport authentication"}},
	}
}

// shortDir is a temp directory with a deliberately short path. t.TempDir()
// spends most of sun_path's 104 bytes on $TMPDIR plus the test's own name —
// the very limit CheckPath exists for — so socket tests cannot use it. It is
// still a temp dir with the same cleanup, and never a real drawbridge path.
func shortDir(t *testing.T) string {
	t.Helper()
	base := ""
	if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "dbi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func sockPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(shortDir(t), "s.sock")
}

func serve(t *testing.T, path string, snapshot func() State) *Server {
	t.Helper()
	srv, err := Listen(path, os.Geteuid(), snapshot)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve()
	return srv
}

func TestRoundTrip(t *testing.T) {
	path := sockPath(t)
	want := sample()
	serve(t, path, func() State { return want })

	got, err := Fetch(path, time.Second)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !got.Usable {
		t.Fatalf("snapshot reported unusable at schema %d", got.State.Schema)
	}
	if got.Path != path {
		t.Fatalf("Path = %q, want %q", got.Path, path)
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got.State)
	if string(a) != string(b) {
		t.Fatalf("payload changed across the wire:\n got %s\nwant %s", b, a)
	}
}

// The protocol is write-only: the daemon must never read a byte from a
// client, so a client that talks first — garbage, a request grammar someone
// hoped for, anything — still gets its complete snapshot. This is the
// property that makes the socket undriveable (docs/doctor.md D2).
func TestServerNeverReads(t *testing.T) {
	path := sockPath(t)
	serve(t, path, sample)

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(`{"op":"shutdown"}` + strings.Repeat("\x00", 512))); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var st State
	if err := json.NewDecoder(conn).Decode(&st); err != nil {
		t.Fatalf("decode after client wrote first: %v", err)
	}
	if st.Version != "v0.1.0" || st.Sync.PoolParked != 4 {
		t.Fatalf("truncated snapshot after a talkative client: %+v", st)
	}
}

// A consumer that connects and never reads must not pin the endpoint: the
// write deadline expires, the conn is dropped, and the next reader is served.
func TestWriteDeadlineFreesTheSlot(t *testing.T) {
	path := sockPath(t)
	big := sample()
	// Bigger than the socket buffer (macOS defaults to 8 KiB) so the write
	// blocks, and well under the client's payload cap so recovery is
	// observable through a normal Fetch.
	for i := 0; i < 3000; i++ {
		big.RecentRefusals = append(big.RecentRefusals, Refusal{ID: "x", Line: strings.Repeat("y", 64)})
	}
	srv, err := Listen(path, os.Geteuid(), func() State { return big })
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()
	srv.WriteTimeout = 200 * time.Millisecond // set before Serve reads it
	go srv.Serve()

	var silent []net.Conn
	for i := 0; i < maxInFlight; i++ {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		silent = append(silent, c)
	}
	defer func() {
		for _, c := range silent {
			c.Close()
		}
	}()

	// Every slot is now held by a client that will never read. Once the
	// deadlines fire the loop recovers on its own.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := Fetch(path, 2*time.Second); err == nil {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("endpoint never recovered from non-reading clients: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// More concurrent dials than the in-flight cap: excess connections wait in
// the backlog and are served, none are dropped.
func TestConcurrentDialsPastTheCap(t *testing.T) {
	path := sockPath(t)
	serve(t, path, sample)

	const n = maxInFlight * 4
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			snap, err := Fetch(path, 5*time.Second)
			if err == nil && snap.State.Version != "v0.1.0" {
				err = errors.New("incomplete snapshot")
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
}

// A crashed daemon leaves the socket file behind. Connecting to it is
// ECONNREFUSED, which the client reports as absent, and the next daemon
// unlinks it and binds in its place.
func TestStaleSocketIsAbsentThenRebindable(t *testing.T) {
	path := sockPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ln.SetUnlinkOnClose(false) // what a crash leaves behind
	ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stale socket file missing: %v", err)
	}

	if _, err := Fetch(path, time.Second); !errors.Is(err, ErrAbsent) {
		t.Fatalf("Fetch on a stale socket = %v, want ErrAbsent", err)
	}
	serve(t, path, sample)
	if _, err := Fetch(path, time.Second); err != nil {
		t.Fatalf("Fetch after unlink-then-bind: %v", err)
	}
}

// Listen must not unlink something that is not a socket: a mistyped
// -introspect path is a startup error, never a deletion.
func TestListenRefusesNonSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, os.Geteuid(), sample); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "keep me" {
		t.Fatalf("file was touched: %q %v", b, err)
	}
}

// The unprivileged flavor is private to the user: 0700 dir, 0600 socket (D3).
func TestUserSocketPermissions(t *testing.T) {
	dir := filepath.Join(shortDir(t), "run")
	path := filepath.Join(dir, "s.sock")
	serve(t, path, sample)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %o, want 600", got)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Fatalf("dir mode = %o, want 700", got)
	}
}

// Asking for the root flavor without being root: the mode is applied, the
// ownership change is not, and that is reported rather than fatal — a
// permission step that fails leaves the socket narrower, never wider.
func TestRootFlavorWithoutPrivilegeNarrowsAndReports(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the failure this pins cannot happen")
	}
	path := sockPath(t)
	srv, err := Listen(path, 0, sample)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()
	if srv.Note == "" {
		t.Fatal("chown failure went unreported")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %o, want 660", got)
	}
}
