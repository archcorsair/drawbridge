package tui

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// shortHome is a HOME with a deliberately short path: the user run dir hangs
// off it and sun_path is 104 bytes, so t.TempDir()'s long name cannot be used
// for a directory that will hold a socket (the introspect package's own
// discipline). Isolating HOME also keeps the real Application Support
// directory out of every test that derives a path.
func shortHome(t *testing.T) string {
	t.Helper()
	base := ""
	if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "dbt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	return dir
}

// The one test that speaks to a real socket: fetchCmd against a live
// introspect.Listen, through Discover, exactly as the daemon serves it.
func TestFetchCmdReadsALiveSocket(t *testing.T) {
	shortHome(t)
	path, err := introspect.UserSocketPath("lima", "dev")
	if err != nil {
		t.Fatal(err)
	}
	want := healthySnap().State
	srv, err := introspect.Listen(path, os.Geteuid(), func() introspect.State { return want })
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Serve()

	msg, ok := fetchCmd().(snapshotsMsg)
	if !ok {
		t.Fatalf("fetchCmd returned %T", fetchCmd())
	}
	if msg.at.IsZero() {
		t.Fatal("the message carries no fetch time — staleness has nothing to count from")
	}
	var got *introspect.Snapshot
	for _, s := range msg.snaps {
		if s.Path == path {
			got = s
		}
	}
	if got == nil {
		t.Fatalf("the live socket %s is not among %d snapshots", path, len(msg.snaps))
	}
	if !got.Usable || got.State.PID != want.PID || len(got.State.Mirror.Entries) != len(want.Mirror.Entries) {
		t.Fatalf("snapshot did not round-trip: %+v", got.State)
	}

	// And the model renders it: the fetch path and the view meet here and
	// nowhere else in the tests.
	m := newModel(Options{CLIVersion: "v0.1.0"})
	m.width, m.height = 120, 40
	m.now = time.Now()
	m, _ = send(m, msg)
	if m.selected == "" {
		t.Fatal("a live snapshot did not select a daemon")
	}
	// On a developer's Mac a real daemon's socket may be discovered alongside
	// ours and win the default selection, so pin the view to the test socket.
	m = m.selectPath(path)
	if v := m.View(); !strings.Contains(v, "tcp://192.168.64.5:4777") {
		t.Fatalf("the fetched snapshot is not on screen:\n%s", v)
	}
}

// A socket that answers with something unreadable is a problem, not a
// snapshot: the TUI must name it and keep going.
func TestFetchProblemsSurfaceWithoutADaemon(t *testing.T) {
	shortHome(t)
	m := newModel(Options{CLIVersion: "v0.1.0"})
	m.width, m.height = 120, 40
	msg := fetchCmd().(snapshotsMsg)
	m, _ = send(m, msg)
	// Nothing of ours is listening; on a developer's Mac a real daemon may be,
	// so only the no-crash and guard-release properties are asserted here.
	if m.wantFetch() != true {
		t.Fatal("the in-flight guard did not reopen after a fetch")
	}
	if m.View() == "" {
		t.Fatal("an empty fetch rendered nothing at all")
	}
}
