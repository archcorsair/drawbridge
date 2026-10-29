package main

import (
	"net"
	"os"
	"testing"
)

// shortDir is a socket directory short enough for sun_path on macOS (104
// bytes), which t.TempDir's nested path can exceed.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// 2026-10-28 M3, decision E2: the probe socket is root-only unless the
// agent is told otherwise, and the opt-in is the only way to 0666.
func TestListenNotifyMode(t *testing.T) {
	for _, tc := range []struct {
		name         string
		unprivileged bool
		want         os.FileMode
	}{
		{"default", false, 0o600},
		{"opt-in", true, 0o666},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := shortDir(t) + "/notify.sock"
			// A stale file from a previous agent is replaced, not an error.
			if err := os.WriteFile(path, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			ln, err := listenNotify(path, tc.unprivileged)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&os.ModeSocket == 0 {
				t.Fatalf("%s is %v, not a socket", path, fi.Mode())
			}
			if got := fi.Mode().Perm(); got != tc.want {
				t.Fatalf("mode %o, want %o", got, tc.want)
			}
			c, err := net.Dial("unix", path)
			if err != nil {
				t.Fatalf("socket does not accept: %v", err)
			}
			c.Close()
		})
	}
	if notifySockMode(false) != notifySockModeRoot || notifySockModeRoot != 0o600 {
		t.Fatalf("production default is %o, want 0600", notifySockMode(false))
	}
}
