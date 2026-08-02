package introspect

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// HOME is isolated in every test that derives a path (the secret_test.go
// discipline): the real Application Support directory is never touched.
func homeDir(t *testing.T) string {
	t.Helper()
	home := shortDir(t) // sockets get bound under it; sun_path is 104 bytes
	t.Setenv("HOME", home)
	return home
}

func TestUserPathDerivation(t *testing.T) {
	home := homeDir(t)
	got, err := UserSocketPath("colima", "colima")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Library", "Application Support", "drawbridge", "run", "introspect-colima-colima.sock")
	if got != want {
		t.Fatalf("UserSocketPath = %q, want %q", got, want)
	}
}

// auto is per-euid: root is the singleton path, anyone else gets their own
// per-VM socket (D3).
func TestAutoPath(t *testing.T) {
	homeDir(t)
	ref, err := vmprovider.ParseRef("lima:drawbridge")
	if err != nil {
		t.Fatal(err)
	}
	root, err := AutoPath(0, ref)
	if err != nil {
		t.Fatal(err)
	}
	if root != RootSocketPath {
		t.Fatalf("AutoPath(0) = %q, want %q", root, RootSocketPath)
	}
	user, err := AutoPath(501, ref)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(user, "introspect-lima-drawbridge.sock") {
		t.Fatalf("AutoPath(501) = %q", user)
	}
}

// A pathological home path must produce a sentence at startup, not a bare
// "invalid argument" from bind.
func TestCheckPathLength(t *testing.T) {
	if err := CheckPath(RootSocketPath); err != nil {
		t.Fatalf("the root path must be bindable: %v", err)
	}
	long := "/" + strings.Repeat("d", 110) + "/s.sock"
	err := CheckPath(long)
	if err == nil {
		t.Fatal("an over-long path was accepted")
	}
	if !strings.Contains(err.Error(), "unix-socket limit") {
		t.Fatalf("error does not name the limit: %v", err)
	}
	if err := CheckPath("relative/s.sock"); err == nil {
		t.Fatal("a relative path was accepted")
	}
	if err := CheckPath(""); err == nil {
		t.Fatal("an empty path was accepted")
	}
}

// Listen refuses the same over-long path, so the check is not decoration a
// caller can forget.
func TestListenRejectsOverLongPath(t *testing.T) {
	if _, err := Listen("/"+strings.Repeat("d", 110)+"/s.sock", os.Geteuid(), sample); err == nil {
		t.Fatal("Listen accepted an over-long path")
	}
}

// Discovery lists what exists — a socket file, not a stale regular file — and
// returns every candidate, because root and user daemons both answering is
// itself a finding.
func TestDiscover(t *testing.T) {
	home := homeDir(t)
	runDir := filepath.Join(home, "Library", "Application Support", "drawbridge", "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "introspect-not-a.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"introspect-lima-a.sock", "introspect-colima-b.sock"} {
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(runDir, name), Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
	}
	got := Discover()
	// The root socket may exist on a developer's Mac; only the user half is
	// asserted here.
	var user []string
	for _, p := range got {
		if p != RootSocketPath {
			user = append(user, filepath.Base(p))
		}
	}
	want := []string{"introspect-colima-b.sock", "introspect-lima-a.sock"}
	if strings.Join(user, ",") != strings.Join(want, ",") {
		t.Fatalf("Discover user sockets = %v, want %v", user, want)
	}
}

func TestVMFromSocketPath(t *testing.T) {
	provider, instance, ok := VMFromSocketPath("/x/run/introspect-colima-colima.sock")
	if !ok || provider != "colima" || instance != "colima" {
		t.Fatalf("= %q %q %v", provider, instance, ok)
	}
	if _, _, ok := VMFromSocketPath("/x/run/other.sock"); ok {
		t.Fatal("an unrelated socket name parsed as a VM")
	}
}
