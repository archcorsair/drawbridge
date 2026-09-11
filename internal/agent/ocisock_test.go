package agent

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// An empty owner is the rootful case: the socket keeps root's 0600 and
// nothing is touched at all.
func TestOwnOCISocketEmptyIsANoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oci.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := OwnOCISocket(path, ""); err != nil {
		t.Fatalf("empty owner = %v, want a no-op", err)
	}
}

// Chowning to the user we already are is permitted unprivileged, which is
// what makes the success path testable off a guest: what it pins is that
// the mode is still 0600 afterwards, since "one named user, not the world"
// is half owner and half mode.
func TestOwnOCISocketKeepsMode0600(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if me.Username == "" {
		t.Skip("current user has no name to look up")
	}
	path := filepath.Join(t.TempDir(), "oci.sock")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := OwnOCISocket(path, me.Username); err != nil {
		t.Fatalf("OwnOCISocket(%q) = %v", me.Username, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600 — the socket hands out seccomp notify fds", perm)
	}
}

// A configured owner that does not resolve is fatal, not a warning: an
// agent that continued would look healthy and arbitrate nothing, which is
// exactly the failure the flag exists to prevent.
func TestOwnOCISocketRefusesUnknownUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oci.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := OwnOCISocket(path, "drawbridge-no-such-user")
	if err == nil {
		t.Fatal("an unknown owner was accepted")
	}
	if !strings.Contains(err.Error(), "-oci-sock-owner") || !strings.Contains(err.Error(), "drawbridge up") {
		t.Fatalf("the refusal names neither the flag nor the remedy: %v", err)
	}
}

// A missing socket is an error too: the caller has just bound it, so the
// only way here is a path that is not the one in use.
func TestOwnOCISocketRefusesMissingPath(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Username == "" {
		t.Skip("no current user")
	}
	if err := OwnOCISocket(filepath.Join(t.TempDir(), "absent.sock"), me.Username); err == nil {
		t.Fatal("chowning a socket that is not there succeeded")
	}
}
