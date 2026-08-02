package transportauth

import (
	"errors"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func ref(t *testing.T, spec string) vmprovider.Ref {
	t.Helper()
	r, err := vmprovider.ParseRef(spec)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", spec, err)
	}
	return r
}

// The filename derives from the canonical ref, not the user's spelling: the
// two ways to name colima's default VM must reach the same secret, or `up`
// and `drawbridged` provision and read different files for one guest (§5).
func TestFileNameUsesCanonicalRef(t *testing.T) {
	if a, b := FileName(ref(t, "colima:default")), FileName(ref(t, "colima:colima")); a != b {
		t.Fatalf("colima:default → %q but colima:colima → %q", a, b)
	}
	for _, tc := range []struct{ spec, want string }{
		{"drawbridge", "transport-secret-lima-drawbridge"},
		{"lima:drawbridge", "transport-secret-lima-drawbridge"},
		{"colima:colima", "transport-secret-colima-colima"},
		{"colima:default", "transport-secret-colima-colima"},
		{"colima:work", "transport-secret-colima-colima-work"},
	} {
		if got := FileName(ref(t, tc.spec)); got != tc.want {
			t.Errorf("FileName(%q) = %q, want %q", tc.spec, got, tc.want)
		}
	}

	// Different VMs never share a secret — that is the whole per-VM scope
	// decision (§2): a Mac-wide secret would authenticate the wrong-peer
	// attach cleanly.
	if FileName(ref(t, "drawbridge")) == FileName(ref(t, "colima:colima")) {
		t.Fatal("two providers share one secret file")
	}
}

func TestPathForRefLivesUnderApplicationSupport(t *testing.T) {
	p, err := PathForRef(ref(t, "colima:default"))
	if err != nil {
		t.Fatal(err)
	}
	dir, file := filepath.Split(p)
	if file != "transport-secret-colima-colima" {
		t.Errorf("basename = %q", file)
	}
	if !strings.HasSuffix(filepath.Clean(dir), filepath.Join("Library", "Application Support", DirName)) {
		t.Errorf("directory = %q, want ~/Library/Application Support/%s", dir, DirName)
	}
	if !filepath.IsAbs(p) {
		t.Errorf("path %q is not absolute", p)
	}
}

// Under sudo the secret belongs to the invoking user, not to root: `sudo
// drawbridge install` and `sudo drawbridged` must find the file the
// unprivileged flow wrote (§5).
func TestHomeDirIsSudoUserAware(t *testing.T) {
	lookup := func(name string) (*user.User, error) {
		switch name {
		case "alice":
			return &user.User{Username: "alice", HomeDir: "/Users/alice"}, nil
		case "homeless":
			return &user.User{Username: "homeless"}, nil
		}
		return nil, errors.New("unknown user")
	}
	fallback := func() (string, error) { return "/var/root", nil }

	t.Run("root with SUDO_USER", func(t *testing.T) {
		got, err := homeDirFor(0, "alice", lookup, fallback)
		if err != nil || got != "/Users/alice" {
			t.Fatalf("homeDirFor = %q, %v; want /Users/alice", got, err)
		}
	})
	t.Run("root without SUDO_USER", func(t *testing.T) {
		got, err := homeDirFor(0, "", lookup, fallback)
		if err != nil || got != "/var/root" {
			t.Fatalf("homeDirFor = %q, %v; want the ambient home", got, err)
		}
	})
	t.Run("unprivileged ignores SUDO_USER", func(t *testing.T) {
		// A stale SUDO_USER in the environment of a non-root process must
		// not redirect the lookup.
		got, err := homeDirFor(501, "alice", lookup, fallback)
		if err != nil || got != "/var/root" {
			t.Fatalf("homeDirFor = %q, %v; want the ambient home", got, err)
		}
	})
	t.Run("unknown SUDO_USER fails closed", func(t *testing.T) {
		if _, err := homeDirFor(0, "nobody-here", lookup, fallback); err == nil {
			t.Fatal("unknown SUDO_USER resolved instead of erroring")
		}
	})
	t.Run("home-less SUDO_USER fails closed", func(t *testing.T) {
		if _, err := homeDirFor(0, "homeless", lookup, fallback); err == nil {
			t.Fatal("SUDO_USER without a home resolved instead of erroring")
		}
	})
}
