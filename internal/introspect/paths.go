package introspect

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// RootSocketPath is the privileged daemon's endpoint. Fixed, not per-VM: the
// LaunchDaemon is a singleton (D3).
const RootSocketPath = "/var/run/drawbridge/introspect.sock"

// RootSocketDir is the directory the root daemon creates at startup
// (0755 root:wheel — traversable so a staff consumer can reach the 0660
// socket inside it).
var RootSocketDir = filepath.Dir(RootSocketPath)

// socketGlob matches the per-VM user sockets. Foreground daemons are per-VM,
// so discovery globs rather than assumes.
const socketGlob = "introspect-*.sock"

// maxSunPath is macOS's sockaddr_un.sun_path size, NUL included; Linux
// allows 108, so the smaller bound is the portable one to enforce. Only
// pathological home paths get near it, but the failure mode without the
// check is a bare "invalid argument" from bind.
const maxSunPath = 104

// UserRunDir is the unprivileged daemon's socket directory (0700; private to
// the user, who is its only consumer). It sits under the same Application
// Support directory as the transport secrets, and resolves through the same
// home-directory rule — under sudo that is the invoking user's home, so a
// consumer run with sudo still finds the foreground daemon's sockets.
func UserRunDir() (string, error) {
	dir, err := transportauth.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "run"), nil
}

// UserSocketPath is the unprivileged daemon's socket for one VM. The
// provider/instance pair is the canonical one (vmprovider.Ref), already
// through ParseRef's allowlist grammar, so nothing here needs sanitizing.
func UserSocketPath(provider, instance string) (string, error) {
	dir, err := UserRunDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "introspect-"+provider+"-"+instance+".sock"), nil
}

// AutoPath is `-introspect auto`: the D3 path for the euid the daemon runs
// as. Root is the singleton path; anyone else gets their own per-VM socket.
func AutoPath(euid int, ref vmprovider.Ref) (string, error) {
	if euid == 0 {
		return RootSocketPath, nil
	}
	return UserSocketPath(ref.Provider, ref.Instance)
}

// CheckPath rejects a socket path the OS cannot bind, with a sentence
// instead of an errno.
func CheckPath(path string) error {
	if path == "" {
		return fmt.Errorf("introspect: empty socket path")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("introspect: socket path %q must be absolute", path)
	}
	if len(path)+1 > maxSunPath {
		return fmt.Errorf("introspect: socket path is %d bytes, over the %d-byte unix-socket limit: %s — pass a shorter -introspect path, or -introspect off",
			len(path), maxSunPath-1, path)
	}
	return nil
}

// Discover lists the introspection sockets that exist on this Mac: the root
// socket first, then the user run dir's, sorted. Existence is not liveness —
// a stale file survives a crash, and the client reports the connect refusal
// as absent. Both flavors answering is itself a finding (the fighting-daemons
// posture), so this returns every candidate rather than the first hit.
func Discover() []string {
	var out []string
	if isSocket(RootSocketPath) {
		out = append(out, RootSocketPath)
	}
	dir, err := UserRunDir()
	if err != nil {
		return out
	}
	matches, err := filepath.Glob(filepath.Join(dir, socketGlob))
	if err != nil {
		return out
	}
	sort.Strings(matches)
	for _, m := range matches {
		if isSocket(m) {
			out = append(out, m)
		}
	}
	return out
}

// VMFromSocketPath reads the provider/instance a user socket was named for.
// It is a hint for consumers deciding which socket to try first; the payload
// names its own vm.ref, and that is what a consumer matches on.
func VMFromSocketPath(path string) (provider, instance string, ok bool) {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "introspect-") || !strings.HasSuffix(base, ".sock") {
		return "", "", false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(base, "introspect-"), ".sock")
	provider, instance, ok = strings.Cut(mid, "-")
	if !ok || provider == "" || instance == "" {
		return "", "", false
	}
	return provider, instance, true
}

func isSocket(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSocket != 0
}
