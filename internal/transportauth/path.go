package transportauth

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// GuestPath is where `drawbridge up` puts the guest half (0600 root:root).
// It lives under the state directory `drawbridge down` removes wholesale, so
// the guest secret dies with the rest of the install and needs no teardown
// code of its own (§5). Spelled out rather than imported from guestbin: the
// agent links this package, and guestbin embeds the guest binaries.
const GuestPath = "/etc/drawbridge/transport-secret"

// DirName is the Mac-side directory under ~/Library/Application Support
// (mode 0700; the secrets in it are 0600).
const DirName = "drawbridge"

// FileName is the Mac-side secret filename for a VM. It derives from the
// *canonical* ref, never the user's spelling, so `colima:default` and
// `colima:colima` land on the same file. Instance names already passed
// ParseRef's allowlist grammar, so nothing here needs sanitizing.
func FileName(ref vmprovider.Ref) string {
	return "transport-secret-" + ref.Provider + "-" + ref.Instance
}

// Dir is the Mac-side secret directory for the invoking user.
func Dir() (string, error) {
	home, err := HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", DirName), nil
}

// PathForRef is the Mac-side secret path for a VM: the same derivation `up`
// writes with, `drawbridged` defaults to, and `install` renders into the
// LaunchDaemon plist — same file by construction (§5).
func PathForRef(ref vmprovider.Ref) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, FileName(ref)), nil
}

// HomeDir resolves the home directory the secret belongs to. Under sudo that
// is the invoking user's, not root's: the user is this system's trust root,
// `sudo drawbridge install` and `sudo drawbridged` must find the same file
// the unprivileged flow wrote (§5).
func HomeDir() (string, error) {
	return homeDirFor(os.Geteuid(), os.Getenv("SUDO_USER"), user.Lookup, os.UserHomeDir)
}

func homeDirFor(euid int, sudoUser string, lookup func(string) (*user.User, error), fallback func() (string, error)) (string, error) {
	if euid == 0 && sudoUser != "" {
		u, err := lookup(sudoUser)
		if err != nil {
			return "", fmt.Errorf("resolving SUDO_USER %q: %w", sudoUser, err)
		}
		if u.HomeDir == "" {
			return "", fmt.Errorf("SUDO_USER %q has no home directory", sudoUser)
		}
		return u.HomeDir, nil
	}
	return fallback()
}
