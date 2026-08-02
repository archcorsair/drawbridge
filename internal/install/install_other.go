//go:build !darwin

package install

// The install story is macOS-only by design (docs/privileged-daemon.md §11
// q3): what it installs is a launchd daemon, and the guest side stays
// `just agent-up` — nothing here manages guest state. The stubs exist so the
// CLI stays a single portable program (and `GOOS=linux go vet ./...` stays
// clean) rather than growing build tags of its own.

import (
	"errors"
)

// ErrNeedRoot keeps the API shape identical across platforms.
var ErrNeedRoot = errUnsupported

var errUnsupported = errors.New("drawbridge install/uninstall/status is macOS-only (it manages a launchd daemon)")

func Install(cfg Config, binSrc string, step Step) (Status, error) { return Status{}, errUnsupported }

func Uninstall(step Step) error { return errUnsupported }

func Query() Status { return Status{} }

// InstalledVersion has nothing to ask on a non-macOS host: there is no
// LaunchDaemon there to have installed.
func InstalledVersion() (string, error) { return "", ErrNotInstalled }
