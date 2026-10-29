// The OCI listenerPath socket's ownership (docs/podman.md §6.3).
//
// Deliberately not linux-tagged, like listen.go and gvproxy.go: this is
// os/user and os.Chown, and its unit tests run on the Mac alongside the
// rest of `go test ./internal/...`.
package agent

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// OwnOCISocket hands one named local user ownership of the OCI
// listenerPath socket, keeping the mode at 0600.
//
// Why this exists at all: on a *rootful* podman machine the runtime runs as
// root, the socket's 0600 root is already right, and nothing calls this. On
// a rootless machine the engine, conmon and crun all run as the machine's
// unprivileged user, so the wrapper cannot connect to a root-owned 0600
// socket, and its failure posture is to exec crun untouched, which means
// containerized bind arbitration silently does not happen. Chowning widens
// the socket to exactly one named local user, not to the world (0666, the
// probe socket's mode under -notify-sock-unprivileged, would let any
// process in the guest feed the supervisor notify fds), and it is one
// chown to reverse.
//
// A configured-but-unresolvable user is an error, never a warning: the
// agent that continued would look healthy and arbitrate nothing, which is
// the failure this whole flag exists to prevent.
func OwnOCISocket(path, username string) error {
	if username == "" {
		return nil
	}
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("-oci-sock-owner %q: %w (it must be a user that exists in this guest; `drawbridge up` sets it from the machine's own login user)", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("-oci-sock-owner %q: uid %q is not a number: %w", username, u.Uid, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("-oci-sock-owner %q: gid %q is not a number: %w", username, u.Gid, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %s (uid %d): %w", path, username, uid, err)
	}
	// Re-asserted after the chown, not before: the mode is the other half
	// of "one named user, not the world", and an inherited umask is not
	// something to take on trust for a socket that hands out seccomp
	// notify fds.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}
