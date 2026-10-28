package main

import (
	"net"
	"os"
)

// Probe-socket modes. Root-only is the production posture: no production
// sender is unprivileged (container runtimes hand their fds over the 0600
// OCI socket, and the e2e and smoke-sudo probe legs run bindprobe under
// sudo), and a socket any guest process can reach let one unprivileged
// process fill the supervision cap and pin an OS thread per slot
// (2026-10-28 M3, decision E2). The wide mode exists for tests and smoke
// legs that need an unprivileged sender, and only behind
// -notify-sock-unprivileged.
const (
	notifySockModeRoot         os.FileMode = 0o600
	notifySockModeUnprivileged os.FileMode = 0o666
)

func notifySockMode(unprivileged bool) os.FileMode {
	if unprivileged {
		return notifySockModeUnprivileged
	}
	return notifySockModeRoot
}

// listenNotify replaces whatever is at path with the probe socket and sets
// its mode. A chmod failure is fatal: a socket left at the umask's mode
// would be wider or narrower than the flag says, silently.
func listenNotify(path string, unprivileged bool) (*net.UnixListener, error) {
	os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, notifySockMode(unprivileged)); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
