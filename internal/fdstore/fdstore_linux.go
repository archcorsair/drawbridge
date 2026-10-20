//go:build linux

package fdstore

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// Send delivers one sd_notify datagram to socketPath (the NOTIFY_SOCKET
// value: a filesystem path, or '@'-prefixed abstract name) with fds
// attached as SCM_RIGHTS. systemd dups what it stores, so the caller keeps
// ownership of fds. An empty socketPath is ErrNoSocket: the service runs
// without a store (a transient unit without FileDescriptorStoreMax=, a
// foreground run), which callers degrade from rather than fail on.
func Send(socketPath string, msg []byte, fds ...int) error {
	if socketPath == "" {
		return ErrNoSocket
	}
	name := socketPath
	if strings.HasPrefix(name, "@") {
		name = "\x00" + name[1:]
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("fdstore: socket: %w", err)
	}
	defer unix.Close(fd)
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	addr := &unix.SockaddrUnix{Name: name}
	if err := unix.Sendmsg(fd, msg, oob, addr, 0); err != nil {
		return fmt.Errorf("fdstore: sendmsg %s: %w", socketPath, err)
	}
	return nil
}

// ErrNoSocket is Send's answer to an empty NOTIFY_SOCKET.
var ErrNoSocket = errors.New("fdstore: no NOTIFY_SOCKET in the environment")
