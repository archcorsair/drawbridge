//go:build linux

package fdstore

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// SendTimeout bounds one datagram to the notify socket. Send runs on the
// bind supervisor's path before the first notification is answered, and a
// unix datagram send blocks while the receiver's queue is full, so a
// stalled manager must cost a container's bind at most this long and then
// degrade to "not stored" (the caller logs it once), never block it.
const SendTimeout = 500 * time.Millisecond

// Send delivers one sd_notify datagram to socketPath (the NOTIFY_SOCKET
// value: a filesystem path, or '@'-prefixed abstract name) with fds
// attached as SCM_RIGHTS. systemd dups what it stores, so the caller keeps
// ownership of fds. The send waits at most SendTimeout for queue space
// (EAGAIN after that), so a stalled manager cannot hold a bind open. An empty socketPath is ErrNoSocket: the service runs
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
	tv := unix.NsecToTimeval(SendTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return fmt.Errorf("fdstore: SO_SNDTIMEO: %w", err)
	}
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
