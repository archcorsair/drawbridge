//go:build linux

package seccomp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ProbeResult is the JSON line RunBindProbe prints.
type ProbeResult struct {
	Errno int    `json:"errno"` // 0 on success, else the bind errno (98 = EADDRINUSE)
	Error string `json:"error,omitempty"`
}

// RunBindProbe stands in for a container process under the Phase 4 OCI
// hook: install the bind filter, hand the notify fd to the agent over the
// unix socket, then attempt the bind and report how it went. The listener
// is held briefly so the tracker path can observe it.
func RunBindProbe(network, addr, notifySock string, hold time.Duration, offThread bool, out io.Writer) error {
	// The unix connection must exist BEFORE the filter is installed: Go's
	// net package does capability probes on first use, and any syscall it
	// makes post-install would be answered by a supervisor that does not
	// exist yet — deadlocking the handoff we are trying to perform.
	c, err := net.Dial("unix", notifySock)
	if err != nil {
		return fmt.Errorf("dial notify socket: %w", err)
	}
	defer c.Close()
	uc := c.(*net.UnixConn)

	nfd, err := InstallBindFilter()
	if err != nil {
		return fmt.Errorf("install filter: %w", err)
	}
	defer unix.Close(nfd)

	if _, _, err := uc.WriteMsgUnix([]byte{0}, unix.UnixRights(nfd), nil); err != nil {
		return fmt.Errorf("send notify fd: %w", err)
	}

	res := ProbeResult{}
	ln, err := listenMaybeOffThread(network, addr, offThread)
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return fmt.Errorf("bind failed without errno: %w", err)
		}
		res.Errno = int(errno)
		res.Error = errno.Error()
	} else {
		defer ln.Close()
	}
	if err := json.NewEncoder(out).Encode(res); err != nil {
		return err
	}
	if res.Errno == 0 && hold > 0 {
		time.Sleep(hold)
	}
	return nil
}

// listenMaybeOffThread binds from a thread that is deliberately not the
// group leader when offThread is set: the notification then carries a
// non-leader TID, the case the supervisor's tgid fallback exists for. Main
// is pinned first so the goroutine cannot be scheduled onto it.
func listenMaybeOffThread(network, addr string, offThread bool) (net.Listener, error) {
	if !offThread {
		return net.Listen(network, addr)
	}
	runtime.LockOSThread()
	type result struct {
		ln  net.Listener
		err error
	}
	ch := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ln, err := net.Listen(network, addr)
		ch <- result{ln, err}
	}()
	r := <-ch
	return r.ln, r.err
}
