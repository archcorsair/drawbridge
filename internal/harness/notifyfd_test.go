//go:build linux

package harness

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/agent"
)

// Audit finding 4: the notify socket was 0666 (root-only since the
// 2026-10-28 review, 0666 only behind -notify-sock-unprivileged) and used
// to park whatever fd arrived in a blocking poll. A pipe read end never reports POLLIN or
// POLLHUP, so each handoff pinned an OS thread for the life of the agent.
// Both handoff paths must now close anything that is not a seccomp
// listener and keep serving real ones.
func TestNotifyRejectsNonListener(t *testing.T) {
	a, err := agent.New("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("load+attach: %v", err)
	}
	defer a.Close()

	dir := t.TempDir()
	notifySock := dir + "/notify.sock"
	nln, err := net.ListenUnix("unix", &net.UnixAddr{Name: notifySock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer nln.Close()
	go a.ServeNotify(nln)

	ociSock := dir + "/oci.sock"
	oln, err := net.ListenUnix("unix", &net.UnixAddr{Name: ociSock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer oln.Close()
	go a.ServeOCISeccomp(oln)

	// handPipe sends a pipe's read end over sock with payload, closes the
	// local read end, and reports whether the agent closed its copy: once
	// no reader is left, a write to the other end fails with EPIPE. An
	// agent that parked the fd keeps the write succeeding.
	handPipe := func(t *testing.T, sock string, payload []byte) {
		t.Helper()
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		r, w := p[0], p[1]
		defer unix.Close(w)
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.(*net.UnixConn).WriteMsgUnix(payload, unix.UnixRights(r), nil); err != nil {
			t.Fatal(err)
		}
		c.Close()
		unix.Close(r)
		deadline := time.Now().Add(3 * time.Second)
		for {
			_, err := unix.Write(w, []byte{0})
			if errors.Is(err, unix.EPIPE) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("agent still holds the pipe read end 3s after the handoff (write err=%v)", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	t.Run("ProbeSocketClosesPipe", func(t *testing.T) {
		handPipe(t, notifySock, []byte{0})
	})

	t.Run("OCISocketClosesPipe", func(t *testing.T) {
		st, _ := json.Marshal(map[string]any{
			"ociVersion": "1.2.0",
			"fds":        []string{"seccompFd"},
			"pid":        os.Getpid(),
			"state":      map[string]any{"id": "harness-pipe", "status": "creating", "pid": os.Getpid(), "bundle": "/nonexistent"},
		})
		handPipe(t, ociSock, st)
	})

	// Both sockets still serve a real handoff afterwards: a probe binds a
	// free port through each path and gets a verdict (CONTINUE, no Mac).
	t.Run("ProbeSocketStillServes", func(t *testing.T) {
		port := freePort(t, "tcp")
		res, wait := startProbe(t, "tcp4", addr(port), notifySock, 0)
		defer wait()
		if res.Errno != 0 {
			t.Fatalf("bind through the probe socket after a refused handoff: %+v", res)
		}
	})
	t.Run("OCISocketStillServes", func(t *testing.T) {
		port := freePort(t, "tcp")
		res, wait := startOCIProbe(t, false, "tcp4", addr(port), ociSock, 0)
		defer wait()
		if res.Errno != 0 {
			t.Fatalf("bind through the oci socket after a refused handoff: %+v", res)
		}
	})

	// A handoff with no fd at all, and one with a real listener riding
	// alongside junk fds: the junk is closed, the listener supervised.
	t.Run("ExtraFdsClosed", func(t *testing.T) {
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		r, w := p[0], p[1]
		defer unix.Close(w)
		// A plain socket stands in for "the first fd": it is refused too,
		// but the extra pipe behind it must be closed regardless.
		s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("unix", notifySock)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.(*net.UnixConn).WriteMsgUnix([]byte{0}, unix.UnixRights(s, r), nil); err != nil {
			t.Fatal(err)
		}
		c.Close()
		unix.Close(s)
		unix.Close(r)
		deadline := time.Now().Add(3 * time.Second)
		for {
			_, err := unix.Write(w, []byte{0})
			if errors.Is(err, syscall.EPIPE) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("extra fd in the handoff was not closed (write err=%v)", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}
