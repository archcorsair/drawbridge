//go:build linux

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/seccomp"
)

// OCI Phase A (docs/oci-hook.md): the agent's second listener speaks the
// runtime-spec seccomp-agent protocol. The "ocibind" helper plays runc's
// role — install the bind filter, deliver the notify fd with a JSON
// ContainerProcessState in spec framing (one message, fds on the first
// sendmsg, close after transmission) — then plays the workload and binds.

// runOCIBindHelper is the re-exec'd helper body (see TestMain).
func runOCIBindHelper() error {
	// Dial before installing the filter for the same reason RunBindProbe
	// does: the Go runtime's first net use makes trapped syscalls.
	c, err := net.Dial("unix", os.Getenv("HELPER_NOTIFY_SOCK"))
	if err != nil {
		return err
	}
	uc := c.(*net.UnixConn)
	nfd, err := seccomp.InstallBindFilter()
	if err != nil {
		return err
	}
	st := map[string]any{
		"ociVersion": "1.2.0",
		"fds":        []string{"seccompFd"},
		"pid":        os.Getpid(),
		"metadata":   "harness-ocibind",
		"state": map[string]any{
			"id":     "harness-container",
			"status": "creating",
			"pid":    os.Getpid(),
			"bundle": "/nonexistent",
		},
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if _, _, err := uc.WriteMsgUnix(b, unix.UnixRights(nfd), nil); err != nil {
		return err
	}
	uc.Close() // spec: the runtime closes after transmission
	unix.Close(nfd)

	hold, _ := time.ParseDuration(os.Getenv("HELPER_HOLD"))
	res := seccomp.ProbeResult{}
	ln, err := net.Listen(os.Getenv("HELPER_NETWORK"), os.Getenv("HELPER_ADDR"))
	if err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			return err
		}
		res.Errno = int(errno)
		res.Error = errno.Error()
	} else {
		defer ln.Close()
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		return err
	}
	if res.Errno == 0 && hold > 0 {
		time.Sleep(hold)
	}
	return nil
}

// runFdHandHelper installs the filter, hands the fd over the 1-byte
// protocol, and exits at once — the "container died" case for
// TestNotifyFilterExitSemantics.
func runFdHandHelper() error {
	c, err := net.Dial("unix", os.Getenv("HELPER_NOTIFY_SOCK"))
	if err != nil {
		return err
	}
	uc := c.(*net.UnixConn)
	nfd, err := seccomp.InstallBindFilter()
	if err != nil {
		return err
	}
	_, _, err = uc.WriteMsgUnix([]byte{0}, unix.UnixRights(nfd), nil)
	return err
}

// startOCIProbe launches the ocibind helper, optionally inside a fresh
// network namespace (unshare --net), and returns its bind result.
func startOCIProbe(t *testing.T, unshareNet bool, network, address, ociSock string, hold time.Duration) (seccomp.ProbeResult, func()) {
	t.Helper()
	var cmd *exec.Cmd
	if unshareNet {
		cmd = exec.Command("unshare", "--net", os.Args[0])
	} else {
		cmd = exec.Command(os.Args[0])
	}
	cmd.Env = append(os.Environ(),
		"DRAWBRIDGE_TEST_HELPER=ocibind",
		"HELPER_NETWORK="+network,
		"HELPER_ADDR="+address,
		"HELPER_NOTIFY_SOCK="+ociSock,
		"HELPER_HOLD="+hold.String(),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(stdout)
	var res seccomp.ProbeResult
	if err := dec.Decode(&res); err != nil {
		cmd.Wait()
		t.Fatalf("oci probe produced no result: %v", err)
	}
	return res, func() { cmd.Wait() }
}

func TestPhase4OCIProtocol(t *testing.T) {
	a, err := agent.New("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("load+attach: %v", err)
	}
	defer a.Close()

	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tln.Close()
	go a.ServeTransport(tln)

	ociSock := t.TempDir() + "/oci.sock"
	oln, err := net.ListenUnix("unix", &net.UnixAddr{Name: ociSock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer oln.Close()
	go a.ServeOCISeccomp(oln)

	poll := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatalf("timeout waiting for %s", desc)
	}

	m := mirror.New(tln.Addr().String(), fakeMacIP)
	m.ReserveTTL = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	probePort := freePort(t, "tcp")
	poll("'R' reservation conn parked", func() bool {
		return a.ReservePort("tcp", probePort, "127.0.0.1") != "unknown"
	})

	t.Run("DenyViaOCIFraming", func(t *testing.T) {
		holder, err := net.Listen("tcp4", fakeMacIP+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()
		port := uint16(holder.Addr().(*net.TCPAddr).Port)

		res, wait := startOCIProbe(t, false, "tcp4", addr(port), ociSock, 0)
		defer wait()
		if res.Errno != int(syscall.EADDRINUSE) {
			t.Fatalf("want EADDRINUSE(%d), got %+v", int(syscall.EADDRINUSE), res)
		}
	})

	t.Run("FreePortContinuesAndMirrors", func(t *testing.T) {
		port := freePort(t, "tcp")
		poll("mirror quiescent for the probe port", func() bool { return !m.Mirrors("tcp", port) })
		res, wait := startOCIProbe(t, false, "tcp4", addr(port), ociSock, 3*time.Second)
		defer wait()
		if res.Errno != 0 {
			t.Fatalf("bind on free port failed: %+v", res)
		}
		// Reserve-before-ack through the OCI path too: mirror listener
		// observable as soon as bind returned.
		if !m.Mirrors("tcp", port) {
			t.Fatalf("no mirror on %s:%d right after bind returned", fakeMacIP, port)
		}
	})

	t.Run("ForeignNetnsContinues", func(t *testing.T) {
		holder, err := net.Listen("tcp4", fakeMacIP+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()
		port := uint16(holder.Addr().(*net.TCPAddr).Port)

		// Inside a fresh netns the same port is genuinely free; the
		// backstop must CONTINUE (never consult the Mac, which holds it —
		// without the netns check this bind would be denied EADDRINUSE).
		res, wait := startOCIProbe(t, true, "tcp4", fmt.Sprintf("0.0.0.0:%d", port), ociSock, 0)
		defer wait()
		if res.Errno != 0 {
			t.Fatalf("foreign-netns bind arbitrated: %+v", res)
		}
	})
}

// TestNotifyFilterExitSemantics pins the kernel behavior the supervisor's
// lifecycle handling relies on: once the filter's last task exits, the
// notify fd raises EPOLLHUP — and that is the ONLY signal, because
// NOTIF_RECV on a dead filter blocks forever instead of erroring
// (observed on 6.8; an earlier draft assumed ENOENT and hung right here).
// Hence superviseNotify polls before every recv. If this test starts
// failing on a new kernel, re-derive the exit condition in the guest, not
// from memory.
func TestNotifyFilterExitSemantics(t *testing.T) {
	sock := t.TempDir() + "/hand.sock"
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"DRAWBRIDGE_TEST_HELPER=fdhand",
		"HELPER_NOTIFY_SOCK="+sock,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 1)
	oob := make([]byte, 64)
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) == 0 {
		t.Fatalf("control message: %v", err)
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) == 0 {
		t.Fatalf("rights: %v", err)
	}
	fd := fds[0]
	defer unix.Close(fd)

	if err := cmd.Wait(); err != nil {
		t.Fatalf("fdhand helper: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !seccomp.FilterDead(fd) {
		if time.Now().After(deadline) {
			t.Fatal("no EPOLLHUP within 3s of the last filtered task exiting")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// HUP is level-triggered: PollNotif on a dead filter must report hup
	// with nothing receivable, immediately.
	done := make(chan struct{})
	var in, hup bool
	var perr error
	go func() {
		in, hup, perr = seccomp.PollNotif(fd)
		close(done)
	}()
	select {
	case <-done:
		if perr != nil {
			t.Fatalf("PollNotif on dead filter: %v", perr)
		}
		if !hup || in {
			t.Fatalf("dead filter: in=%v hup=%v, want hup only", in, hup)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PollNotif on dead filter blocked")
	}
}
