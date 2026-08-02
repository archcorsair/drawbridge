//go:build linux

package harness

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/seccomp"
)

// Phase 4 in-guest integration: a filtered process (this binary, re-exec'd
// via TestMain) hands its notify fd to the agent and binds. The fake Mac is
// a mirror.Client on 127.0.0.4 — a distinct loopback address standing in
// for Mac localhost, so "Mac-native holders" and guest sockets can coexist
// on one kernel.
const fakeMacIP = "127.0.0.4"

// startProbe re-execs the test binary as a bind probe and returns its
// result (printed before any hold) plus a wait func for cleanup.
func startProbe(t *testing.T, network, addr, notifySock string, hold time.Duration) (seccomp.ProbeResult, func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"DRAWBRIDGE_TEST_HELPER=bindprobe",
		"HELPER_NETWORK="+network,
		"HELPER_ADDR="+addr,
		"HELPER_NOTIFY_SOCK="+notifySock,
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
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		cmd.Wait()
		t.Fatalf("probe produced no result line: %v", err)
	}
	var res seccomp.ProbeResult
	if err := json.Unmarshal([]byte(line), &res); err != nil {
		cmd.Wait()
		t.Fatalf("bad probe result %q: %v", line, err)
	}
	return res, func() { cmd.Wait() }
}

func TestPhase4SyncBind(t *testing.T) {
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

	notifySock := t.TempDir() + "/notify.sock"
	nln, err := net.ListenUnix("unix", &net.UnixAddr{Name: notifySock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer nln.Close()
	go a.ServeNotify(nln)

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

	// Before any Mac side exists: reservation is "unknown" → CONTINUE, the
	// bind proceeds natively. Graceful degradation.
	t.Run("DegradesWithoutMac", func(t *testing.T) {
		port := freePort(t, "tcp")
		res, wait := startProbe(t, "tcp4", addr(port), notifySock, 0)
		defer wait()
		if res.Errno != 0 {
			t.Fatalf("bind with no Mac session failed: %+v", res)
		}
	})

	// Fake Mac comes up: mirror client on 127.0.0.4 with a short TTL.
	m := mirror.New(tln.Addr().String(), fakeMacIP)
	m.ReserveTTL = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Run(ctx)
	// Wait for the 'R' conn: a probe reservation that answers anything but
	// "unknown" proves the RPC is live. It expires on its own TTL.
	probePort := freePort(t, "tcp")
	poll("'R' reservation conn parked", func() bool {
		return a.ReservePort("tcp", probePort, "127.0.0.1") != "unknown"
	})

	t.Run("SynchronousEADDRINUSE", func(t *testing.T) {
		holder, err := net.Listen("tcp4", fakeMacIP+":0")
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Close()
		port := uint16(holder.Addr().(*net.TCPAddr).Port)

		res, wait := startProbe(t, "tcp4", addr(port), notifySock, 0)
		defer wait()
		if res.Errno != int(syscall.EADDRINUSE) {
			t.Fatalf("want EADDRINUSE(%d), got %+v", int(syscall.EADDRINUSE), res)
		}
		// The syscall never executed: the guest-side port is still free.
		ln, err := net.Listen("tcp4", addr(port))
		if err != nil {
			t.Fatalf("guest port %d not free after denied bind: %v", port, err)
		}
		ln.Close()
	})

	t.Run("ReserveBeforeAckAndAdoption", func(t *testing.T) {
		port := freePort(t, "tcp")
		res, wait := startProbe(t, "tcp4", addr(port), notifySock, 3*time.Second)
		defer wait()
		if res.Errno != 0 {
			t.Fatalf("bind on free port failed: %+v", res)
		}
		// Reserve-before-ack: the mirror listener existed before bind()
		// returned, so it must be observable immediately.
		if !m.Mirrors("tcp", port) {
			t.Fatalf("no mirror on %s:%d right after bind returned", fakeMacIP, port)
		}
		// It is a real, spliceable mirror.
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", fakeMacIP, port), 2*time.Second)
		if err != nil {
			t.Fatalf("dial fake-Mac mirror: %v", err)
		}
		c.Close()
		// Adoption: the tracker's add event clears pending, so the entry
		// must survive past the reservation TTL while the listener lives.
		time.Sleep(1500 * time.Millisecond) // > ReserveTTL
		if !m.Mirrors("tcp", port) {
			t.Fatalf("adopted mirror on :%d vanished at TTL", port)
		}
		wait() // probe exits, listener closes
		poll("mirror removed after listener close", func() bool { return !m.Mirrors("tcp", port) })
	})

	t.Run("GuestOwnedPortStillFailsNatively", func(t *testing.T) {
		// The Mac is free but the guest already owns the port: the agent
		// reserves and CONTINUEs, and the guest kernel supplies the same
		// EADDRINUSE it always would. Arbitration must not mask it.
		guestHolder, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer guestHolder.Close()
		port := uint16(guestHolder.Addr().(*net.TCPAddr).Port)

		res, wait := startProbe(t, "tcp4", addr(port), notifySock, 0)
		defer wait()
		if res.Errno != int(syscall.EADDRINUSE) {
			t.Fatalf("want native EADDRINUSE, got %+v", res)
		}
	})

	t.Run("TTLReleasesUnadoptedReservation", func(t *testing.T) {
		// A reservation nobody binds (the guest bind failed, or the
		// process died between CONTINUE and bind) must not pin the Mac
		// port forever.
		port := freePort(t, "tcp")
		// freePort briefly held a real listener, so its add/del events are
		// still in flight; reserving now would let the stale add adopt the
		// reservation and the stale del delete it. Wait for quiescence.
		poll("mirror quiescent for the probe port", func() bool { return !m.Mirrors("tcp", port) })
		time.Sleep(100 * time.Millisecond)
		if v := a.ReservePort("tcp", port, "127.0.0.1"); v != "ok" {
			t.Fatalf("reserve %d = %q, want ok", port, v)
		}
		if !m.Mirrors("tcp", port) {
			t.Fatalf("reserve-before-ack: no listener on %s:%d after ok", fakeMacIP, port)
		}
		poll("reservation TTL release", func() bool { return !m.Mirrors("tcp", port) })
	})
}
