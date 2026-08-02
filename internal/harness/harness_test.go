//go:build linux

// Phase 1 acceptance harness. Runs INSIDE the Lima guest as root:
//
//	sudo go test -v ./internal/harness/
//
// It loads and attaches the real BPF gateway to the root cgroup, drives the
// agent registry directly (in-process), and proves the five Phase 1 claims.
package harness

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/bpf"
	"github.com/archcorsair/drawbridge/internal/seccomp"
)

const backendIP = "127.0.0.3" // simulated "Mac side" targets live here

func TestMain(m *testing.M) {
	// Re-exec helpers: the Phase 4 / OCI tests run this same binary as a
	// stand-in for a container process (or for runc delivering its fd).
	switch os.Getenv("DRAWBRIDGE_TEST_HELPER") {
	case "bindprobe":
		hold, _ := time.ParseDuration(os.Getenv("HELPER_HOLD"))
		if err := seccomp.RunBindProbe(os.Getenv("HELPER_NETWORK"), os.Getenv("HELPER_ADDR"),
			os.Getenv("HELPER_NOTIFY_SOCK"), hold, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "ocibind": // spec-framed handoff, then bind (ociseccomp_test.go)
		if err := runOCIBindHelper(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "fdhand": // install filter, hand fd over, exit immediately
		if err := runFdHandHelper(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		fmt.Println("SKIP: phase 1 harness loads BPF and must run as root")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestPhase1(t *testing.T) {
	a, err := agent.New("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("load+attach BPF gateway: %v", err)
	}
	defer a.Close()

	t.Run("1_RefusedFastPath", func(t *testing.T) { refusedFastPath(t, a) })
	t.Run("2_TCPProxyAndGetpeername", func(t *testing.T) { tcpProxyGetpeername(t, a) })
	t.Run("3_GuestPrecedence", func(t *testing.T) { guestPrecedence(t, a) })
	t.Run("4_UDPUnconnectedTwoDest", func(t *testing.T) { udpTwoDest(t, a) })
	t.Run("5_Latency", func(t *testing.T) { latency(t, a) })
}

// --- assertion 1: unmapped port -> native fast ECONNREFUSED, proxy untouched.

func refusedFastPath(t *testing.T, a *agent.Agent) {
	port := freePort(t, "tcp")
	before := a.Stats.TCPConns.Load()

	start := time.Now()
	_, err := net.DialTimeout("tcp", addr(port), time.Second)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected connection refused, got success")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("want ECONNREFUSED, got: %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("refusal took %v, want native-fast", elapsed)
	}
	if got := a.Stats.TCPConns.Load(); got != before {
		t.Fatalf("proxy accepted %d conns during refused dial", got-before)
	}
	t.Logf("native ECONNREFUSED in %v", elapsed)
}

// --- assertion 2: mac-mapped TCP port round-trips via proxy; getpeername
// reports the ORIGINAL destination (127.0.0.1:P), not the gateway.

func tcpProxyGetpeername(t *testing.T, a *agent.Agent) {
	backend := startTCPEcho(t, "MAC:")
	port := freePort(t, "tcp")
	mustAdd(t, a.AddMacPort(bpf.ProtoTCP, port, netip.IPv4Unspecified(), backend))
	t.Cleanup(func() { a.RemoveMacPort(bpf.ProtoTCP, port) })

	before := a.Stats.TCPConns.Load()
	c, err := net.DialTimeout("tcp", addr(port), time.Second)
	if err != nil {
		t.Fatalf("dial mac-mapped port: %v", err)
	}
	defer c.Close()

	// Raw getpeername straight from the kernel — proves the BPF un-rewrite,
	// independent of what Go's net package caches.
	rc, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var sa syscall.Sockaddr
	rc.Control(func(fd uintptr) { sa, err = syscall.Getpeername(int(fd)) })
	if err != nil {
		t.Fatalf("getpeername: %v", err)
	}
	sa4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("getpeername family: %T", sa)
	}
	if sa4.Addr != [4]byte{127, 0, 0, 1} || sa4.Port != int(port) {
		t.Fatalf("getpeername leaked gateway: %v:%d", sa4.Addr, sa4.Port)
	}

	if _, err := fmt.Fprintf(c, "hello\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if line != "MAC:hello\n" {
		t.Fatalf("unexpected echo %q", line)
	}
	if a.Stats.TCPConns.Load() == before {
		t.Fatal("proxy not involved — traffic did not traverse gateway")
	}
	t.Logf("proxied round-trip OK, getpeername=127.0.0.1:%d", port)
}

// --- assertion 3: a port owned by BOTH guest and mac stays native (guest wins).

func guestPrecedence(t *testing.T, a *agent.Agent) {
	guestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guestLn.Close() })
	go serveStatic(guestLn, "GUEST\n")
	port := uint16(guestLn.Addr().(*net.TCPAddr).Port)

	mustAdd(t, a.AddGuestPort(bpf.ProtoTCP, port, netip.MustParseAddr("127.0.0.1")))
	t.Cleanup(func() { a.RemoveGuestPort(bpf.ProtoTCP, port) })
	macBackend := startTCPStatic(t, "MAC\n")
	mustAdd(t, a.AddMacPort(bpf.ProtoTCP, port, netip.IPv4Unspecified(), macBackend))
	t.Cleanup(func() { a.RemoveMacPort(bpf.ProtoTCP, port) })

	before := a.Stats.TCPConns.Load()
	c, err := net.DialTimeout("tcp", addr(port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "GUEST\n" {
		t.Fatalf("guest listener did not win: got %q", line)
	}
	if got := a.Stats.TCPConns.Load(); got != before {
		t.Fatalf("proxy saw %d conns for a guest-owned port", got-before)
	}
	t.Log("guest-owned port served natively; proxy untouched")
}

// --- assertion 4: one unconnected UDP socket, two mac-mapped destinations;
// replies demux correctly and sources un-rewrite to 127.0.0.1.

func udpTwoDest(t *testing.T, a *agent.Agent) {
	b1 := startUDPEcho(t, "ONE:")
	b2 := startUDPEcho(t, "TWO:")
	p1 := freePort(t, "udp")
	p2 := freePort(t, "udp")
	mustAdd(t, a.AddMacPort(bpf.ProtoUDP, p1, netip.IPv4Unspecified(), b1))
	t.Cleanup(func() { a.RemoveMacPort(bpf.ProtoUDP, p1) })
	mustAdd(t, a.AddMacPort(bpf.ProtoUDP, p2, netip.IPv4Unspecified(), b2))
	t.Cleanup(func() { a.RemoveMacPort(bpf.ProtoUDP, p2) })

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	send := func(port uint16, payload string) {
		_, err := client.WriteToUDP([]byte(payload), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatalf("sendto :%d: %v", port, err)
		}
	}
	send(p1, "alpha")
	send(p2, "beta")

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	replies := map[int]string{}
	buf := make([]byte, 2048)
	for len(replies) < 2 {
		n, from, err := client.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("reply timeout, got %v so far: %v", replies, err)
		}
		if !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("recvmsg un-rewrite failed: reply source %v", from)
		}
		replies[from.Port] = string(buf[:n])
	}
	if replies[int(p1)] != "ONE:alpha" || replies[int(p2)] != "TWO:beta" {
		t.Fatalf("demux wrong: %v", replies)
	}
	t.Logf("two-destination UDP demux OK: %v", replies)
}

// --- assertion 5: latency numbers — native vs proxied vs refused.

func latency(t *testing.T, a *agent.Agent) {
	const rounds = 150

	// native baseline: plain guest listener, no maps involved
	nativeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nativeLn.Close() })
	go acceptAndClose(nativeLn)
	nativePort := uint16(nativeLn.Addr().(*net.TCPAddr).Port)

	// proxied: mac-mapped port with accepting backend
	backend := startTCPEcho(t, "L:")
	proxPort := freePort(t, "tcp")
	mustAdd(t, a.AddMacPort(bpf.ProtoTCP, proxPort, netip.IPv4Unspecified(), backend))
	t.Cleanup(func() { a.RemoveMacPort(bpf.ProtoTCP, proxPort) })

	refPort := freePort(t, "tcp")

	measure := func(name string, port uint16, wantErr bool) (p50, p95 time.Duration) {
		ds := make([]time.Duration, 0, rounds)
		for i := 0; i < rounds; i++ {
			start := time.Now()
			c, err := net.DialTimeout("tcp", addr(port), time.Second)
			d := time.Since(start)
			if wantErr != (err != nil) {
				t.Fatalf("%s round %d: err=%v", name, i, err)
			}
			if c != nil {
				c.Close()
			}
			ds = append(ds, d)
		}
		slices.Sort(ds)
		return ds[rounds/2], ds[rounds*95/100]
	}

	n50, n95 := measure("native", nativePort, false)
	x50, x95 := measure("proxied", proxPort, false)
	r50, r95 := measure("refused", refPort, true)

	t.Logf("connect latency p50/p95 — native: %v/%v  proxied: %v/%v  refused: %v/%v",
		n50, n95, x50, x95, r50, r95)
	t.Logf("gateway overhead p50: %v", x50-n50)
	if x95 > 50*time.Millisecond {
		t.Fatalf("proxied p95 %v exceeds 50ms sanity bound", x95)
	}
}

// --- helpers ---

func addr(port uint16) string { return fmt.Sprintf("127.0.0.1:%d", port) }

func mustAdd(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// freePort finds a currently-free port by binding :0 on the given proto and
// releasing it. Racy in principle, fine in a single-purpose test VM.
func freePort(t *testing.T, proto string) uint16 {
	t.Helper()
	if proto == "udp" {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		p := uint16(c.LocalAddr().(*net.UDPAddr).Port)
		c.Close()
		return p
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	return p
}

// startTCPEcho serves prefix+line echo on backendIP, one line per connection kept open.
func startTCPEcho(t *testing.T, prefix string) string {
	t.Helper()
	ln, err := net.Listen("tcp", backendIP+":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					fmt.Fprintf(c, "%s%s\n", prefix, sc.Text())
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startTCPStatic writes a fixed line to every connection and closes it.
func startTCPStatic(t *testing.T, line string) string {
	t.Helper()
	ln, err := net.Listen("tcp", backendIP+":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveStatic(ln, line)
	return ln.Addr().String()
}

func serveStatic(ln net.Listener, line string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			c.Write([]byte(line))
			c.Close()
		}()
	}
}

func acceptAndClose(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}

func startUDPEcho(t *testing.T, prefix string) string {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(backendIP)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP(append([]byte(prefix), buf[:n]...), from)
		}
	}()
	return c.LocalAddr().String()
}
