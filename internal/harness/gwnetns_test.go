//go:build linux

package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/bpf"
)

// Audit finding 1: the gateway attaches at the root cgroup, so its
// connect/sendmsg hooks also run for bridged containers' sockets. A
// container's own 127.0.0.1:P must stay reachable from inside that
// container even when the Mac holds P — the rewrite is scoped to the
// agent's netns by host_netns_cookie. Without the gate this leg gets
// ECONNREFUSED: the connect is sent to 127.0.0.2:P inside the foreign
// netns, where nothing listens.

type loNetnsResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// runLoNetnsHelper is the re-exec'd body (see TestMain), started under
// `unshare --net`: bring lo up, listen on 127.0.0.1:P, connect to the same
// address from this netns, and prove the bytes reached the local listener.
func runLoNetnsHelper() error {
	report := func(err error) error {
		res := loNetnsResult{OK: err == nil}
		if err != nil {
			res.Error = err.Error()
		}
		return json.NewEncoder(os.Stdout).Encode(res)
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		return report(fmt.Errorf("ip link set lo up: %v: %s", err, strings.TrimSpace(string(out))))
	}
	address := os.Getenv("HELPER_ADDR")
	ln, err := net.Listen("tcp4", address)
	if err != nil {
		return report(fmt.Errorf("listen %s: %w", address, err))
	}
	defer ln.Close()
	const token = "LOCAL\n"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return
		}
		c.Write([]byte("GOT:" + line))
	}()
	c, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err != nil {
		return report(fmt.Errorf("connect %s from the foreign netns: %w", address, err))
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte(token)); err != nil {
		return report(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return report(fmt.Errorf("read reply: %w", err))
	}
	if line != "GOT:"+token {
		return report(fmt.Errorf("reply %q: connect did not reach the netns-local listener", line))
	}
	return report(nil)
}

func TestGatewayForeignNetnsPassThrough(t *testing.T) {
	a, err := agent.New("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("load+attach: %v", err)
	}
	defer a.Close()

	// P is Mac-held: in the host netns a connect to 127.0.0.1:P must still
	// be rewritten to the gateway and reach the backend.
	backend := startTCPEcho(t, "MAC:")
	port := freePort(t, "tcp")
	mustAdd(t, a.AddMacPort(bpf.ProtoTCP, port, netip.IPv4Unspecified(), backend))
	t.Cleanup(func() { a.RemoveMacPort(bpf.ProtoTCP, port) })

	hc, err := net.DialTimeout("tcp", addr(port), time.Second)
	if err != nil {
		t.Fatalf("host-netns dial of the Mac-held port: %v", err)
	}
	hc.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprint(hc, "ping\n")
	line, err := bufio.NewReader(hc).ReadString('\n')
	hc.Close()
	if err != nil || line != "MAC:ping\n" {
		t.Fatalf("host-netns connect did not reach the Mac backend: %q, %v", line, err)
	}

	// Same port, foreign netns: the helper's own listener must win.
	cmd := exec.Command("unshare", "--net", os.Args[0])
	cmd.Env = append(os.Environ(),
		"DRAWBRIDGE_TEST_HELPER=lonetns",
		"HELPER_ADDR="+addr(port),
	)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("lonetns helper: %v (output %q)", err, out)
	}
	var res loNetnsResult
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("lonetns helper output %q: %v", out, err)
	}
	if !res.OK {
		t.Fatalf("intra-netns connect to a Mac-held port broke: %s", res.Error)
	}
}
