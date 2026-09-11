// Minimal repro for the Little Snitch inbound-bulk wedge (docs/notes/
// local-network-permission.md finding 3): with the LS network extension
// active, Mac→guest bulk upload through a mirror times out on the sink
// ack — but only after outbound traffic has flowed on the same session.
//
// Gated: DRAWBRIDGE_WEDGE=1. Knobs:
//
//	DRAWBRIDGE_WEDGE_OUTBOUND  outbound firstbyte iterations (default 8, 0 skips)
//	DRAWBRIDGE_WEDGE_BYTES     upload size (default 256 MiB)
//
// Run with tcpdump on Mac bridge100 and guest lima0 (port 4777) to see
// which direction's segments vanish.
package bench

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/macsync"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func envInt64(name string, def int64) int64 {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func TestWedgeRepro(t *testing.T) {
	if os.Getenv("DRAWBRIDGE_WEDGE") == "" {
		t.Skip("set DRAWBRIDGE_WEDGE=1")
	}
	ref, err := vmprovider.ParseRef(vmSpec)
	if err != nil {
		t.Fatalf("DRAWBRIDGE_VM=%q: %v", vmSpec, err)
	}
	vmRef, vmProvider = ref, vmprovider.ForRef(ref)
	insts, err := vmProvider.List()
	if err != nil {
		t.Skipf("listing %s instances: %v", ref.Provider, err)
	}
	if !running(insts, ref.Instance) {
		t.Skipf("VM %s is not running", ref.Spec)
	}
	res := resolve(ref)
	agentAddr = res.Endpoint
	t.Logf("agent transport: %s source=%s", res.Endpoint, res.Source)
	// The repro is about a non-loopback flow, so it is a Lima/Colima vzNAT
	// leg by construction: a podman machine's transport is loopback and
	// exempt from both Little Snitch signatures, and skips here on its own.
	if res.Source != limaaddr.SourceVZNATDirect {
		t.Skipf("wedge repro needs the vzNAT path (loopback is exempt); resolver reported %s: %s", res.Source, res.Note)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := mirror.New(agentAddr, "127.0.0.1")
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		Exclude: func(l macsync.Listener) bool {
			return l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
		},
	}
	go m.Run(ctx)
	go s.Run(ctx)

	// --- Outbound leg: guest → Mac echo through the 'D' reverse streams.
	outIters := int(envInt64("DRAWBRIDGE_WEDGE_OUTBOUND", 8))
	if outIters > 0 {
		echoPort := macServer(t, "echo")
		deadline := time.Now().Add(20 * time.Second)
		var lastErr error
		for {
			if time.Now().After(deadline) {
				t.Fatalf("Mac echo :%d never reachable from guest: %v", echoPort, lastErr)
			}
			if _, lastErr = benchclient(t, fmt.Sprintf("-mode firstbyte -target 127.0.0.1:%d -iters 1", echoPort)); lastErr == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if _, err := benchclient(t, fmt.Sprintf("-mode firstbyte -target 127.0.0.1:%d -iters %d", echoPort, outIters)); err != nil {
			t.Fatalf("outbound leg: %v", err)
		}
		t.Logf("outbound leg done: %d firstbyte iters", outIters)
	} else {
		t.Logf("outbound leg skipped")
	}

	// --- Inbound leg: Mac → guest sink, instrumented upload.
	guestUnit(t, "dbg-wedge-sink", "sink", guestSinkPort)
	sinkAddr := fmt.Sprintf("127.0.0.1:%d", guestSinkPort)
	var c net.Conn
	deadline := time.Now().Add(20 * time.Second)
	for {
		c, err = net.DialTimeout("tcp", sinkAddr, 2*time.Second)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest sink :%d never mirrored: %v", guestSinkPort, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer c.Close()
	t.Logf("upload conn: %s -> %s", c.LocalAddr(), c.RemoteAddr())

	n := envInt64("DRAWBRIDGE_WEDGE_BYTES", bulkBytes)
	buf := make([]byte, 1<<20)
	start := time.Now()
	for sent := int64(0); sent < n; {
		chunk := int64(len(buf))
		if n-sent < chunk {
			chunk = n - sent
		}
		w, werr := c.Write(buf[:chunk])
		if werr != nil {
			t.Fatalf("write at offset %d: %v", sent, werr)
		}
		sent += int64(w)
	}
	wrote := time.Since(start)
	t.Logf("wrote %d MiB in %.2fs (%.1f MB/s)", n>>20, wrote.Seconds(),
		float64(n)/1e6/wrote.Seconds())
	if tc, ok := c.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
	}
	t.Logf("CloseWrite done at %.2fs; waiting for sink ack", time.Since(start).Seconds())

	c.SetReadDeadline(time.Now().Add(75 * time.Second))
	var ack [1]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		t.Logf("WEDGED: ack read failed after %.2fs: %v", time.Since(start).Seconds(), err)
		dumpFlowState(t)
		t.Fatalf("sink ack never arrived")
	}
	t.Logf("ack received at %.2fs — NO wedge", time.Since(start).Seconds())
}

// dumpFlowState logs Mac and guest socket state for the transport port and
// the sink at the moment of the wedge.
func dumpFlowState(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("bash", "-c",
		fmt.Sprintf("netstat -an -p tcp | grep -E '4777|%d' | grep -v LISTEN", guestSinkPort)).CombinedOutput(); err == nil {
		t.Logf("Mac sockets:\n%s", out)
	}
	if out, err := guest(t, fmt.Sprintf("ss -tnp | grep -E '4777|%d' || true", guestSinkPort)); err == nil {
		t.Logf("guest sockets:\n%s", out)
	}
}
