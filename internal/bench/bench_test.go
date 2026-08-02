// Drawbridge latency/throughput benchmark, run from the Mac against the
// live dev VM (agent installed via `just agent-up`). Gated:
// DRAWBRIDGE_BENCH=1 (use `just bench`).
//
// Outbound (guest → Mac, Phase 3 'D' reverse streams) is measured by the
// guest binary's benchclient subcommand against Mac-side servers; inbound
// (Mac → guest, Phase 2 'S' streams) by this process against guest
// benchserve units through the mirrors. Baselines are native loopback
// echoes on each side, with the BPF hooks attached — the delta is
// drawbridge's real overhead.
package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/benchtool"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/macsync"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// agentAddr is resolved by requireBench: vzNAT direct TCP when reachable,
// else the SSH-forwarded loopback.
var agentAddr string

const (
	vmName    = "drawbridge"
	agentPort = 4777

	guestEchoPort   = 47801
	guestSinkPort   = 47802
	guestSourcePort = 47803
	// UDP inbound unit port: must sit OUTSIDE the guest autobind range
	// (32768-60999) — the mirror rejects that range by design.
	guestUDPEchoPort = 25998

	rttIters    = 300
	burstRounds = 5
	bulkBytes   = int64(256 << 20)
	udpSize     = 64    // DNS-shaped request/reply payload
	udpLargeSz  = 60000 // guest→Mac only: macOS caps UDP sends at ~9216
)

func limactl(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("limactl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func guest(t *testing.T, script string) (string, error) {
	t.Helper()
	return limactl(t, "shell", vmName, "--", "sudo", "bash", "-c", script)
}

// macAuth mirrors the e2e suite's loader: DRAWBRIDGE_SECRET_FILE, else the
// per-VM default `drawbridge up` writes, else unauthenticated (§6). A bench
// run against a provisioned guest must speak the same wire the daemon does,
// or the numbers describe a path nobody uses.
var macAuth transportauth.MacConfig

func loadMacAuth(t *testing.T) transportauth.MacConfig {
	t.Helper()
	cfg := transportauth.MacConfig{VM: vmName}
	if p := os.Getenv("DRAWBRIDGE_SECRET_FILE"); p != "" {
		cfg.SecretFile = p
	} else if ref, err := vmprovider.ParseRef(vmName); err == nil {
		if p, err := transportauth.PathForRef(ref); err == nil {
			cfg.SecretFile = p
		}
	}
	sec, err := cfg.Secret()
	if err != nil {
		t.Fatalf("transport secret: %v", err)
	}
	if sec == nil {
		t.Logf("transport auth: none (no secret at %q)", cfg.SecretFile)
	} else {
		t.Logf("transport auth: enabled (%s)", cfg.SecretFile)
	}
	return cfg
}

func requireBench(t *testing.T) {
	t.Helper()
	if os.Getenv("DRAWBRIDGE_BENCH") == "" {
		t.Skip("set DRAWBRIDGE_BENCH=1 (or run `just bench`)")
	}
	if _, err := exec.LookPath("limactl"); err != nil {
		t.Skip("limactl not on PATH")
	}
	if out, err := limactl(t, "list", "--format", "{{.Status}}", vmName); err != nil || out != "Running" {
		t.Skipf("VM %s not running (%q, %v) — run `just vm-up && just agent-up`", vmName, out, err)
	}
	macAuth = loadMacAuth(t)
	// Results header: recorded tables must never be ambiguous about which
	// path they measured. DRAWBRIDGE_AGENT skips resolution outright, which
	// is how the forwarder gets benchmarked now that vznat-direct is the
	// resolved default (docs/transport.md §2.5).
	if ep := os.Getenv("DRAWBRIDGE_AGENT"); ep != "" {
		e, err := transport.Parse(ep)
		if err != nil {
			t.Fatalf("DRAWBRIDGE_AGENT=%q: %v", ep, err)
		}
		agentAddr = e.String()
		t.Logf("agent transport: %s source=override:%s", agentAddr, ep)
	} else {
		r := limaaddr.Resolve(vmName, agentPort)
		agentAddr = r.Endpoint
		t.Logf("agent transport: %s source=%s", agentAddr, r.Source)
		if r.Note != "" {
			t.Logf("agent transport note: %s", r.Note)
		}
	}
	c, err := transport.Dial(agentAddr)
	if err != nil {
		t.Fatalf("agent transport not reachable at %s — run `just agent-up`: %v", agentAddr, err)
	}
	c.Close()
}

// agentBin is the guest binary's path, identical on both sides of the rw
// mount.
func agentBin(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../bin/drawbridge-agent-linux-arm64")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("guest binary missing (run `just build`): %v", err)
	}
	return p
}

// benchclient runs the guest-side client and parses its JSON result line.
func benchclient(t *testing.T, args string) (benchtool.Result, error) {
	t.Helper()
	out, err := guest(t, agentBin(t)+" benchclient "+args)
	if err != nil {
		return benchtool.Result{}, fmt.Errorf("%v: %s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			var res benchtool.Result
			if err := json.Unmarshal([]byte(line), &res); err != nil {
				return benchtool.Result{}, fmt.Errorf("bad JSON %q: %w", line, err)
			}
			return res, nil
		}
	}
	return benchtool.Result{}, fmt.Errorf("no JSON in output: %s", out)
}

func macServer(t *testing.T, mode string) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go benchtool.Serve(ln, mode)
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func guestUnit(t *testing.T, name, mode string, port int) {
	t.Helper()
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", name, name))
	if out, err := guest(t, fmt.Sprintf(
		"systemd-run --unit=%s --collect %s benchserve -listen :%d -mode %s", name, agentBin(t), port, mode)); err != nil {
		t.Fatalf("start %s: %v: %s", name, err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", name)) })
}

func logRTT(t *testing.T, label string, res benchtool.Result) {
	t.Logf("%-24s connect p50/p95/p99 %5d/%5d/%5d µs   rtt p50/p95/p99/max %5d/%5d/%5d/%6d µs",
		label, res.ConnectUS.P50, res.ConnectUS.P95, res.ConnectUS.P99,
		res.RTTUS.P50, res.RTTUS.P95, res.RTTUS.P99, res.RTTUS.Max)
}

func logUDP(t *testing.T, label string, res benchtool.Result) {
	t.Logf("%-24s rtt p50/p95/p99/max %5d/%5d/%5d/%6d µs   drops %d",
		label, res.RTTUS.P50, res.RTTUS.P95, res.RTTUS.P99, res.RTTUS.Max, res.Drops)
}

// macUDPServer starts an in-process UDP server on Mac loopback.
func macUDPServer(t *testing.T, mode string) uint16 {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	if mode == "udphash" {
		go benchtool.UDPHashServe(pc)
	} else {
		go benchtool.UDPEchoServe(pc)
	}
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

// eCanary is an extra 'E' subscription held open across a bulk leg. The
// agent closes a subscription whose buffer overflows (AGENTS.md: the event
// stream never drops silently), and any transport-level starvation shows up
// the same way — as a read error on this conn. Zero events is not a failure
// (an idle guest emits only the initial snapshot); a dead session is.
type eCanary struct {
	conn   net.Conn
	mu     sync.Mutex
	err    error
	events int
}

func startECanary(t *testing.T) *eCanary {
	t.Helper()
	c, err := transport.Dial(agentAddr)
	if err != nil {
		t.Fatalf("'E' canary dial: %v", err)
	}
	// Hello + proof in one write, then the agent's proof before any event is
	// read — the same gate the real client applies (docs/transport-auth.md §3.2).
	sec, err := macAuth.Secret()
	if err != nil {
		c.Close()
		t.Fatalf("'E' canary secret: %v", err)
	}
	frame, err := transportauth.ClientHello(c, sec, 'E', nil)
	if err != nil {
		c.Close()
		t.Fatalf("'E' canary subscribe: %v", err)
	}
	if err := transportauth.AwaitAgentProof(c, sec, frame, transportauth.HandshakeTimeout); err != nil {
		c.Close()
		t.Fatalf("'E' canary handshake: %v", err)
	}
	ca := &eCanary{conn: c}
	go func() {
		dec := json.NewDecoder(c)
		for {
			var ev struct {
				Op string `json:"op"`
			}
			if err := dec.Decode(&ev); err != nil {
				ca.mu.Lock()
				ca.err = err
				ca.mu.Unlock()
				return
			}
			ca.mu.Lock()
			ca.events++
			ca.mu.Unlock()
		}
	}()
	return ca
}

func (ca *eCanary) check(t *testing.T, leg string) {
	t.Helper()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.err != nil {
		t.Errorf("'E' canary session died during %s: %v — head-of-line starvation or subscriber overflow", leg, ca.err)
		return
	}
	t.Logf("%-24s 'E' canary alive across %s (%d events)", "head-of-line", leg, ca.events)
}

func (ca *eCanary) close() { ca.conn.Close() }

func TestBench(t *testing.T) {
	requireBench(t)

	// drawbridged, production wiring, in-process.
	// Mac UDP targets exist before the syncer so UDPPorts can carry them.
	macUDPEchoPort := macUDPServer(t, "udpecho")
	macUDPHashPort := macUDPServer(t, "udphash")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := mirror.New(agentAddr, "127.0.0.1")
	m.Auth = macAuth
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		Auth:      macAuth,
		Exclude: func(l macsync.Listener) bool {
			return l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
		},
		UDPPorts: []uint16{macUDPEchoPort, macUDPHashPort},
	}
	go m.Run(ctx)
	go s.Run(ctx)

	// Mac-side targets for the outbound direction.
	echoPort := macServer(t, "echo")
	sinkPort := macServer(t, "sink")
	sourcePort := macServer(t, "source")

	// Wait until the Mac echo server is synced and reachable from the guest.
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

	t.Run("OutboundFirstByte", func(t *testing.T) {
		res, err := benchclient(t, fmt.Sprintf("-mode firstbyte -target 127.0.0.1:%d -iters %d", echoPort, rttIters))
		if err != nil {
			t.Fatal(err)
		}
		logRTT(t, "guest→Mac (drawbridge)", res)
	})

	t.Run("GuestBaseline", func(t *testing.T) {
		res, err := benchclient(t, fmt.Sprintf("-mode baseline -iters %d", rttIters))
		if err != nil {
			t.Fatal(err)
		}
		logRTT(t, "guest loopback (native)", res)
	})

	t.Run("OutboundThroughput", func(t *testing.T) {
		// Head-of-line assertion (docs/transport.md §2.5). On the shared SSH
		// tunnel a bulk leg starved the 'E' stream until its subscriber
		// buffer overflowed and the agent closed the subscription; on
		// vznat-direct each conn is its own TCP flow, so the canary must
		// survive 512 MiB untouched. Applied to the outbound legs on
		// purpose: the inbound bulk leg wedges with Little Snitch active
		// (plan.md §Benchmark), which would mask the signal here.
		canary := startECanary(t)
		defer canary.close()

		up, err := benchclient(t, fmt.Sprintf("-mode upload -target 127.0.0.1:%d -bytes %d", sinkPort, bulkBytes))
		if err != nil {
			t.Fatal(err)
		}
		down, err := benchclient(t, fmt.Sprintf("-mode download -target 127.0.0.1:%d -bytes %d", sourcePort, bulkBytes))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("guest→Mac upload   %7.1f MB/s (%d MiB in %.2fs)", up.MBPerSec, bulkBytes>>20, up.Seconds)
		t.Logf("guest→Mac download %7.1f MB/s (%d MiB in %.2fs)", down.MBPerSec, bulkBytes>>20, down.Seconds)
		canary.check(t, "outbound bulk")
	})

	t.Run("OutboundBurst", func(t *testing.T) {
		for _, k := range []int{4, 8, 16, 32} {
			res, err := benchclient(t, fmt.Sprintf("-mode burst -target 127.0.0.1:%d -conns %d -rounds %d", echoPort, k, burstRounds))
			if err != nil {
				t.Fatalf("burst %d: %v", k, err)
			}
			logRTT(t, fmt.Sprintf("burst k=%d (pool=%d)", k, macsync.DefaultPoolSize), res)
		}
	})

	// Guest-side targets for the inbound direction.
	guestUnit(t, "dbg-bench-echo", "echo", guestEchoPort)
	guestUnit(t, "dbg-bench-sink", "sink", guestSinkPort)
	guestUnit(t, "dbg-bench-source", "source", guestSourcePort)

	inboundEcho := fmt.Sprintf("127.0.0.1:%d", guestEchoPort)
	deadline = time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("guest echo :%d never mirrored on Mac: %v", guestEchoPort, lastErr)
		}
		if _, lastErr = benchtool.FirstByte(inboundEcho, 1); lastErr == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Run("InboundFirstByte", func(t *testing.T) {
		samples, err := benchtool.FirstByte(inboundEcho, rttIters)
		if err != nil {
			t.Fatal(err)
		}
		c, r := benchtool.QuantilesOf(benchtool.Connects(samples)), benchtool.QuantilesOf(benchtool.RTTs(samples))
		logRTT(t, "Mac→guest (drawbridge)", benchtool.Result{ConnectUS: &c, RTTUS: &r})
	})

	t.Run("MacBaseline", func(t *testing.T) {
		port := macServer(t, "echo")
		samples, err := benchtool.FirstByte(fmt.Sprintf("127.0.0.1:%d", port), rttIters)
		if err != nil {
			t.Fatal(err)
		}
		c, r := benchtool.QuantilesOf(benchtool.Connects(samples)), benchtool.QuantilesOf(benchtool.RTTs(samples))
		logRTT(t, "Mac loopback (native)", benchtool.Result{ConnectUS: &c, RTTUS: &r})
	})

	t.Run("InboundThroughput", func(t *testing.T) {
		d, err := benchtool.Upload(fmt.Sprintf("127.0.0.1:%d", guestSinkPort), bulkBytes)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Mac→guest upload   %7.1f MB/s (%d MiB in %.2fs)", benchtool.MBps(bulkBytes, d), bulkBytes>>20, d.Seconds())
		d, err = benchtool.Download(fmt.Sprintf("127.0.0.1:%d", guestSourcePort), bulkBytes)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Mac→guest download %7.1f MB/s (%d MiB in %.2fs)", benchtool.MBps(bulkBytes, d), bulkBytes>>20, d.Seconds())
	})

	// --- UDP legs (docs/udp.md U4) ---

	t.Run("OutboundUDPRTT", func(t *testing.T) {
		res, err := benchclient(t, fmt.Sprintf("-mode udprtt -target 127.0.0.1:%d -iters %d -size %d", macUDPEchoPort, rttIters, udpSize))
		if err != nil {
			t.Fatal(err)
		}
		logUDP(t, "guest→Mac udp (drawbr.)", res)
	})

	t.Run("GuestUDPBaseline", func(t *testing.T) {
		res, err := benchclient(t, fmt.Sprintf("-mode udpbaseline -iters %d -size %d", rttIters, udpSize))
		if err != nil {
			t.Fatal(err)
		}
		logUDP(t, "guest udp loop (native)", res)
	})

	t.Run("OutboundUDPBurst", func(t *testing.T) {
		// Fresh socket per query — the stub-resolver pattern. The first
		// wave includes the one-time stream activation.
		for _, k := range []int{4, 8, 16, 32} {
			res, err := benchclient(t, fmt.Sprintf("-mode udpburst -target 127.0.0.1:%d -conns %d -rounds %d -size %d", macUDPEchoPort, k, burstRounds, udpSize))
			if err != nil {
				t.Fatalf("udpburst %d: %v", k, err)
			}
			logUDP(t, fmt.Sprintf("udp burst k=%d", k), res)
		}
	})

	t.Run("OutboundUDPLarge", func(t *testing.T) {
		// Integrity at sizes far beyond the loopback MTU (guest→Mac only:
		// macOS's net.inet.udp.maxdgram caps Mac-side sends at ~9216).
		res, err := benchclient(t, fmt.Sprintf("-mode udplarge -target 127.0.0.1:%d -bytes %d", macUDPHashPort, udpLargeSz))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%-24s %d-byte datagram round-tripped intact (hash ack)", "guest→Mac udp large", res.Bytes)
	})

	guestUnit(t, "dbg-bench-udpecho", "udpecho", guestUDPEchoPort)

	t.Run("InboundUDPRTT", func(t *testing.T) {
		deadline := time.Now().Add(15 * time.Second)
		for !m.Mirrors("udp", guestUDPEchoPort) {
			if time.Now().After(deadline) {
				t.Fatalf("guest udp :%d never mirrored", guestUDPEchoPort)
			}
			time.Sleep(200 * time.Millisecond)
		}
		samples, drops, err := benchtool.UDPRTT(fmt.Sprintf("127.0.0.1:%d", guestUDPEchoPort), rttIters, udpSize)
		if err != nil {
			t.Fatal(err)
		}
		q := benchtool.QuantilesOf(samples)
		logUDP(t, "Mac→guest udp (drawbr.)", benchtool.Result{RTTUS: &q, Drops: drops})
	})

	t.Run("MacUDPBaseline", func(t *testing.T) {
		samples, drops, err := benchtool.UDPRTT(fmt.Sprintf("127.0.0.1:%d", macUDPEchoPort), rttIters, udpSize)
		if err != nil {
			t.Fatal(err)
		}
		q := benchtool.QuantilesOf(samples)
		logUDP(t, "Mac udp loop (native)", benchtool.Result{RTTUS: &q, Drops: drops})
	})
}
