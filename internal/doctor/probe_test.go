package doctor

// Check 8's classifier over probe transcripts, plus the live client against an
// in-process fake agent. The transcripts are the point: the killer signature
// took a week of field debugging to produce once, and every verdict below is
// reachable from a fixture instead of only from a filtered network.

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A transcript that reached the wire, with the shared fields already set.
func transcript(mut func(*HalfCloseProbe)) HalfCloseProbe {
	p := HalfCloseProbe{
		Ran:       true,
		Endpoint:  "tcp://192.168.64.2:4777",
		Source:    "vznat-direct",
		Auth:      true,
		PreBytes:  685,
		PreEvents: 1,
		Window:    ProbePostFINWindow,
	}
	mut(&p)
	return p
}

func TestCheckHalfCloseNotRun(t *testing.T) {
	f := CheckHalfClose(HalfCloseProbe{})
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "-probe")
}

func TestCheckHalfCloseSkipReasonIsCarried(t *testing.T) {
	f := CheckHalfClose(HalfCloseProbe{Skip: "no endpoint was resolved, so there is nothing to probe (see checks 1 and 4)."})
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "no endpoint was resolved")
}

// A session that never opened is checks 4/6/auth's diagnosis, not this one's:
// saying it twice in different words helps nobody.
func TestCheckHalfCloseNoSession(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.Err = "dial tcp 192.168.64.2:4777: i/o timeout"
		p.PreBytes, p.PreEvents = 0, 0
	}))
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "i/o timeout")
	wantContains(t, f, "checks 4 and 6")
}

func TestCheckHalfCloseContinuedEvents(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.PostBytes, p.PostEvents = 28, 2
	}))
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "kept streaming")
	wantNotContains(t, f, loopbackCaveat)
}

// "Clean EOF after continued events" is still the tolerant shape: the bytes
// crossed the FIN, and an 'E' session ending afterwards is ordinary.
func TestCheckHalfCloseContinuedThenEOF(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.PostBytes, p.PostEvents, p.PostEOF = 14, 1, true
	}))
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "ended cleanly")
}

func TestCheckHalfCloseStarvedIsTheKillerSignature(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.NEFilter = []string{"at.obdev.littlesnitch.networkextension"}
	}))
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "finding 4's signature")
	wantContains(t, f, "at.obdev.littlesnitch.networkextension")
	wantContains(t, f, "Network Extensions")
	// The window outlasting the ping is what makes silence mean something.
	wantContains(t, f, AgentPingEvery.String())
}

// With no NE filter found, the suspect order moves on to the forwarder — the
// reason LIMA_SSH_PORT_FORWARDER=true is pinned.
func TestCheckHalfCloseStarvedWithoutFilterBlamesTheForwarder(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {}))
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "LIMA_SSH_PORT_FORWARDER=true")
	wantContains(t, f, "gRPC tunnel drops TCP half-close")
}

// §D6's gate, spelled exactly. If the agent ever closes on client FIN the
// probe cannot discriminate — and the answer is never to change the agent.
func TestCheckHalfCloseGateSkipsWhenTheSessionEndsAtTheFIN(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.PostEOF = true
	}))
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "the agent closes on client FIN, so a half-close probe cannot distinguish an NE filter from "+
		"normal agent behavior; the probe waits for an agent that streams past FIN")
}

// Loopback is exempt from both LS bugs, so every loopback verdict — pass or
// starve — is labelled non-evidence for the vznat path.
func TestCheckHalfCloseLoopbackIsLabelledNonEvidence(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*HalfCloseProbe)
		want Status
	}{
		{"pass", func(p *HalfCloseProbe) { p.PostBytes, p.PostEvents = 14, 1 }, StatusOK},
		{"starved", func(p *HalfCloseProbe) {}, StatusWarn},
		{"eof at the fin", func(p *HalfCloseProbe) { p.PostEOF = true }, StatusSkip},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
				p.Endpoint, p.Source, p.Loopback = "tcp://127.0.0.1:4777", "ssh-forwarder", true
				tc.mut(p)
			}))
			wantStatus(t, f, tc.want)
			wantContains(t, f, "NOT about the vznat-direct path")
		})
	}
}

// A loopback starve is never the LS signature, so it must not be reported as
// one — the fail branch's remedies would send the user after the wrong thing.
func TestCheckHalfCloseLoopbackStarveIsNotAFail(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.Endpoint, p.Loopback = "tcp://127.0.0.1:4777", true
		p.NEFilter = []string{"at.obdev.littlesnitch.networkextension"}
	}))
	wantStatus(t, f, StatusWarn)
	wantNotContains(t, f, "Login Items & Extensions")
}

// A silent session leaves nothing to compare across the FIN.
func TestCheckHalfCloseNoSnapshot(t *testing.T) {
	f := CheckHalfClose(transcript(func(p *HalfCloseProbe) {
		p.PreBytes, p.PreEvents = 0, 0
	}))
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "snapshot")
}

// The -probe floor: a 30s default (or a user's short -timeout) would cut the
// post-FIN window short and manufacture the starve verdict.
func TestProbeRaisesTheTimeoutFloor(t *testing.T) {
	if got := effectiveTimeout(Options{}); got != 30*time.Second {
		t.Fatalf("default timeout = %s, want 30s", got)
	}
	if got := effectiveTimeout(Options{Probe: true, Timeout: 5 * time.Second}); got != ProbeBudget {
		t.Fatalf("-probe -timeout 5s = %s, want the %s floor", got, ProbeBudget)
	}
	if got := effectiveTimeout(Options{Probe: true, Timeout: 5 * time.Minute}); got != 5*time.Minute {
		t.Fatalf("a generous -timeout was lowered to %s", got)
	}
	if got := effectiveTimeout(Options{Timeout: 5 * time.Second}); got != 5*time.Second {
		t.Fatalf("the floor applied without -probe: %s", got)
	}
	if ProbeBudget <= ProbePostFINWindow+ProbeSnapshotWindow {
		t.Fatalf("ProbeBudget %s leaves no room for the probe's own windows", ProbeBudget)
	}
}

func TestLoopbackEndpoint(t *testing.T) {
	tests := []struct {
		ep   string
		want bool
	}{
		{"tcp://127.0.0.1:4777", true},
		{"127.0.0.1:4777", true},
		{"tcp://[::1]:4777", true},
		{"localhost:4777", true},
		{"tcp://192.168.64.2:4777", false},
		{"unix:///var/run/drawbridge/x.sock", true},
		{"nonsense", false},
	}
	for _, tc := range tests {
		if got := loopbackEndpoint(tc.ep); got != tc.want {
			t.Errorf("loopbackEndpoint(%q) = %v, want %v", tc.ep, got, tc.want)
		}
	}
}

// --- the live client, against an in-process fake agent ----------------------

// fakeAgent speaks just enough of the 'E' wire: read the 4-byte frame, write a
// snapshot line, then whatever the test wants. Unauthenticated (auth=0) —
// transportauth's own tests own the proof exchange; this one owns the FIN.
func fakeAgent(t *testing.T, after func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var frame [4]byte
		if _, err := io.ReadFull(c, frame[:]); err != nil {
			return
		}
		if frame[0] != 'E' {
			return
		}
		if _, err := c.Write([]byte(`{"op":"snapshot","listeners":[]}` + "\n")); err != nil {
			return
		}
		after(c)
	}()
	return "tcp://" + ln.Addr().String()
}

func TestRunHalfCloseProbeSeesBytesAfterFIN(t *testing.T) {
	ep := fakeAgent(t, func(c net.Conn) {
		time.Sleep(50 * time.Millisecond)
		c.Write([]byte(`{"op":"ping"}` + "\n"))
		time.Sleep(200 * time.Millisecond)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := runProbeWithWindow(ctx, HalfCloseTarget{Endpoint: ep, Source: "test"}, 2*time.Second)
	if !p.Ran || p.Err != "" {
		t.Fatalf("probe did not run: %+v", p)
	}
	if p.PreEvents != 1 {
		t.Fatalf("pre-FIN events = %d, want 1 (%+v)", p.PreEvents, p)
	}
	if p.PostBytes == 0 {
		t.Fatalf("no bytes after FIN: %+v", p)
	}
	if !p.Loopback {
		t.Fatalf("loopback endpoint not recognised: %+v", p)
	}
	wantStatus(t, CheckHalfClose(p), StatusOK)
}

// The probe must observe a closing agent as EOF, not as a starve — the two
// verdicts point at completely different things.
func TestRunHalfCloseProbeSeesEOF(t *testing.T) {
	// The close has to land after the probe has read the snapshot: an agent
	// that hangs up *before* the FIN is a different transcript (Err), because
	// there was no half-close to test.
	ep := fakeAgent(t, func(c net.Conn) {
		time.Sleep(150 * time.Millisecond)
		c.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := runProbeWithWindow(ctx, HalfCloseTarget{Endpoint: ep, Source: "test"}, 2*time.Second)
	if !p.PostEOF || p.PostBytes != 0 || p.Err != "" {
		t.Fatalf("want a clean EOF and no post-FIN bytes, got %+v", p)
	}
	wantStatus(t, CheckHalfClose(p), StatusSkip)
}

// The starve: an agent that says nothing more and never closes.
func TestRunHalfCloseProbeStarves(t *testing.T) {
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	ep := fakeAgent(t, func(c net.Conn) { <-done })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := runProbeWithWindow(ctx, HalfCloseTarget{Endpoint: ep, Source: "test"}, 300*time.Millisecond)
	if p.PostBytes != 0 || p.PostEOF {
		t.Fatalf("want a starved read, got %+v", p)
	}
	// Loopback, so the honest verdict is a labelled warn and never the fail.
	f := CheckHalfClose(p)
	wantStatus(t, f, StatusWarn)
}

// An agent that hangs up before the probe ever half-closes is not the gate
// condition and must not be reported as one — there was no FIN to tolerate.
func TestRunHalfCloseProbeEOFBeforeTheFIN(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		var frame [4]byte
		io.ReadFull(c, frame[:])
		c.Close() // not one event, straight to EOF
	}()
	p := runProbeWithWindow(context.Background(),
		HalfCloseTarget{Endpoint: "tcp://" + ln.Addr().String()}, 2*time.Second)
	if p.Err == "" || !strings.Contains(p.Err, "before the probe closed its write half") {
		t.Fatalf("want the pre-FIN-EOF transcript, got %+v", p)
	}
	f := CheckHalfClose(p)
	wantStatus(t, f, StatusSkip)
	wantNotContains(t, f, gateSkipReason)
}

func TestRunHalfCloseProbeUnreachableEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing is listening there now
	p := RunHalfCloseProbe(context.Background(), HalfCloseTarget{Endpoint: "tcp://" + addr})
	if p.Err == "" {
		t.Fatalf("want a dial error, got %+v", p)
	}
	wantStatus(t, CheckHalfClose(p), StatusSkip)
}

// A configured-but-unreadable secret fails closed, in the daemon's own words —
// the probe must not fall back to an unauthenticated hello.
func TestRunHalfCloseProbeMalformedSecretFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := RunHalfCloseProbe(context.Background(), HalfCloseTarget{
		Endpoint: "tcp://127.0.0.1:1", SecretFile: path, VM: "lima:drawbridge",
	})
	if p.Err == "" || !strings.Contains(p.Err, "transport secret") {
		t.Fatalf("want the §7 secret-unreadable line, got %q", p.Err)
	}
	if p.Auth {
		t.Fatal("an unusable secret must never be reported as authenticated")
	}
}
