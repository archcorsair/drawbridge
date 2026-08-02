package doctor

// Check 8 — the active half-close probe (docs/doctor.md §D6, §4 check 8),
// both halves: the live client and the pure classifier over its transcript.
//
// The probe is a *client* and nothing else. It speaks the real `'E'` wire —
// the 4-byte conn-type frame plus the static-HMAC proof in ONE write, through
// transportauth.ClientHello, exactly as internal/mirror does, with the agent's
// own proof verified before a single event byte is trusted — then closes its
// write half and keeps reading. There is no wire change, no agent change and
// no state change anywhere: an `'E'` subscription is read-only by protocol
// design, and the probe never opens an `'R'` conn, so it takes no part in bind
// arbitration.
//
// What it discriminates. The `'E'` direction is agent-push: the agent never
// reads a byte from an `'E'` conn (internal/agent.serveEvents), so it has no
// reason to notice a client FIN, and bytes that keep arriving after one are
// proof the path still delivers them. Finding 4 in
// docs/notes/local-network-permission.md is the opposite shape — with an
// LS-class network extension active, inbound bytes on a *non-loopback* flow
// are ACKed by the kernel after the app's shutdown(SHUT_WR) and never
// delivered to the process, so the read starves forever. Loopback flows are
// exempt from both LS bugs, which is why a loopback verdict is reported and
// then explicitly labelled non-evidence for the vznat path.
//
// **Live correction to §D6's sketch (verified 2026-08-01, dev VM over the
// loopback forwarder):** the post-FIN window is 20 s, not 3 s. The agent
// tolerates the FIN — it kept the session and wrote `{"op":"ping"}` at +15 s
// and +30 s — but after the initial snapshot its *only* self-generated
// traffic on a quiet guest is that 15 s liveness ping. A 3 s window would
// therefore starve on a perfectly healthy path and report the killer
// signature for every guest that happened not to bind a port during the
// probe. The window has to outlast one ping, and doctor's global budget gets
// a floor to match (ProbeBudget).

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// Probe timings. AgentPingEvery is not imported from internal/agent (that
// package is linux-only): it is the `'E'` stream's documented liveness cadence
// (docs/transport.md §2.6), and the post-FIN window exists to outlast it.
const (
	AgentPingEvery = 15 * time.Second
	// ProbeSnapshotWindow bounds the pre-FIN read: the hub primes every new
	// subscriber with a snapshot event, so this normally returns at once.
	ProbeSnapshotWindow = 1 * time.Second
	// ProbePostFINWindow is the read window after CloseWrite.
	ProbePostFINWindow = AgentPingEvery + 5*time.Second
	// ProbeBudget is the floor Gather puts under -timeout when -probe is
	// passed. Truncating the one check the flag was passed for would turn a
	// healthy agent into the killer signature.
	ProbeBudget = 60 * time.Second
)

// HalfCloseProbe is the probe transcript: what the wire did, with no verdict
// attached. It is the seam the classifier tests drive — every state below is
// reachable from a fixture instead of only from a filtered network.
type HalfCloseProbe struct {
	Ran      bool   // the probe was asked to run and got as far as dialing
	Skip     string // why it did not run (no -probe, no endpoint)
	Endpoint string
	Source   string // limaaddr resolution source, for the report line
	Loopback bool   // the endpoint is loopback (or unix): exempt from both LS bugs
	Auth     bool   // a secret was configured, so the agent proved itself too
	Err      string // dial or handshake failure; the probe says nothing then

	PreBytes   int // bytes read before CloseWrite
	PreEvents  int // newline-terminated events read before CloseWrite
	PostBytes  int // bytes read after CloseWrite
	PostEvents int
	PostEOF    bool          // the agent closed its half during the window
	Window     time.Duration // the post-FIN read window actually used

	NEFilter []string // check 7's activated extensions, for suspect ordering
}

// HalfCloseTarget is what the live probe needs: the endpoint check 4 resolved,
// and the same per-VM secret path the daemon would use.
type HalfCloseTarget struct {
	Endpoint   string
	Source     string
	SecretFile string
	VM         string
	NEFilter   []string
}

// RunHalfCloseProbe dials, completes the `'E'` hello, reads the primed
// snapshot, closes its write half and keeps reading. It returns a transcript,
// never a verdict, and never an error: a probe that could not run is a
// reportable state, not a doctor failure.
func RunHalfCloseProbe(ctx context.Context, t HalfCloseTarget) HalfCloseProbe {
	return runProbeWithWindow(ctx, t, ProbePostFINWindow)
}

// runProbeWithWindow is the body, with the post-FIN window injected so the
// tests can drive the same code in milliseconds. The window is a transcript
// field, not a constant the classifier assumes.
func runProbeWithWindow(ctx context.Context, t HalfCloseTarget, window time.Duration) HalfCloseProbe {
	p := HalfCloseProbe{
		Ran:      true,
		Endpoint: t.Endpoint,
		Source:   t.Source,
		Loopback: loopbackEndpoint(t.Endpoint),
		Window:   window,
		NEFilter: t.NEFilter,
	}

	auth := transportauth.MacConfig{
		SecretFile: t.SecretFile,
		VM:         t.VM,
		Source:     func() string { return t.Source },
	}
	sec, err := auth.Secret()
	if err != nil {
		p.Err = auth.Wrap(err, t.Endpoint).Error()
		return p
	}
	p.Auth = sec != nil

	conn, err := transport.DialTimeout(t.Endpoint, transport.DefaultDialTimeout)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// Frame + proof in one Write, then the agent's proof before a single
	// event byte is trusted — the mirror client's exact order, and the reason
	// the frame layout has one source of truth (transportauth.ClientHello).
	frame, err := transportauth.ClientHello(conn, sec, 'E', nil)
	if err != nil {
		p.Err = err.Error()
		return p
	}
	if err := transportauth.AwaitAgentProof(conn, sec, frame, transportauth.HandshakeTimeout); err != nil {
		p.Err = auth.Wrap(err, t.Endpoint).Error()
		return p
	}

	pre := readWindow(conn, ProbeSnapshotWindow, true)
	p.PreBytes, p.PreEvents = pre.bytes, pre.events
	if pre.eof {
		// The agent hung up before the probe ever closed its write half, so
		// there is no half-close to talk about — and reporting this as the
		// post-FIN EOF would name the wrong condition entirely.
		p.Err = "the agent ended the session before the probe closed its write half, so there was no half-close to test"
		return p
	}

	hc, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		p.Err = "this endpoint's conn cannot half-close, so the probe has nothing to test"
		return p
	}
	if err := hc.CloseWrite(); err != nil {
		p.Err = "CloseWrite: " + err.Error()
		return p
	}

	post := readWindow(conn, window, false)
	p.PostBytes, p.PostEvents, p.PostEOF = post.bytes, post.events, post.eof
	return p
}

type windowResult struct {
	bytes  int
	events int
	eof    bool
}

// readWindow reads until the deadline, or — when stopEarly — as soon as one
// complete newline-terminated event has arrived. Events are counted by
// newline rather than decoded: the half-close signature is about bytes being
// delivered at all, and a JSON decoder cut off mid-object by a deadline would
// lose the count it was supposed to report.
func readWindow(c net.Conn, window time.Duration, stopEarly bool) windowResult {
	var out windowResult
	if err := c.SetReadDeadline(time.Now().Add(window)); err != nil {
		return out
	}
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 32<<10)
	for {
		n, err := c.Read(buf[:])
		if n > 0 {
			out.bytes += n
			out.events += bytes.Count(buf[:n], []byte{'\n'})
		}
		if err != nil {
			if !isTimeout(err) {
				out.eof = true
			}
			return out
		}
		if stopEarly && out.events > 0 {
			return out
		}
	}
}

// loopbackEndpoint reports whether the resolved endpoint is exempt from the
// two LS bugs. A unix socket counts: it is local IPC, never a filtered flow.
func loopbackEndpoint(ep string) bool {
	e, err := transport.Parse(ep)
	if err != nil {
		return false
	}
	if e.Scheme != transport.SchemeTCP {
		return true
	}
	host, _, err := net.SplitHostPort(e.Addr)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return strings.EqualFold(host, "localhost")
	}
	return addr.IsLoopback()
}

// ---------------------------------------------------------------------------
// 8. half-close-probe — the classifier
// ---------------------------------------------------------------------------

// loopbackCaveat is attached to every loopback verdict, in both directions.
// A loopback probe is a real test of the *agent*, and no test at all of the
// path the vznat-direct endpoint would take.
const loopbackCaveat = "the endpoint is loopback, which is exempt from both LS bugs — this is evidence about the agent, " +
	"NOT about the vznat-direct path; re-run with the direct endpoint resolved (checks 5 and 6 say why it was not)."

// gateSkipReason is §D6's gate, spelled exactly. If the agent ever closes on
// client FIN, the probe cannot discriminate and says so — the answer is never
// to change the agent.
const gateSkipReason = "the agent closes on client FIN, so a half-close probe cannot distinguish an NE filter from " +
	"normal agent behavior; the probe waits for an agent that streams past FIN"

// CheckHalfClose classifies a probe transcript (§4 check 8). Pure: every
// verdict below is reachable from a fixture.
func CheckHalfClose(p HalfCloseProbe) Finding {
	f := Finding{ID: IDHalfClose}

	if !p.Ran {
		f.Status = StatusSkip
		f.Title = "half-close probe — not run"
		f.Evidence = append(f.Evidence, firstNonEmpty(p.Skip,
			"the active half-close probe is opt-in; pass -probe to run it."))
		return f
	}

	where := p.Endpoint
	if p.Source != "" {
		where += " (source " + p.Source + ")"
	}

	if p.Err != "" {
		// Reachability and authentication have their own checks with their own
		// remedies; check 8 needs a working 'E' session before it can say
		// anything at all, and saying it twice in different words helps nobody.
		f.Status = StatusSkip
		f.Title = "half-close probe — no `'E'` session to half-close"
		f.Evidence = append(f.Evidence, "endpoint: "+where, p.Err,
			"checks 4 and 6 diagnose reachability and the auth block diagnoses the handshake; check 8 only speaks once a session survives to the FIN.")
		return f
	}

	f.Evidence = append(f.Evidence,
		"endpoint: "+where+authSuffix(p.Auth),
		evidenceCounts(p))

	switch {
	case p.PreBytes == 0:
		f.Status = StatusSkip
		f.Title = "half-close probe — the agent sent no snapshot"
		f.Evidence = append(f.Evidence,
			"the hub primes every new subscriber with a snapshot event, so a silent session is itself abnormal — but it leaves nothing to compare across the FIN.")
		return f

	case p.PostBytes > 0:
		f.Status = StatusOK
		f.Title = "half-close probe — the agent kept streaming after the client's FIN"
		f.Evidence = append(f.Evidence,
			"bytes arrived after CloseWrite, so this path delivers server data across a client half-close.")
		if p.PostEOF {
			f.Evidence = append(f.Evidence, "the session then ended cleanly, which is an ordinary end to an `'E'` session.")
		}
		if p.Loopback {
			f.Evidence = append(f.Evidence, loopbackCaveat)
		}
		return f

	case p.PostEOF:
		// §D6's gate. Live verification (2026-08-01) says the agent does NOT
		// do this — serveEvents never reads the conn — so reaching this branch
		// means something else ended the session, and either way the probe
		// cannot discriminate. It reports that and stops; the agent is not the
		// thing to change.
		f.Status = StatusSkip
		f.Title = "half-close probe — the session ended at the FIN"
		f.Evidence = append(f.Evidence, gateSkipReason+".")
		if p.Loopback {
			f.Evidence = append(f.Evidence, loopbackCaveat)
		}
		return f
	}

	// Starved: no bytes, no EOF, for the whole window — and the window
	// outlasts the agent's 15 s liveness ping, so silence is not "the guest
	// was quiet".
	f.Evidence = append(f.Evidence,
		"nothing arrived and the peer never closed, for the whole window — and the window outlasts the agent's "+
			AgentPingEvery.String()+" liveness ping, so a quiet guest does not explain it.",
		"this is finding 4's signature exactly: after shutdown(SHUT_WR) the inbound bytes are ACKed by the kernel and never delivered to the process.")
	if p.Loopback {
		f.Status = StatusWarn
		f.Title = "half-close probe — starved read on a loopback endpoint"
		f.Evidence = append(f.Evidence, loopbackCaveat)
		f.Remedy = "loopback should never show this — check whether the agent is still alive (`drawbridge doctor` check 3) before suspecting a filter"
		return f
	}

	f.Status = StatusFail
	f.Title = "half-close probe — the read starved after the client's FIN"
	if len(p.NEFilter) > 0 {
		f.Evidence = append(f.Evidence,
			"check 7 found activated network extension(s): "+strings.Join(p.NEFilter, ", ")+" — the first suspect, in that order.")
		f.Remedy = "System Settings → General → Login Items & Extensions → Network Extensions, and deactivate it (not just \"disable the filter\")\n" +
			"— then re-run `drawbridge doctor -probe`; if it still starves, the endpoint's forwarder is the next suspect"
	} else {
		f.Evidence = append(f.Evidence,
			"no activated network extension was found (check 7), so the next suspect is a half-close-dropping forwarder in the path.")
		f.Remedy = "if this endpoint is a provider forwarder, pin the SSH forwarder (`LIMA_SSH_PORT_FORWARDER=true`, as `just vm-up` does)\n" +
			"— Lima's default gRPC tunnel drops TCP half-close, which is exactly this signature"
	}
	f.Data = map[string]any{"endpoint": p.Endpoint, "source": p.Source, "window": p.Window.String()}
	return f
}

func authSuffix(auth bool) string {
	if auth {
		return ", authenticated"
	}
	return ", unauthenticated"
}

func evidenceCounts(p HalfCloseProbe) string {
	return fmt.Sprintf("before FIN: %d event(s) / %d bytes; after FIN (%s): %d event(s) / %d bytes%s",
		p.PreEvents, p.PreBytes, p.Window, p.PostEvents, p.PostBytes, eofSuffix(p.PostEOF))
}

func eofSuffix(eof bool) string {
	if eof {
		return ", then EOF"
	}
	return ", no EOF"
}
