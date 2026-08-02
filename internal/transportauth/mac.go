package transportauth

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// RefusalLogEvery is the throttle window for refusal lines: the Mac's dial
// loops retry every second, and journal spam would bury the diagnosis (§7).
const RefusalLogEvery = 30 * time.Second

// Throttle emits one line per key per window. A nil *Throttle allows
// everything, so a client constructed without one (tests, harnesses) still
// logs every decision.
type Throttle struct {
	every time.Duration
	now   func() time.Time // test seam; nil ⇒ time.Now

	mu   sync.Mutex
	last map[string]time.Time
}

func NewThrottle(every time.Duration) *Throttle {
	return &Throttle{every: every, last: map[string]time.Time{}}
}

func (t *Throttle) Allow(key string) bool {
	if t == nil {
		return true
	}
	now := time.Now()
	if t.now != nil {
		now = t.now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = map[string]time.Time{}
	}
	if seen, ok := t.last[key]; ok && now.Sub(seen) < t.every {
		return false
	}
	if len(t.last) > 1024 { // unbounded keys must not grow the map forever
		for k, seen := range t.last {
			if now.Sub(seen) >= t.every {
				delete(t.last, k)
			}
		}
	}
	t.last[key] = now
	return true
}

// Doctor check IDs for the Mac-side refusal causes (docs/transport-auth.md
// §7 → docs/doctor.md §5). They are spelled here, at the emit sites, rather
// than imported: this package is a leaf that both the daemon and the guest
// agent link, and internal/introspect derives its socket paths from its
// home-directory rule, so the dependency must not run both ways.
// internal/doctor spells the same strings as its finding IDs; the design
// note is the contract both sides implement.
const (
	CheckAuthMismatch   = "auth-mismatch"           // rows 2 and 4
	CheckAuthWrongPeer  = "auth-wrong-peer"         // row 5
	CheckAuthFilePerms  = "auth-file-perms"         // row 8
	CheckAuthMacMissing = "auth-mac-missing-secret" // rows 1 and 6
)

// Recorder receives ID-tagged refusal lines. *introspect.Ring implements it;
// an interface keeps this package free of the introspection payload types,
// and a nil Recorder records nothing.
type Recorder interface {
	Record(id, line string)
}

// MacConfig is the Mac side's transport-auth configuration plus the context
// its refusal lines need (§7 rows 4–6): which VM this daemon was pointed at,
// where the endpoint came from, and where the secret was expected. It is
// carried by both Mac-side clients so the two speak with one voice.
//
// The zero value is unauthenticated mode: today's wire, byte-identical.
type MacConfig struct {
	// SecretFile is the secret's path. Empty, or a path with no file, means
	// unauthenticated. Re-read per dial, so rotation heals live (§5).
	SecretFile string
	// VM is the -vm spelling, named in the remedies ("drawbridge up <vm>").
	VM string
	// Source reports where the current endpoint came from ("vznat-direct",
	// "forwarder", "flag"). Row 5's job is to make a forwarder-fallback
	// attach self-explaining, so this is not decoration.
	Source func() string
	// Throttle, when set, rate-limits the lines callers log off Diagnose.
	// Shared between clients so the daemon speaks once per cause, not once
	// per dial loop.
	Throttle *Throttle
	// Refusals, when set, receives every line the throttle admits, tagged
	// with the §7 check ID — the ring doctor reads runtime auth evidence
	// from (docs/doctor.md §3.2), which is how a foreground daemon with no
	// log file still produces evidence. Unset changes no behavior.
	Refusals Recorder
}

// Secret loads the configured secret, or reports nil for unauthenticated
// mode. A malformed file is a refusal, not an ordinary error:
// configured-but-unusable always fails closed, and it must reach the log as
// row 8's diagnosis rather than as a bare parse failure (§5).
func (m MacConfig) Secret() (*Secret, error) {
	s, err := LoadOptional(m.SecretFile)
	if err != nil {
		return nil, refuse(CauseSecretUnreadable, err)
	}
	return s, nil
}

func (m MacConfig) vm() string {
	if m.VM == "" {
		return "<vm>"
	}
	return m.VM
}

func (m MacConfig) source() string {
	if m.Source == nil {
		return "unknown"
	}
	if s := m.Source(); s != "" {
		return s
	}
	return "unknown"
}

// Diagnose renders the §7 line for a Mac-side handshake failure, or "" when
// err is not a refusal (the caller then handles it as an ordinary I/O
// error). Rows 4 and 5 are one condition seen from two vantage points, so
// they are distinguished by cause, never by errno: EOF and ECONNRESET both
// mean "the peer closed on us mid-handshake".
func (m MacConfig) Diagnose(err error, ep string) string {
	cause, ok := CauseOf(err)
	if !ok {
		return ""
	}
	switch cause {
	case CauseProofMismatch: // row 5 — THE line for the demonstrated failure
		return fmt.Sprintf("peer at %s presented an invalid transport secret: this is NOT the agent '%s' was provisioned for — wrong VM or a squatter answered (source=%s); refusing. Check -vm, and whether the transport fell back to the loopback forwarder",
			ep, m.vm(), m.source())
	case CauseSecretUnreadable: // row 8, this side's half
		return fmt.Sprintf("this Mac's transport secret is unusable (%v) — it must be 64 hex characters, mode 0600; re-run 'drawbridge up %s' to reprovision", innermost(err), m.vm())
	default: // row 4
		// Row 4 also carries row 5's wrong-peer job: in the live mismatch
		// topology the agent refuses proof_mac and closes before sending its
		// own proof, so the Mac never reaches the row-5 verdict — this line
		// is the one the demonstrated wrong-VM fallback attach actually
		// produces, and "re-run up" alone is the wrong remedy when the
		// daemon is dialing a different VM's endpoint. Naming the resolution
		// source makes the fallback case self-explaining.
		return fmt.Sprintf("agent at %s closed during transport authentication (source=%s) — the guest's secret differs, the agent predates auth, or this is a DIFFERENT VM's agent reached via a fallback path; re-run 'drawbridge up %s' to converge, and if the source above is not vznat-direct, check why resolution fell back ('drawbridge doctor' compares both sides)",
			ep, m.source(), m.vm())
	}
}

// ClosedEarly is row 6: we sent auth=0 because we have no secret, and the
// conn died before the agent said anything. The likeliest cause is a guest
// that *is* provisioned, so the line names the file this daemon would have
// used and both commands that produce it.
func (m MacConfig) ClosedEarly(ep string) string {
	where := m.SecretFile
	if where == "" {
		where = "no path derived (pass -secret-file)"
	}
	return fmt.Sprintf("agent at %s closed the connection immediately — if that guest was provisioned with a transport secret, this daemon needs one too: expected at %s (not found). 'drawbridge up' writes it; 'sudo drawbridge install' points the daemon at it",
		ep, where)
}

// innermost unwraps a refusal to the error it carries, so a line quotes the
// actual parse or I/O failure rather than the refusal wrapper around it.
func innermost(err error) error {
	var r *RefusedError
	if errors.As(err, &r) && r.Err != nil {
		return r.Err
	}
	return err
}

// Wrap turns a handshake failure into an error whose message *is* the §7
// diagnosis, so a caller that already logs its session errors prints the
// remedy instead of a bare I/O error. The cause stays reachable through
// errors.As/CauseOf. Non-refusal errors pass through untouched.
func (m MacConfig) Wrap(err error, ep string) error {
	line := m.Diagnose(err, ep)
	if line == "" {
		return err
	}
	return &diagError{line: line, err: err}
}

type diagError struct {
	line string
	err  error
}

func (e *diagError) Error() string { return e.line }
func (e *diagError) Unwrap() error { return e.err }

// AllowLine reports whether a rendered line should be logged now, keyed on
// its cause and endpoint so one failing endpoint cannot mute another.
func (m MacConfig) AllowLine(err error, ep string) bool {
	cause, _ := CauseOf(err)
	return m.Throttle.Allow(string(cause) + "@" + ep)
}

// CheckID maps a refusal cause to the doctor check its evidence belongs to.
// Rows 4 and 5 are one condition from two vantage points, but they carry
// different IDs because only row 5 proves the peer is a different VM's agent.
func (m MacConfig) CheckID(err error) string {
	cause, ok := CauseOf(err)
	if !ok {
		return CheckAuthMismatch
	}
	switch cause {
	case CauseProofMismatch:
		return CheckAuthWrongPeer
	case CauseSecretUnreadable:
		return CheckAuthFilePerms
	default:
		return CheckAuthMismatch
	}
}

// Report renders the §7 line for a per-connection refusal and returns it only
// when the throttle admits it, recording it in the refusal ring on the way
// out. It is the one place the log line and the ID-tagged evidence are
// produced together, so the two cannot drift.
func (m MacConfig) Report(err error, ep string) string {
	line := m.Diagnose(err, ep)
	if line == "" || !m.AllowLine(err, ep) {
		return ""
	}
	m.Record(m.CheckID(err), line)
	return line
}

// Record files an ID-tagged line in the refusal ring, if one is configured.
// Exported because rows without a refusal cause — row 6's immediate close —
// are diagnosed by their caller and still belong in the ring.
func (m MacConfig) Record(id, line string) {
	if m.Refusals == nil {
		return
	}
	m.Refusals.Record(id, line)
}
