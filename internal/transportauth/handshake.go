package transportauth

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// HandshakeTimeout bounds every handshake read on both sides (§3.2). It also
// bounds the agent's frame read, which until now could pin a goroutine
// forever on a dialer that connected and then said nothing.
const HandshakeTimeout = 5 * time.Second

// Cause classifies a refusal so callers can render the §7 log line and
// throttle per (cause, source) without string-matching an error.
type Cause string

const (
	// CausePeerUnauthenticated: we hold a secret, the peer sent auth=0 (row 1).
	CausePeerUnauthenticated Cause = "peer-unauthenticated"
	// CauseProofMismatch: the peer holds a different secret (rows 2 and 5).
	CauseProofMismatch Cause = "invalid-secret"
	// CauseNoLocalSecret: the peer requires auth, we have no secret (row 3).
	CauseNoLocalSecret Cause = "no-local-secret"
	// CauseIncomplete: the conn died or stalled mid-handshake (row 4).
	CauseIncomplete Cause = "handshake-incomplete"
	// CauseSecretUnreadable: our own secret file is malformed/unreadable (row 8).
	CauseSecretUnreadable Cause = "secret-unreadable"
)

// RefusedError is a refusal: a closed conn plus a diagnosis, never a
// warning-and-continue (§1).
type RefusedError struct {
	Cause Cause
	Err   error // underlying I/O or load error, if any
}

func (e *RefusedError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("transport auth refused (%s): %v", e.Cause, e.Err)
	}
	return fmt.Sprintf("transport auth refused (%s)", e.Cause)
}

func (e *RefusedError) Unwrap() error { return e.Err }

// CauseOf reports the refusal cause carried by err, if any.
func CauseOf(err error) (Cause, bool) {
	var r *RefusedError
	if errors.As(err, &r) {
		return r.Cause, true
	}
	return "", false
}

func refuse(c Cause, err error) *RefusedError { return &RefusedError{Cause: c, Err: err} }

// ClientHello writes the Mac side's opening segment in ONE Write: the 4-byte
// type frame, the Mac proof when a secret is configured, then extra (the 'S'
// conn's 4-byte stream header; nil for every other type). One write is the
// invariant — the frame must never reach the wire as a lone segment, and the
// proof must never be a segment of its own (§3.3, DPI).
//
// It returns the frame it wrote, which AwaitAgentProof needs to recompute the
// agent's proof.
func ClientHello(w io.Writer, sec *Secret, typ byte, extra []byte) ([FrameLen]byte, error) {
	frame := AuthFrame(typ, sec)
	hello := make([]byte, 0, FrameLen+ProofLen+len(extra))
	hello = append(hello, frame[:]...)
	if sec != nil {
		p := sec.MacProof(frame)
		hello = append(hello, p[:]...)
	}
	hello = append(hello, extra...)
	if _, err := w.Write(hello); err != nil {
		return frame, err
	}
	return frame, nil
}

// AwaitAgentProof reads and verifies the agent's proof before the caller
// trusts or forwards a single payload byte. It is a no-op when no secret is
// configured (auth=0: today's wire, byte-identical).
//
// The read deadline is cleared on return: what follows on this conn is a
// parked 'D' (silent for as long as the guest likes), a long-lived 'E'
// session, or a splice — none of which may inherit a handshake deadline.
func AwaitAgentProof(c net.Conn, sec *Secret, frame [FrameLen]byte, timeout time.Duration) error {
	if sec == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	if err := c.SetReadDeadline(time.Now().Add(timeout)); err == nil {
		defer c.SetReadDeadline(time.Time{})
	}
	var got [ProofLen]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		return refuse(CauseIncomplete, err)
	}
	if !Verify(sec.AgentProof(frame), got[:]) {
		return refuse(CauseProofMismatch, nil)
	}
	return nil
}

// ServerHandshake is the agent's half, run after the frame is read and
// before any dispatch side effect (§3.2). On success with auth=1 it has
// written the agent proof; on failure it returns a *RefusedError and the
// caller closes the conn.
//
// Deadlines are set and cleared here, for the same reason AwaitAgentProof
// clears its own: dispatch — above all pool.park — must see a deadline-free
// conn, or the dial pool's watchdog fires the instant it arms.
func ServerHandshake(c net.Conn, sec *Secret, frame [FrameLen]byte, timeout time.Duration) error {
	auth := frame[1]
	switch {
	case sec == nil && auth == AuthNone:
		return nil // both sides unconfigured: today's wire (§6 row 5)
	case sec == nil:
		return refuse(CauseNoLocalSecret, nil) // row 3
	case auth == AuthNone:
		return refuse(CausePeerUnauthenticated, nil) // row 1
	}
	if timeout <= 0 {
		timeout = HandshakeTimeout
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err == nil {
		defer c.SetDeadline(time.Time{})
	}
	var got [ProofLen]byte
	if _, err := io.ReadFull(c, got[:]); err != nil {
		return refuse(CauseIncomplete, err)
	}
	if !Verify(sec.MacProof(frame), got[:]) {
		return refuse(CauseProofMismatch, nil) // row 2
	}
	p := sec.AgentProof(frame)
	if _, err := c.Write(p[:]); err != nil {
		return refuse(CauseIncomplete, err)
	}
	return nil
}
