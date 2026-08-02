package introspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// DialTimeout is the consumer-side budget for one socket. Doctor must
// terminate against a wedged machine, and a unix-socket dial that has not
// completed in 250ms is not going to.
const DialTimeout = 250 * time.Millisecond

// maxPayload bounds a snapshot read. The document is kilobytes; the cap
// exists so a consumer cannot be made to buffer a garbage stream.
const maxPayload = 1 << 20

var (
	// ErrAbsent: nothing is listening — no socket file, a stale one
	// (ECONNREFUSED), or a dial that timed out. Never an error by itself;
	// introspection is an enrichment tier, so consumers fall back to
	// inference.
	ErrAbsent = errors.New("introspect: no daemon answered")
	// ErrMalformed: something answered but the payload is not a snapshot —
	// a corrupt daemon or a truncated write. Distinguishable from absent
	// because it deserves a warning line, not silence.
	ErrMalformed = errors.New("introspect: unreadable snapshot")
)

// Snapshot is one fetched payload plus the reader-side posture.
type Snapshot struct {
	// Path is the socket it came from, so a consumer can name which daemon
	// it is talking about when several answer.
	Path string
	// State is the decoded document. When Usable is false only the two
	// frozen fields — Schema and Version — mean anything (D4).
	State State
	// Usable reports whether this build understands the payload's schema.
	Usable bool
}

// Fetch dials one introspection socket and reads the single snapshot the
// daemon writes. It sends nothing: the protocol has no request, and a client
// that writes is a client whose bytes the daemon will never read.
func Fetch(path string, timeout time.Duration) (*Snapshot, error) {
	if timeout <= 0 {
		timeout = DialTimeout
	}
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrAbsent, path, err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout + WriteTimeout))
	b, err := io.ReadAll(io.LimitReader(conn, maxPayload+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrMalformed, path, err)
	}
	if len(b) > maxPayload {
		return nil, fmt.Errorf("%w: %s: over %d bytes", ErrMalformed, path, maxPayload)
	}
	snap, err := Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	snap.Path = path
	return snap, nil
}

// Decode parses one payload with the D4 posture: the two frozen fields are
// read first, and a schema this build does not know yields a Snapshot
// carrying only those — enough to report version skew, not enough to trust
// anything else.
func Decode(b []byte) (*Snapshot, error) {
	var frozen struct {
		Schema  int    `json:"schema"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &frozen); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if frozen.Schema <= 0 {
		return nil, fmt.Errorf("%w: no schema field", ErrMalformed)
	}
	if frozen.Schema > Schema {
		return &Snapshot{State: State{Schema: frozen.Schema, Version: frozen.Version}}, nil
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return &Snapshot{State: st, Usable: true}, nil
}

// FetchAll reads every socket Discover found. Both a root and a user daemon
// answering is the documented fighting-daemons posture, so this returns all
// of them and lets the consumer say so. Absent sockets are silent (they are
// the normal case); anything that answered but could not be read comes back
// as a problem, because that is a warning a consumer must print rather than
// swallow.
func FetchAll(timeout time.Duration) (snaps []*Snapshot, problems []error) {
	for _, p := range Discover() {
		snap, err := Fetch(p, timeout)
		switch {
		case err == nil:
			snaps = append(snaps, snap)
		case !errors.Is(err, ErrAbsent):
			problems = append(problems, err)
		}
	}
	return snaps, problems
}
