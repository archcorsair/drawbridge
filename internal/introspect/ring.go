package introspect

import (
	"sync"
	"time"
)

// RingSize is the ring's fixed depth. Small on purpose: this is recent
// evidence for a diagnostic, not a log.
const RingSize = 32

// Ring is the shared refusal recorder. It is injected into mirror, macsync,
// and the transport-auth throttle as a nil-safe field, so those packages stay
// daemon-independent — a nil *Ring records nothing and a test injects its
// own. Safe for concurrent use: every refusal site is on a dial or accept
// path, and several run at once.
type Ring struct {
	now func() time.Time // test seam; nil ⇒ time.Now

	mu  sync.Mutex
	buf [RingSize]Refusal
	n   int // total recorded; the ring holds the last min(n, RingSize)
}

// Record stamps and stores one ID-tagged refusal line. A nil receiver is a
// no-op, which is what makes the field injectable rather than required.
func (r *Ring) Record(id, line string) {
	if r == nil {
		return
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.n%RingSize] = Refusal{At: now(), ID: id, Line: line}
	r.n++
}

// Snapshot returns the retained entries, oldest first.
func (r *Ring) Snapshot() []Refusal {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.n
	if n > RingSize {
		n = RingSize
	}
	out := make([]Refusal, 0, n)
	for i := r.n - n; i < r.n; i++ {
		out = append(out, r.buf[i%RingSize])
	}
	return out
}
