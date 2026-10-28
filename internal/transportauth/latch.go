package transportauth

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
)

// configured is the process's sticky record of which secret paths are
// configured (§5): a path enters it on an explicit -secret-file (Require) or
// the first time LoadLatched finds a file there, well-formed or not, and
// never leaves. From then on, the file's absence is a refusal
// (ErrConfiguredMissing), never a fall back to unauthenticated mode. Restarting the process is the only way back to
// unauthenticated mode, which is the point: a running side does not drop
// authentication because a file disappeared under it.
//
// It is process-wide and keyed by path, on purpose. "Configured" is a fact
// about this process, not about a value: MacConfig is copied into the mirror
// client, the syncer and doctor's probe, often before any of them has
// dialed, so a latch carried inside the value could be lost by any copy made
// before the first load. A path key cannot be lost that way, and it only
// ever moves one direction (unset → set), so concurrent dials and accepts
// need nothing beyond sync.Map's own ordering: a load that observed the
// file stores the key before it returns the secret, so any read that starts
// after it sees the latch.
var configured sync.Map // filepath.Clean(path) → struct{}

func latchKey(path string) string { return filepath.Clean(path) }

// Require latches path as configured for this process before any read: an
// explicit -secret-file states intent (§5), so a file that is absent now,
// or later, is a refusal rather than unauthenticated mode. An empty path is
// a no-op.
func Require(path string) {
	if path == "" {
		return
	}
	configured.Store(latchKey(path), struct{}{})
}

// Configured reports whether path is latched for this process.
func Configured(path string) bool {
	if path == "" {
		return false
	}
	_, ok := configured.Load(latchKey(path))
	return ok
}

// LoadLatched is the runtime read both sides do per dial or accept: Load,
// with "absent" meaning unauthenticated mode only while this process has
// never seen a file at path.
//
//   - present and well-formed: the secret; path is latched from now on.
//   - present but malformed or unreadable: ErrMalformed, a refusal as
//     before, and path is latched too. A file that exists is evidence a
//     secret was configured, so a malformed file that is later deleted
//     must not drop the process back to unauthenticated mode.
//   - absent, never latched: (nil, nil), today's unauthenticated mode
//     (the dev flow and audit #26, unchanged).
//   - absent, latched: ErrConfiguredMissing. The caller refuses with
//     CauseSecretUnreadable; it must never send or accept auth=0.
//
// Rotation keeps healing live: a file replaced with a new valid secret is
// simply read on the next call. Only the bytes come from the file; the
// latch never holds or exposes them.
func LoadLatched(path string) (*Secret, error) {
	if path == "" {
		return nil, nil
	}
	s, err := Load(path)
	if errors.Is(err, ErrAbsent) {
		if Configured(path) {
			return nil, fmt.Errorf("%s: %w", path, ErrConfiguredMissing)
		}
		return nil, nil
	}
	// Present, whether or not it parsed: latch before returning either
	// outcome, so any read that starts after this one sees it.
	configured.Store(latchKey(path), struct{}{})
	if err != nil {
		return nil, err
	}
	return &s, nil
}
