// Supervised-fd bookkeeping for the bind supervisor (notify.go). Deliberately
// untagged so the arithmetic is tested on the Mac.

package agent

import (
	"sync"
	"sync/atomic"
	"time"
)

// maxSupervisedNotifyFds caps how many seccomp notify fds the agent parks at
// once. Each pins an OS thread in a blocking poll, and Go aborts the
// process at 10000 threads; the notify socket is 0666, so the cap is what
// turns "any guest process can crash the agent" into one refused handoff
// (audit finding 4). 4096 leaves room for every realistic container and
// `docker exec` count on one developer VM.
const maxSupervisedNotifyFds = 4096

// superviseCap counts fds under supervision.
type superviseCap struct {
	max int64
	n   atomic.Int64
}

// acquire takes one slot; false means the cap is reached and the caller
// must close the fd instead of parking it.
func (c *superviseCap) acquire() bool {
	if c.n.Add(1) > c.max {
		c.n.Add(-1)
		return false
	}
	return true
}

func (c *superviseCap) release() { c.n.Add(-1) }

// inUse is the current count (tests, logs).
func (c *superviseCap) inUse() int64 { return c.n.Load() }

// peerLimiter rate-limits refusal log lines per sender uid: whoever feeds
// the socket junk must not be able to fill the journal with it.
type peerLimiter struct {
	mu    sync.Mutex
	every time.Duration
	last  map[uint32]time.Time
}

func newPeerLimiter(every time.Duration) *peerLimiter {
	return &peerLimiter{every: every, last: map[uint32]time.Time{}}
}

func (l *peerLimiter) allow(uid uint32, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[uid]; ok && now.Sub(t) < l.every {
		return false
	}
	if len(l.last) > 1024 {
		for k, t := range l.last {
			if now.Sub(t) >= l.every {
				delete(l.last, k)
			}
		}
	}
	l.last[uid] = now
	return true
}
