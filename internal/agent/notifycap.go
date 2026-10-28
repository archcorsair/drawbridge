// Supervised-fd bookkeeping for the bind supervisor (notify.go). Deliberately
// untagged so the arithmetic is tested on the Mac.

package agent

import (
	"sync"
	"sync/atomic"
	"time"
)

// maxSupervisedNotifyFds caps how many probe-socket handoffs the agent
// supervises at once. Each supervised fd pins an OS thread in a blocking
// poll, and Go aborts the process at 10000 threads. The probe socket is
// root-only in production and widened only by -notify-sock-unprivileged
// (tests, smoke legs), so the cap is the backstop for that mode and for a
// misbehaving root sender (audit finding 4, 2026-10-28 M3). It also gates
// fd-store adoption, which must never refuse: it runs before either socket
// opens, and the unit's FileDescriptorStoreMax equals this value, so it
// cannot. Do not lower it below FileDescriptorStoreMax.
const maxSupervisedNotifyFds = 4096

// superviseCap accounts for the fds under supervision in two buckets, and
// remembers which fds those are so a probe handoff of a file that is
// already supervised can be recognised (admitProbe).
//
//   - capped (n, bounded by max): probe-socket handoffs. A refusal closes
//     the fd, which is safe there: the sender keeps its own reference, and
//     a duplicate's original stays supervised.
//   - trusted: OCI-socket handoffs and fds re-adopted from the fd store.
//     Counted for logs, never refused for capacity (decision E2). Such an
//     fd is the container's only reference to its listener: closing it
//     turns every later bind() in that container into ENOSYS for life
//     (2026-10-28 M3). The OCI socket is 0600 and reachable only by root
//     or the one -oci-sock-owner user, i.e. by the runtime, so the bucket
//     grows with real containers and `docker exec`s, not with an attacker.
type superviseCap struct {
	max     int64
	n       atomic.Int64
	trusted atomic.Int64

	mu  sync.Mutex
	fds map[int]struct{} // every fd under supervision, either bucket
}

// acquire takes one capped slot; false means the cap is reached and the
// caller must close the fd instead of parking it.
func (c *superviseCap) acquire() bool {
	if c.n.Add(1) > c.max {
		c.n.Add(-1)
		return false
	}
	return true
}

func (c *superviseCap) release() { c.n.Add(-1) }

// inUse is the capped bucket's current count (tests, logs).
func (c *superviseCap) inUse() int64 { return c.n.Load() }

// acquireTrusted takes one trusted slot. It never refuses; it returns the
// bucket's new count for the log line.
func (c *superviseCap) acquireTrusted() int64 { return c.trusted.Add(1) }

func (c *superviseCap) releaseTrusted() { c.trusted.Add(-1) }

// trustedInUse is the trusted bucket's current count (tests, logs).
func (c *superviseCap) trustedInUse() int64 { return c.trusted.Load() }

// track records fd as under supervision.
func (c *superviseCap) track(fd int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trackLocked(fd)
}

func (c *superviseCap) trackLocked(fd int) {
	if c.fds == nil {
		c.fds = map[int]struct{}{}
	}
	c.fds[fd] = struct{}{}
}

// untrack forgets fd. It must run before fd is closed: once the number is
// free the kernel can hand it to the next handoff, and comparing that
// handoff against a stale entry with the same number would call it a
// duplicate of itself.
func (c *superviseCap) untrack(fd int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.fds, fd)
}

// tracked is how many fds are under supervision, either bucket (tests).
func (c *superviseCap) tracked() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.fds)
}

// admitVerdict is admitProbe's answer.
type admitVerdict int

const (
	admitted admitVerdict = iota
	admitDuplicate
	admitFull
)

// admitProbe decides a probe-socket handoff. A file already under
// supervision is a duplicate: every handoff of one listener arrives as a
// new fd number, so without this one process holding one listener could
// take every slot (2026-10-28 NEW-2), and two supervisors on one listener
// race for each notification, the loser blocking in NOTIF_RECV, which
// never returns once the filter dies. same compares two fds of this
// process by open file (kcmp(KCMP_FILE) on Linux; an inode compare cannot
// work, every seccomp listener shares one anon inode). Otherwise a capped
// slot is taken and fd tracked. The check and the insert happen under one
// lock, so two concurrent handoffs of one file cannot both be admitted.
func (c *superviseCap) admitProbe(fd int, same func(a, b int) bool) admitVerdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	for t := range c.fds {
		if same(fd, t) {
			return admitDuplicate
		}
	}
	if !c.acquire() {
		return admitFull
	}
	c.trackLocked(fd)
	return admitted
}

// admitTrusted takes a trusted slot and tracks fd; it never refuses.
// Returns the trusted bucket's new count.
func (c *superviseCap) admitTrusted(fd int) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trackLocked(fd)
	return c.acquireTrusted()
}

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
