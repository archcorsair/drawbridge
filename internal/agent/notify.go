//go:build linux

package agent

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/acceptloop"
	"github.com/archcorsair/drawbridge/internal/seccomp"
)

// Phase 4: bind supervision. Hooked processes (bindprobe today, the OCI
// hook later) send their seccomp notify fd over this unix socket; each
// blocked bind() is answered synchronously — EADDRINUSE when the Mac side
// reports the port taken, CONTINUE otherwise. Every uncertain path answers
// CONTINUE: degradation is async mirroring, never a broken bind.

// probeHandoffTimeout bounds how long a probe-socket connection may sit
// before it delivers its fd (2026-10-28 L14). A sender writes as soon as
// it has connected (RunBindProbe installs its filter in between, which
// takes microseconds), so anything slower is an idle or stalled conn that
// would otherwise hold an agent fd and goroutine for as long as it likes.
// A var for tests.
var probeHandoffTimeout = 2 * time.Second

// ServeNotify accepts notify-fd handoffs until the listener closes.
func (a *Agent) ServeNotify(ln *net.UnixListener) {
	acceptloop.Serve(ln.AcceptUnix, func(c *net.UnixConn) { go a.recvNotifyFd(c) }, notifyLogf)
}

func notifyLogf(format string, args ...any) { log.Printf("notify: "+format, args...) }

func (a *Agent) recvNotifyFd(c *net.UnixConn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(probeHandoffTimeout))
	buf := make([]byte, 1)
	oob := make([]byte, 1024)
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		// Throttled like a refusal: idle conns timing out are exactly
		// what a sender flooding the socket produces.
		if from := peerOf(c); a.refusals.allow(from.uid, time.Now()) {
			log.Printf("notify: read fd message from %s: %v", from, err)
		}
		return
	}
	// Every control message, every fd: the first is the handoff, the rest
	// are closed rather than leaked (audit finding 4).
	fds := parseRights(oob[:oobn])
	if len(fds) == 0 {
		log.Printf("notify: no fd in handoff message (%d oob bytes)", oobn)
		return
	}
	for _, extra := range fds[1:] {
		unix.Close(extra)
	}
	// The sender blocks in bind() as soon as it has handed the fd over, so
	// supervision must outlive this connection.
	a.acceptProbeFd(fds[0], peerOf(c))
}

// peerCred identifies a handoff's sender for refusal logs and their
// throttle. ok is false when SO_PEERCRED could not be read.
type peerCred struct {
	pid, uid uint32
	ok       bool
}

func (p peerCred) String() string {
	if !p.ok {
		return "unknown peer"
	}
	return fmt.Sprintf("pid=%d uid=%d", p.pid, p.uid)
}

func peerOf(c *net.UnixConn) peerCred {
	rc, err := c.SyscallConn()
	if err != nil {
		return peerCred{}
	}
	var out peerCred
	rc.Control(func(fd uintptr) {
		if cr, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			out = peerCred{pid: uint32(cr.Pid), uid: cr.Uid, ok: true}
		}
	})
	return out
}

// refusalLogEvery throttles refusal lines per sender uid.
const refusalLogEvery = 10 * time.Second

// refuse closes a handoff's fd and logs why, once per sender uid per
// refusalLogEvery.
func (a *Agent) refuse(fd int, from peerCred, via, why string) {
	unix.Close(fd)
	if a.refusals.allow(from.uid, time.Now()) {
		log.Printf("notify: refused fd from %s via %s: %s", from, via, why)
	}
}

// acceptProbeFd takes ownership of a probe-socket fd: a seccomp listener
// that is not already supervised goes under supervision (and into the fd
// store) while a capped slot is free; anything else is closed. A pipe read
// end parked in a blocking poll would pin an OS thread forever, so the
// gate is "prove it is a listener" rather than "trust the framing" (audit
// finding 4). Closing here never costs a container its listener: the
// sender keeps its own reference, and a duplicate's original stays
// supervised.
func (a *Agent) acceptProbeFd(fd int, from peerCred) bool {
	const via = "probe socket"
	if !seccomp.IsListener(fd) {
		a.refuse(fd, from, via, "not a seccomp notify listener")
		return false
	}
	switch a.cap.admitProbe(fd, sameOpenFile) {
	case admitDuplicate:
		a.refuse(fd, from, via, "that listener is already under supervision (same open file)")
		return false
	case admitFull:
		a.refuse(fd, from, via, fmt.Sprintf("%d probe-socket fds already under supervision", maxSupervisedNotifyFds))
		return false
	}
	go a.superviseNew(fd, a.cap.release)
	return true
}

// acceptOCIFd takes ownership of an OCI-socket fd. A non-listener is
// closed: the socket is 0600, but the gate costs nothing and a parked pipe
// would pin a thread. A listener is always supervised. It is the
// container's only reference, so refusing it for capacity would turn the
// container's bind() into ENOSYS for life (2026-10-28 M3, decision E2).
// Returns the trusted bucket's count, 0 when the fd was refused.
func (a *Agent) acceptOCIFd(fd int, from peerCred, via string) int64 {
	if !seccomp.IsListener(fd) {
		a.refuse(fd, from, via, "not a seccomp notify listener")
		return 0
	}
	n := a.cap.admitTrusted(fd)
	go a.superviseNew(fd, a.cap.releaseTrusted)
	return n
}

// superviseNew parks a freshly handed-over fd in the fd store (when there
// is one) and supervises it. Takes ownership of fd and of the slot.
func (a *Agent) superviseNew(fd int, release func()) {
	a.supervise(fd, a.store.add(fd), release)
}

// superviseStored supervises an fd re-adopted from the fd store under
// name. AdoptStoredFds took a capped slot for it; adopted fds are this
// agent's own and any of them may be a container's only listener, so the
// slot is traded for a trusted one before supervision starts.
func (a *Agent) superviseStored(fd int, name string) {
	a.cap.release()
	a.cap.admitTrusted(fd)
	a.supervise(fd, name, a.cap.releaseTrusted)
}

// supervise runs fd's supervisor until its filter dies, then untracks and
// closes fd, drops it from the store (name is "" when it is not stored),
// and gives back the caller's slot through release. Takes ownership of fd
// and of the slot; fd must already be tracked.
func (a *Agent) supervise(fd int, name string, release func()) {
	defer release()
	defer a.store.remove(name)
	defer func() {
		a.cap.untrack(fd) // before the close: see untrack
		unix.Close(fd)
	}()
	a.runSupervision(fd)
}

// kcmpFile is KCMP_FILE from linux/kcmp.h; x/sys/unix does not export it.
const kcmpFile = 0

var (
	kcmpUnavailable     atomic.Bool
	kcmpUnavailableOnce sync.Once
)

// sameOpenFile reports whether fds a and b of this process refer to the
// same open file description, by kcmp(2) with KCMP_FILE. It needs
// CONFIG_KCMP, which Ubuntu's kernels ship. Where kcmp is missing or
// forbidden (ENOSYS, EPERM) the duplicate check is off for the life of the
// process, logged once, and the cap alone bounds the probe socket: a
// degrade, never a refused handoff.
func sameOpenFile(a, b int) bool {
	if kcmpUnavailable.Load() {
		return false
	}
	pid := uintptr(os.Getpid())
	r, _, errno := unix.Syscall6(unix.SYS_KCMP, pid, pid, kcmpFile, uintptr(a), uintptr(b), 0)
	if errno != 0 {
		if errno == unix.ENOSYS || errno == unix.EPERM {
			kcmpUnavailable.Store(true)
			kcmpUnavailableOnce.Do(func() {
				log.Printf("notify: kcmp(KCMP_FILE): %v; probe-socket duplicate check disabled, the cap alone bounds it", errno)
			})
		}
		return false
	}
	return r == 0
}

// runSupervision answers fd's notifications until its filter dies. The
// caller closes fd.
func (a *Agent) runSupervision(fd int) {
	// Poll-first, never bare Recv: NOTIF_RECV blocks forever once the
	// filter's last task exits (kernel gives no error — pinned by
	// TestNotifyFilterExitSemantics), so recv-looping would leak an OS
	// thread and the fd per exited container. HUP without IN is the only
	// termination signal there is.
	for {
		in, hup, err := seccomp.PollNotif(fd)
		if err != nil {
			log.Printf("notify: poll: %v", err)
			return
		}
		if !in {
			if hup {
				return
			}
			continue
		}
		nf, err := seccomp.Recv(fd)
		if err != nil {
			// ENOENT: the blocked task was signalled away between poll
			// and recv. If it was the last one, the next poll says HUP.
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			log.Printf("notify: recv: %v", err)
			return
		}
		a.answerBind(fd, nf)
	}
}

var (
	v4LoopbackA = netip.MustParseAddr("127.0.0.1")
	v4AnyA      = netip.MustParseAddr("0.0.0.0")
	v6AnyA      = netip.MustParseAddr("::")
	v6LoopbackA = netip.MustParseAddr("::1")
)

func (a *Agent) answerBind(fd int, nf seccomp.Notif) {
	cont := func() {
		if err := seccomp.SendContinue(fd, nf.ID); err != nil {
			log.Printf("notify: continue id=%d: %v", nf.ID, err)
		}
	}
	// Only bind is ours to judge. The wrapper never installs a filter that
	// notifies on anything else, but a notify fd can reach this socket from
	// elsewhere; reading a foreign syscall's args as a sockaddr and then
	// possibly answering EADDRINUSE would turn someone else's policy into
	// ours (audit finding 5). CONTINUE, without touching target memory.
	// The check is per ABI (seccomp_data.arch), not against the native
	// number alone: a 32-bit container binds through the compat table with
	// a different nr and the same (fd, sockaddr*, len) args, and must keep
	// its synchronous EADDRINUSE.
	if !seccomp.IsBind(nf.Arch, nf.Nr) {
		a.foreignNrOnce.Do(func() {
			log.Printf("notify: notification for syscall %d under arch %#x (not bind) pid=%d: answering CONTINUE; this filter is not drawbridge's (logged once)",
				nf.Nr, nf.Arch, nf.PID)
		})
		cont()
		return
	}
	ba, err := seccomp.ReadBindAddr(nf.PID, nf.Args[1], nf.Args[2])
	if err != nil {
		log.Printf("notify: read sockaddr pid=%d: %v", nf.PID, err)
		cont()
		return
	}
	if ba.Family != unix.AF_INET && ba.Family != unix.AF_INET6 {
		cont()
		return
	}
	// Ephemeral binds can't be pre-reserved (port unknown until bound), and
	// non-mirrorable scopes never reach the Mac.
	mirrorable := ba.Addr == v4LoopbackA || ba.Addr == v4AnyA || ba.Addr == v6AnyA || ba.Addr == v6LoopbackA
	if ba.Port == 0 || !mirrorable {
		cont()
		return
	}
	// OCI backstop: only binds from the agent's own (host) netns are
	// arbitrated — a bridged container's bind must never reach the Mac,
	// no matter what fed its notify fd to this socket. Foreign or
	// unreadable netns ⇒ CONTINUE.
	same, err := seccomp.SameNetNS(nf.PID)
	if err != nil {
		log.Printf("notify: netns pid=%d: %v", nf.PID, err)
	}
	if err != nil || !same {
		cont()
		return
	}
	stream, err := seccomp.IsInetStream(nf.PID, nf.Args[0])
	if err != nil {
		log.Printf("notify: classify socket pid=%d fd=%d: %v", nf.PID, nf.Args[0], err)
	}
	if err != nil || !stream {
		cont()
		return
	}
	// The sockaddr came from target memory: only act on it if the syscall
	// is still blocked (the target hasn't been signalled away).
	if !seccomp.IDValid(fd, nf.ID) {
		return
	}
	verdict := a.ReservePort("tcp", ba.Port, ba.Addr.String())
	log.Printf("notify: bind %s:%d pid=%d -> %s", ba.Addr, ba.Port, nf.PID, verdict)
	if verdict == "inuse" {
		if err := seccomp.SendErrno(fd, nf.ID, unix.EADDRINUSE); err != nil {
			log.Printf("notify: errno id=%d: %v", nf.ID, err)
		}
		return
	}
	cont() // "ok" (reserved, bind proceeds) or "unknown" (degrade)
}
