//go:build linux

package agent

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
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

// ServeNotify accepts notify-fd handoffs until the listener closes.
func (a *Agent) ServeNotify(ln *net.UnixListener) {
	acceptloop.Serve(ln.AcceptUnix, func(c *net.UnixConn) { go a.recvNotifyFd(c) }, notifyLogf)
}

func notifyLogf(format string, args ...any) { log.Printf("notify: "+format, args...) }

func (a *Agent) recvNotifyFd(c *net.UnixConn) {
	defer c.Close()
	buf := make([]byte, 1)
	oob := make([]byte, 1024)
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		log.Printf("notify: read fd message: %v", err)
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
	a.acceptNotifyFd(fds[0], peerOf(c), "probe socket")
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

// acceptNotifyFd takes ownership of fd: a real seccomp listener goes under
// supervision (and into the fd store); anything else is closed. The socket
// is 0666 and a pipe read end parked in a blocking poll would pin an OS
// thread forever, so the gate is "prove it is a listener" rather than
// "trust the framing", and the cap bounds the thread count whatever the
// sender does (audit finding 4). Refusals are logged once per sender per
// refusalLogEvery.
func (a *Agent) acceptNotifyFd(fd int, from peerCred, via string) bool {
	refuse := func(why string) {
		unix.Close(fd)
		if a.refusals.allow(from.uid, time.Now()) {
			log.Printf("notify: refused fd from %s via %s: %s", from, via, why)
		}
	}
	if !seccomp.IsListener(fd) {
		refuse("not a seccomp notify listener")
		return false
	}
	if !a.cap.acquire() {
		refuse(fmt.Sprintf("%d fds already under supervision", maxSupervisedNotifyFds))
		return false
	}
	go a.superviseNotify(fd)
	return true
}

// superviseNotify parks fd in the fd store (when there is one) and
// supervises it until its filter dies. Takes ownership of fd and of the
// cap slot the caller acquired.
func (a *Agent) superviseNotify(fd int) {
	a.superviseStored(fd, a.store.add(fd))
}

// superviseStored supervises an fd already stored under name ("" when it
// is not stored), drops it from the store when supervision ends, and
// returns the caller's cap slot.
func (a *Agent) superviseStored(fd int, name string) {
	defer a.cap.release()
	defer a.store.remove(name)
	a.runSupervision(fd)
}

func (a *Agent) runSupervision(fd int) {
	defer unix.Close(fd)
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
