//go:build linux

package agent

import (
	"errors"
	"log"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/seccomp"
)

// Phase 4: bind supervision. Hooked processes (bindprobe today, the OCI
// hook later) send their seccomp notify fd over this unix socket; each
// blocked bind() is answered synchronously — EADDRINUSE when the Mac side
// reports the port taken, CONTINUE otherwise. Every uncertain path answers
// CONTINUE: degradation is async mirroring, never a broken bind.

// ServeNotify accepts notify-fd handoffs until the listener closes.
func (a *Agent) ServeNotify(ln *net.UnixListener) {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		go a.recvNotifyFd(c)
	}
}

func (a *Agent) recvNotifyFd(c *net.UnixConn) {
	defer c.Close()
	buf := make([]byte, 1)
	oob := make([]byte, 64)
	_, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		log.Printf("notify: read fd message: %v", err)
		return
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(scms) == 0 {
		log.Printf("notify: parse control message (%d bytes): %v", oobn, err)
		return
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil || len(fds) == 0 {
		log.Printf("notify: parse rights: %v", err)
		return
	}
	// The sender blocks in bind() as soon as it has handed the fd over, so
	// supervision must outlive this connection.
	go a.superviseNotify(fds[0])
}

func (a *Agent) superviseNotify(fd int) {
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
