//go:build linux

package agent

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/fdstore"
	"github.com/archcorsair/drawbridge/internal/seccomp"
)

// notifyStore parks every supervised seccomp notify fd in systemd's fd
// store so it outlives this process (audit finding 2: the agent holds the
// only reference, and a closed listener turns the container's bind() into
// ENOSYS for good). Names are unique per fd — `notify-<nonce>-<seq>`, the
// nonce taken from this process's start time so a restarted agent's
// counter cannot collide with names it inherited — because FDSTOREREMOVE
// drops every fd of a name.
//
// systemd dups what it stores and watches the copies for POLLHUP, so a
// container whose last task exits is dropped from the store by systemd
// itself; the explicit remove on supervision exit covers every other way a
// supervisor returns. Without a NOTIFY_SOCKET (foreground run, a transient
// unit without FileDescriptorStoreMax=) the store is simply absent: one log
// line at start, supervision unchanged, fds die with the process as before.
type notifyStore struct {
	sock  string
	nonce string
	seq   atomic.Uint64
	warn  sync.Once
}

func newNotifyStore() *notifyStore {
	return &notifyStore{
		sock:  os.Getenv("NOTIFY_SOCKET"),
		nonce: fmt.Sprintf("%x", time.Now().UnixNano()),
	}
}

// Available reports whether systemd offered a notification socket.
func (s *notifyStore) Available() bool { return s.sock != "" }

// add stores fd and returns its name, or "" when there is no store or the
// store refused it (logged once per process: it is a posture, not an
// event per container).
func (s *notifyStore) add(fd int) string {
	if s.sock == "" {
		return ""
	}
	name := fmt.Sprintf("%s%s-%d", fdstore.Prefix, s.nonce, s.seq.Add(1))
	msg, err := fdstore.StoreMessage(name)
	if err == nil {
		err = fdstore.Send(s.sock, msg, fd)
	}
	if err != nil {
		s.warn.Do(func() {
			log.Printf("notify: fd store unavailable (%v) — notify fds will not survive an agent restart; is FileDescriptorStoreMax= set on the unit?", err)
		})
		return ""
	}
	return name
}

func (s *notifyStore) remove(name string) {
	if name == "" || s.sock == "" {
		return
	}
	if msg, err := fdstore.RemoveMessage(name); err == nil {
		fdstore.Send(s.sock, msg)
	}
}

// FdStoreAvailable reports whether supervised notify fds are being parked
// in systemd's fd store (startup log line).
func (a *Agent) FdStoreAvailable() bool { return a.store.Available() }

// AdoptStoredFds re-adopts the notify fds a previous agent process parked
// in the fd store (LISTEN_FDS/LISTEN_FDNAMES), resuming supervision of the
// containers they belong to; their binds have been blocking on the
// listener since the old process went away and are answered as soon as
// the supervisor polls. Returns how many were adopted.
//
// Every inherited fd is closed or adopted, never leaked: a name without our
// prefix, or an fd that is not a seccomp listener, is closed and logged.
// The LISTEN_* variables are cleared afterwards so nothing this process
// execs sees them.
func (a *Agent) AdoptStoredFds() (int, error) {
	inherited, err := fdstore.ParseListenEnv(os.Getenv, os.Getpid())
	os.Unsetenv("LISTEN_PID")
	os.Unsetenv("LISTEN_FDS")
	os.Unsetenv("LISTEN_FDNAMES")
	if err != nil {
		return 0, err
	}
	adopted := 0
	for _, in := range inherited {
		switch {
		case !fdstore.IsNotifyName(in.Name):
			log.Printf("notify: inherited fd %d named %q is not a stored notify fd; closing", in.Fd, in.Name)
			unix.Close(in.Fd)
		case !seccomp.IsListener(in.Fd):
			log.Printf("notify: inherited fd %d (%s) is not a seccomp listener; closing and dropping it from the store", in.Fd, in.Name)
			unix.Close(in.Fd)
			a.store.remove(in.Name)
		case !a.cap.acquire():
			log.Printf("notify: inherited fd %d (%s): %d fds already under supervision; closing and dropping it from the store", in.Fd, in.Name, maxSupervisedNotifyFds)
			unix.Close(in.Fd)
			a.store.remove(in.Name)
		default:
			unix.CloseOnExec(in.Fd)
			adopted++
			go a.superviseStored(in.Fd, in.Name)
		}
	}
	return adopted, nil
}
