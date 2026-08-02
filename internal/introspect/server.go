package introspect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// WriteTimeout bounds one snapshot write. A consumer that connects and never
// reads must not pin a slot forever; 2s is generous for a payload measured in
// kilobytes over a unix socket.
const WriteTimeout = 2 * time.Second

// maxInFlight caps concurrent snapshot writes. The accept loop takes a slot
// before it accepts, so excess connections wait in the listen backlog rather
// than fanning out goroutines — a read-only diagnostic endpoint has no reason
// to grow unbounded under a connect storm.
const maxInFlight = 8

// staffGroup owns the root socket (D3): every macOS console user is in
// staff, other-uid service accounts are not.
const staffGroup = "staff"

// Server serves State snapshots on a unix socket. It never reads from an
// accepted connection — see the package comment; that property is the reason
// this listener is safe to run as root, and it is pinned by a test.
type Server struct {
	// Note is a non-fatal startup remark for the daemon to log, e.g. that the
	// socket could not be handed to the staff group and stayed root-only.
	// Permission failures narrow access, never widen it, so they are reported
	// rather than fatal.
	Note string

	// WriteTimeout overrides the default per-connection write budget. Test
	// seam: a consumer that connects and never reads is otherwise a
	// WriteTimeout-long test. Set it before Serve.
	WriteTimeout time.Duration

	path     string
	snapshot func() State
	ln       *net.UnixListener

	closeOnce sync.Once
}

// Listen unlinks any stale socket at path, binds it, and applies the D3
// permissions for euid: root gets 0755 root:wheel dir + 0660 root:staff
// socket, anyone else gets a 0700 dir + 0600 socket. The path is explicit —
// derivation lives in paths.go — so tests bind inside t.TempDir().
func Listen(path string, euid int, snapshot func() State) (*Server, error) {
	if snapshot == nil {
		return nil, errors.New("introspect: nil snapshot function")
	}
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	dirMode, sockMode := os.FileMode(0o700), os.FileMode(0o600)
	if euid == 0 {
		dirMode, sockMode = 0o755, 0o660
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	// MkdirAll respects umask and leaves an existing directory alone, so the
	// mode is asserted rather than assumed.
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	// A crashed daemon leaves the socket file behind; connecting to it gets
	// ECONNREFUSED, which consumers read as absent. Binding needs it gone.
	if err := removeStale(path); err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	s := &Server{path: path, snapshot: snapshot, ln: ln}
	// Between bind and chmod the socket carries umask permissions. Nothing is
	// served in that window — Serve has not started — but a connection could
	// be queued in the backlog, so the mode is tightened immediately and
	// before the caller can start accepting.
	if err := os.Chmod(path, sockMode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("introspect: %w", err)
	}
	if euid == 0 {
		if err := os.Chown(dir, 0, 0); err != nil {
			s.Note = fmt.Sprintf("could not set %s to root:wheel: %v", dir, err)
		}
		if gid, err := groupID(staffGroup); err != nil {
			s.Note = fmt.Sprintf("no %q group on this system (%v) — %s stays root-owned, so unprivileged `drawbridge doctor` cannot read it", staffGroup, err, path)
		} else if err := os.Chown(path, 0, gid); err != nil {
			s.Note = fmt.Sprintf("could not give %s to group %s (%v) — it stays root-only", path, staffGroup, err)
		}
	}
	return s, nil
}

// Path is the bound socket path.
func (s *Server) Path() string { return s.path }

// Serve accepts until Close. One connection is one snapshot: marshal, write
// with a deadline, close. Errors are per-connection and never stop the loop —
// this endpoint is an enrichment tier, and a consumer that hangs up mid-write
// must not take it down.
func (s *Server) Serve() {
	sem := make(chan struct{}, maxInFlight)
	for {
		sem <- struct{}{}
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			<-sem
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go func() {
			defer func() { <-sem }()
			s.write(conn)
		}()
	}
}

// write emits one snapshot. It deliberately contains no Read: the protocol is
// write-only, and whatever the client sends is discarded unread by the kernel
// when the conn closes.
func (s *Server) write(conn *net.UnixConn) {
	defer conn.Close()
	b, err := json.Marshal(s.snapshot())
	if err != nil {
		return
	}
	timeout := s.WriteTimeout
	if timeout <= 0 {
		timeout = WriteTimeout
	}
	conn.SetWriteDeadline(time.Now().Add(timeout))
	conn.Write(append(b, '\n'))
}

// Close stops the listener and removes the socket file.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.ln.Close() })
	return err
}

// removeStale deletes an existing socket file, refusing to unlink anything
// that is not one: `-introspect /etc/passwd` must fail, not delete.
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("introspect: %w", err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("introspect: %s exists and is not a socket (mode %s) — refusing to replace it", path, fi.Mode())
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("introspect: %w", err)
	}
	return nil
}

func groupID(name string) (int, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
