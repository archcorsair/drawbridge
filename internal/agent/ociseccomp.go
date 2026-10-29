//go:build linux

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/archcorsair/drawbridge/internal/acceptloop"
)

// OCI seccomp-agent listener (docs/oci-hook.md, Phase A). Any OCI runtime
// configured with linux.seccomp.listenerPath pointing here (runc >= 1.1.0,
// crun) installs the bind filter in the container init itself and delivers
// the notify fd in runtime-spec framing: one ContainerProcessState JSON per
// connection, fds attached to the first sendmsg, sender closes after
// transmission (the spec says so; runc before 1.3.3 does not, see
// readOCIState) — and a send failure is a container-start failure, so this
// listener must be up before the wrapper injects listenerPath. The probe
// socket's 1-byte protocol (notify.go) is deliberately untouched; two
// sockets, two parsers, one shared supervisor core. Unlike the probe
// socket's, an fd handed over here is never refused for capacity
// (acceptOCIFd).

// ociProcessState is the runtime-spec ContainerProcessState payload.
type ociProcessState struct {
	OCIVersion string   `json:"ociVersion"`
	Fds        []string `json:"fds"`
	Pid        int      `json:"pid"`
	Metadata   string   `json:"metadata,omitempty"`
	State      struct {
		ID          string            `json:"id"`
		Status      string            `json:"status"`
		Pid         int               `json:"pid"`
		Bundle      string            `json:"bundle"`
		Annotations map[string]string `json:"annotations,omitempty"`
	} `json:"state"`
}

// seccompFdName is the spec-defined entry in Fds naming the notify fd's
// position in the SCM_RIGHTS array.
const seccompFdName = "seccompFd"

// ociHandoffTimeout bounds a whole OCI handoff: the first message and any
// continuation of its JSON. The runtime writes the state in one sendmsg
// right after it connects (runc's sendContainerProcessState, crun's
// send_fd_to_socket_with_payload), so the deadline only fires on a
// stalled sender. It is generous on purpose: missing it costs that
// container its arbitration. A var for tests.
var ociHandoffTimeout = 10 * time.Second

// ociStateMax bounds the ContainerProcessState JSON. A docker container's
// state is a few KiB, annotations being the only part that grows; 1 MiB
// is far past any real one and still a bounded allocation.
const ociStateMax = 1 << 20

// ociReadChunk is the first read's data buffer and every later read's.
const ociReadChunk = 64 << 10

// ServeOCISeccomp accepts seccomp-agent handoffs until the listener closes.
func (a *Agent) ServeOCISeccomp(ln *net.UnixListener) {
	acceptloop.Serve(ln.AcceptUnix, func(c *net.UnixConn) { go a.recvOCIState(c) }, ociLogf)
}

func ociLogf(format string, args ...any) { log.Printf("oci: "+format, args...) }

func (a *Agent) recvOCIState(c *net.UnixConn) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(ociHandoffTimeout))
	st, fds, err := readOCIState(c)
	if err != nil {
		// Bare EOF is the wrapper's liveness probe (dial+close), not a
		// malformed handoff — stay quiet.
		if err != io.EOF {
			log.Printf("oci: %v", err)
		}
		return
	}
	idx := slices.Index(st.Fds, seccompFdName)
	if idx < 0 || idx >= len(fds) {
		log.Printf("oci: no %q among fds %v (%d rights)", seccompFdName, st.Fds, len(fds))
		closeFds(fds)
		return
	}
	for i, fd := range fds {
		if i != idx {
			unix.Close(fd)
		}
	}
	n := a.acceptOCIFd(fds[idx], peerOf(c), "oci socket, container "+st.State.ID)
	if n == 0 {
		return
	}
	log.Printf("oci: supervising container %s (init pid %d, metadata %q; %d OCI/adopted fds under supervision)",
		st.State.ID, st.Pid, st.Metadata, n)
}

// readOCIState reads one handoff: the first message, which carries the
// fds, then more bytes only while the JSON is incomplete, up to
// ociStateMax. It never waits for EOF. runc up to 1.3.2 never closes its
// dialed conn (only the dup it took with conn.File()), so draining to EOF
// held a container's binds until runc exited (2026-10-28 NEW-1); the
// conn's read deadline bounds the rest. A first read that ends the conn
// returns io.EOF unwrapped. On any other error every received fd has been
// closed: malformed input closes everything and touches nothing, so the
// worst case is one container without arbitration, and stock containers
// are unaffected.
func readOCIState(c *net.UnixConn) (ociProcessState, []int, error) {
	buf := make([]byte, ociReadChunk)
	oob := make([]byte, 1024)
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err == nil && n == 0 && oobn == 0 {
		err = io.EOF
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ociProcessState{}, nil, io.EOF
		}
		return ociProcessState{}, nil, fmt.Errorf("read state: %w", err)
	}
	fds := parseRights(oob[:oobn])
	fail := func(err error) (ociProcessState, []int, error) {
		closeFds(fds)
		return ociProcessState{}, nil, err
	}
	if len(fds) == 0 {
		return fail(fmt.Errorf("no fds in first message (%d data bytes)", n))
	}
	// The JSON may span writes; rights only ride the first.
	data := append([]byte(nil), buf[:n]...)
	for {
		var st ociProcessState
		err := json.NewDecoder(bytes.NewReader(data)).Decode(&st)
		if err == nil {
			return st, fds, nil
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			return fail(fmt.Errorf("bad ContainerProcessState (%d bytes): %w", len(data), err))
		}
		if len(data) >= ociStateMax {
			return fail(fmt.Errorf("ContainerProcessState incomplete at the %d-byte limit", ociStateMax))
		}
		m, rerr := c.Read(buf[:min(len(buf), ociStateMax-len(data))])
		data = append(data, buf[:m]...)
		if m == 0 && rerr != nil {
			return fail(fmt.Errorf("ContainerProcessState incomplete after %d bytes: %w", len(data), rerr))
		}
	}
}

func closeFds(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

func parseRights(oob []byte) []int {
	scms, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var fds []int
	for i := range scms {
		if f, err := unix.ParseUnixRights(&scms[i]); err == nil {
			fds = append(fds, f...)
		}
	}
	return fds
}
