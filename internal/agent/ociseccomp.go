//go:build linux

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"slices"

	"golang.org/x/sys/unix"
)

// OCI seccomp-agent listener (docs/oci-hook.md, Phase A). Any OCI runtime
// configured with linux.seccomp.listenerPath pointing here (runc >= 1.1.0,
// crun) installs the bind filter in the container init itself and delivers
// the notify fd in runtime-spec framing: one ContainerProcessState JSON per
// connection, fds attached to the first sendmsg, sender closes after
// transmission — and a send failure is a container-start failure, so this
// listener must be up before the wrapper injects listenerPath. The probe
// socket's 1-byte protocol (notify.go) is deliberately untouched; two
// sockets, two parsers, one shared supervisor core.

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

// ServeOCISeccomp accepts seccomp-agent handoffs until the listener closes.
func (a *Agent) ServeOCISeccomp(ln *net.UnixListener) {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		go a.recvOCIState(c)
	}
}

func (a *Agent) recvOCIState(c *net.UnixConn) {
	defer c.Close()
	buf := make([]byte, 64<<10)
	oob := make([]byte, 1024)
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		// Bare EOF is the wrapper's liveness probe (dial+close), not a
		// malformed handoff — stay quiet.
		if !errors.Is(err, io.EOF) {
			log.Printf("oci: read state: %v", err)
		}
		return
	}
	fds := parseRights(oob[:oobn])
	// Malformed input closes everything and touches nothing: worst case is
	// that one container's start erroring; stock containers are unaffected.
	closeAll := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	if len(fds) == 0 {
		log.Printf("oci: no fds in first message (%d data bytes)", n)
		return
	}
	// The JSON may span writes; rights only ride the first.
	data := buf[:n]
	if rest, err := io.ReadAll(c); err == nil && len(rest) > 0 {
		data = append(data, rest...)
	}
	var st ociProcessState
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&st); err != nil {
		log.Printf("oci: bad ContainerProcessState (%d bytes): %v", len(data), err)
		closeAll()
		return
	}
	idx := slices.Index(st.Fds, seccompFdName)
	if idx < 0 || idx >= len(fds) {
		log.Printf("oci: no %q among fds %v (%d rights)", seccompFdName, st.Fds, len(fds))
		closeAll()
		return
	}
	for i, fd := range fds {
		if i != idx {
			unix.Close(fd)
		}
	}
	log.Printf("oci: supervising container %s (init pid %d, metadata %q)",
		st.State.ID, st.Pid, st.Metadata)
	go a.superviseNotify(fds[idx])
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
