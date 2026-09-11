// Package podmanaddr resolves a podman machine's transport endpoint
// (docs/podman.md §3.2). It is to podman what internal/limaaddr is to Lima
// and Colima, and it is a separate package for the reason ergonomics.md §3.3
// gave: podman's resolution has nothing in common with the lease db but the
// shape of its answer.
//
// There is no probing for a better path and no fallback. A podman machine's
// only reachable transport endpoint is the loopback port gvproxy binds on the
// Mac, which `drawbridge up` chose and recorded and the guest agent
// republishes on every machine start. So resolution is: read the record, dial
// it once to see whether it is live, and say what silence means.
//
// limaaddr.Resolution is reused rather than duplicated: it is the daemon's
// and doctor's contract, and moving it to a neutral package is a rename with
// no behaviour change, deliberately deferred. Nothing inside limaaddr changes.
package podmanaddr

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
)

// Source is what a podman resolution reports. It is the direct path for this
// provider and not a fallback: there is nothing better to degrade from.
const Source = vmrecord.TransportGvproxyPublish

// probeTimeout matches limaaddr's, for the same reason: long enough for a
// listener that is there, short enough that a stopped machine does not stall
// a daemon's startup.
const probeTimeout = 800 * time.Millisecond

// Resolve reads the recorded endpoint and probes it.
//
// A resolution with an empty Endpoint is a refusal, not a fallback: the
// caller has nowhere to dial, and the Note says which of the two reasons it
// is (no record, or a record that cannot be read). Every other outcome
// returns the recorded endpoint, a machine that is merely stopped is a
// reconnect away from working, and the daemon's backoff is the right response
// to it.
func Resolve(ref vmprovider.Ref) limaaddr.Resolution {
	rec, err := vmrecord.Read(ref)
	switch {
	case errors.Is(err, vmrecord.ErrAbsent):
		return limaaddr.Resolution{
			Source: Source,
			Note: fmt.Sprintf("%v, run `drawbridge up %s` first: it chooses the Mac-side port, "+
				"records it, and installs the agent that publishes it through gvproxy", err, ref.Spec),
		}
	case err != nil:
		return limaaddr.Resolution{Source: Source, Note: err.Error()}
	}

	ep, err := transport.Parse(rec.Endpoint)
	if err != nil {
		return limaaddr.Resolution{
			Source: Source,
			Note:   fmt.Sprintf("the recorded endpoint %q is not a valid transport endpoint (%v), re-run `drawbridge up %s`", rec.Endpoint, err, ref.Spec),
		}
	}
	if ep.Scheme != transport.SchemeTCP {
		// Branch A publishes a loopback TCP port and nothing else. A record
		// naming another scheme was written by a build that knows something
		// this one does not, and guessing at it is how a daemon ends up
		// dialing a socket nobody owns.
		return limaaddr.Resolution{
			Source: Source,
			Note:   fmt.Sprintf("the recorded endpoint %s is not a tcp endpoint: this build resolves podman machines through the gvproxy publish only, re-run `drawbridge up %s`", ep, ref.Spec),
		}
	}
	addr := ep.String()

	conn, derr := net.DialTimeout("tcp", ep.Addr, probeTimeout)
	if derr == nil {
		conn.Close()
		return limaaddr.Resolution{Endpoint: addr, Source: Source}
	}
	return limaaddr.Resolution{Endpoint: addr, Source: Source, Note: classify(ref, addr, derr)}
}

// classify explains a failed probe. The two answers that matter are different
// failures of the same machine: gvproxy is not holding the port (nothing is
// forwarding, i.e. the machine is stopped or the user's session is gone), and
// gvproxy is holding it but the guest agent has not published (the forward
// exists but nothing answers behind it).
func classify(ref vmprovider.Ref, addr string, err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("nothing is listening on %s: the agent has not published its port. "+
			"Is the machine running (`podman machine list`)? Then: `podman machine ssh %s -- sudo journalctl -u drawbridge-agent -n 30`",
			addr, ref.Instance)
	case isTimeout(err):
		return fmt.Sprintf("%s accepted nothing within %s: gvproxy is forwarding the port but the guest agent is not answering behind it, "+
			"`podman machine ssh %s -- sudo journalctl -u drawbridge-agent -n 30`", addr, probeTimeout, ref.Instance)
	}
	return fmt.Sprintf("%s not reachable (%v), `podman machine ssh %s -- sudo journalctl -u drawbridge-agent -n 30`", addr, err, ref.Instance)
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT)
}
