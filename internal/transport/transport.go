// Package transport owns the endpoint grammar between the Mac side
// (drawbridged, e2e, bench) and the guest agent, plus the two operations
// everything else needs: Dial and Listen.
//
// # Grammar
//
//	endpoint = scheme "://" address | bare
//	scheme   = "tcp" | "unix" | "vsock"
//	tcp      address = host ":" port    e.g. tcp://192.168.64.5:4777
//	unix     address = absolute path    e.g. unix:///run/drawbridge.sock
//	vsock    address = cid ":" port     e.g. vsock://3:4777   (reserved)
//	bare     = host ":" port            → tcp (back-compat: flags, tests,
//	                                      net.Listener.Addr().String())
//
// The API is string-first on purpose: endpoints travel as strings, the
// existing AgentAddr fields keep their type, and every test that does
// AgentAddr: ln.Addr().String() keeps working unmodified.
//
// # Contract (binding on any future transport added behind Dial/Listen)
//
//   - Reliable, ordered, per-connection flow control. The 'E' stream must
//     never silently drop or reorder, and each conn must backpressure
//     independently of the others.
//   - Half-close must propagate. Returned conns implement
//     interface{ CloseWrite() error } (*net.TCPConn and *net.UnixConn both
//     do; asserted in tests). This is the property Lima's gRPC tunnel lacks
//     and the reason the SSH forwarder is pinned.
//   - Dial writes nothing. This binds the transport *layer*: Dial returns a
//     conn on which the transport itself has sent zero bytes — no banners,
//     no handshakes, ever; a transport that needs its own preamble cannot
//     be added behind Dial. The 4-byte conn-type frame is *application*
//     protocol, written by the dial sites after Dial returns — keep the two
//     distinct. The dial-pool invariant is unchanged: the agent's dispatch
//     consumes the type frame before parking, so a parked 'D' conn is
//     byte-silent until the guest writes the 4-byte activation header, and
//     the watchdog treats ANY earlier byte as a dead conn.
//   - The conn-type frame, the per-type headers, and all five stream kinds
//     ('E' 'S' 'R' 'M' 'D') stay byte-identical across schemes.
//
// vsock:// parses (so it can appear in config and docs today) but Dial and
// Listen return ErrUnsupported: reaching a guest vsock port needs the
// VM-owning process — see docs/transport.md §1.
package transport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DefaultDialTimeout matches the 3s every Mac-side dial site used before the
// seam existed.
const DefaultDialTimeout = 3 * time.Second

// Schemes.
const (
	SchemeTCP   = "tcp"
	SchemeUnix  = "unix"
	SchemeVsock = "vsock"
)

// ErrUnsupported is wrapped by Dial/Listen for an endpoint whose scheme
// parses but has no implementation on this build (today: vsock).
var ErrUnsupported = errors.New("transport: unsupported scheme")

// Endpoint is a parsed, canonical endpoint.
type Endpoint struct {
	Scheme string // "tcp", "unix", "vsock"
	Addr   string // host:port | /path | cid:port
}

// String returns the canonical endpoint spelling, always scheme-qualified.
func (e Endpoint) String() string {
	if e.Scheme == "" {
		return e.Addr
	}
	return e.Scheme + "://" + e.Addr
}

// Port is the tcp/vsock port, 0 for unix (and for a zero Endpoint). It
// replaces the ad-hoc net.SplitHostPort in drawbridged and mirror.New.
func (e Endpoint) Port() uint16 {
	switch e.Scheme {
	case SchemeTCP:
		_, p, err := net.SplitHostPort(e.Addr)
		if err != nil {
			return 0
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return 0
		}
		return uint16(v)
	case SchemeVsock:
		_, p, ok := strings.Cut(e.Addr, ":")
		if !ok {
			return 0
		}
		v, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return 0
		}
		return uint16(v)
	}
	return 0
}

// Parse validates an endpoint string and returns its canonical form. A bare
// "host:port" canonicalizes to "tcp://host:port"; a host-less ":port" keeps
// its empty host (the wildcard bind, v4+v6 — rewriting it to 0.0.0.0 would
// silently narrow it).
func Parse(endpoint string) (Endpoint, error) {
	if endpoint == "" {
		return Endpoint{}, errors.New("transport: empty endpoint")
	}
	scheme, addr, ok := strings.Cut(endpoint, "://")
	if !ok {
		scheme, addr = SchemeTCP, endpoint // bare host:port
	}
	switch scheme {
	case SchemeTCP:
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return Endpoint{}, fmt.Errorf("transport: bad tcp endpoint %q: %w", endpoint, err)
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return Endpoint{}, fmt.Errorf("transport: bad tcp port in %q: %w", endpoint, err)
		}
		return Endpoint{Scheme: SchemeTCP, Addr: net.JoinHostPort(host, port)}, nil
	case SchemeUnix:
		if !strings.HasPrefix(addr, "/") {
			return Endpoint{}, fmt.Errorf("transport: unix endpoint needs an absolute path: %q", endpoint)
		}
		return Endpoint{Scheme: SchemeUnix, Addr: addr}, nil
	case SchemeVsock:
		cid, port, ok := strings.Cut(addr, ":")
		if !ok {
			return Endpoint{}, fmt.Errorf("transport: vsock endpoint needs cid:port: %q", endpoint)
		}
		if _, err := strconv.ParseUint(cid, 10, 32); err != nil {
			return Endpoint{}, fmt.Errorf("transport: bad vsock cid in %q: %w", endpoint, err)
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return Endpoint{}, fmt.Errorf("transport: bad vsock port in %q: %w", endpoint, err)
		}
		return Endpoint{Scheme: SchemeVsock, Addr: cid + ":" + port}, nil
	}
	return Endpoint{}, fmt.Errorf("transport: unknown scheme %q in %q", scheme, endpoint)
}

// Dial connects with DefaultDialTimeout. It accepts bare host:port.
func Dial(endpoint string) (net.Conn, error) {
	return DialTimeout(endpoint, DefaultDialTimeout)
}

// DialTimeout connects with an explicit timeout. The transport writes no
// bytes on the returned conn (see the package contract).
func DialTimeout(endpoint string, d time.Duration) (net.Conn, error) {
	e, err := Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch e.Scheme {
	case SchemeTCP:
		return net.DialTimeout("tcp", e.Addr, d)
	case SchemeUnix:
		return net.DialTimeout("unix", e.Addr, d)
	}
	return nil, unsupported(e)
}

// Listen binds the endpoint (guest agent, tests).
func Listen(endpoint string) (net.Listener, error) {
	e, err := Parse(endpoint)
	if err != nil {
		return nil, err
	}
	switch e.Scheme {
	case SchemeTCP:
		return net.Listen("tcp", e.Addr)
	case SchemeUnix:
		return net.Listen("unix", e.Addr)
	}
	return nil, unsupported(e)
}

func unsupported(e Endpoint) error {
	if e.Scheme == SchemeVsock {
		return fmt.Errorf("%w: vsock: requires a VM-owning integration; see docs/transport.md §1", ErrUnsupported)
	}
	return fmt.Errorf("%w: %s", ErrUnsupported, e.Scheme)
}
