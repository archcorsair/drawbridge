// Package udpframe is the v1 datagram framing carried over proto-17
// 'S'/'D' transport streams (docs/udp.md). Byte-exact and frozen:
//
//	offset  size  field
//	0       2     length  — u16 BE, payload bytes N, 0 ≤ N ≤ 65507
//	2       1     flags   — MUST be 0; receiver closes the stream on nonzero
//	3       16    addr    — flow peer address, IPv6 or v4-mapped, network order
//	19      2     port    — flow peer port, u16 BE, nonzero
//	21      N     payload — the datagram, verbatim (N = 0 is legal UDP)
//
// The flow peer is the client side of the flow (the Mac client's AddrPort
// inbound, the guest client's outbound); reply frames must echo it — it is
// both the demux key and the reply destination. Any malformed header is an
// unrecoverable desync: callers close the stream (the owner re-dials or
// re-activates; in-flight datagrams are lost, which is UDP).
package udpframe

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
)

// Flow policy shared by every UDP flow table (docs/udp.md): UDP has no FIN,
// so every table expires idle flows. Vars, not consts, so tests can shrink
// them.
var (
	FlowIdleTimeout   = 60 * time.Second
	FlowSweepInterval = 10 * time.Second
	MaxFlows          = 4096
)

const (
	// HeaderLen is the fixed frame header size.
	HeaderLen = 21
	// MaxPayload is the largest UDP payload (65535 - 8 UDP - 20 IP).
	MaxPayload = 65507
)

// WriteFrame writes one frame with a single Write (header and payload in
// one buffer) so concurrent writers interleave at frame granularity; mu
// serializes writers sharing the stream (pass the stream's write mutex).
func WriteFrame(w io.Writer, mu *sync.Mutex, peer netip.AddrPort, payload []byte) error {
	if len(payload) > MaxPayload {
		return fmt.Errorf("udpframe: payload %d exceeds %d", len(payload), MaxPayload)
	}
	if peer.Port() == 0 {
		return fmt.Errorf("udpframe: zero peer port")
	}
	buf := make([]byte, HeaderLen+len(payload))
	binary.BigEndian.PutUint16(buf[0:], uint16(len(payload)))
	// buf[2] (flags) stays 0.
	a16 := peer.Addr().As16() // As16 v4-maps IPv4 addresses
	copy(buf[3:19], a16[:])
	binary.BigEndian.PutUint16(buf[19:], peer.Port())
	copy(buf[HeaderLen:], payload)
	mu.Lock()
	defer mu.Unlock()
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame. buf must be at least MaxPayload bytes; the
// returned payload aliases it and is only valid until the next call. A nil
// error with a malformed header cannot happen — malformed input returns an
// error and the caller must close the stream.
func ReadFrame(r io.Reader, buf []byte) (netip.AddrPort, []byte, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return netip.AddrPort{}, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[0:]))
	if n > MaxPayload {
		return netip.AddrPort{}, nil, fmt.Errorf("udpframe: length %d exceeds %d", n, MaxPayload)
	}
	if hdr[2] != 0 {
		return netip.AddrPort{}, nil, fmt.Errorf("udpframe: nonzero flags 0x%02x", hdr[2])
	}
	addr := netip.AddrFrom16([16]byte(hdr[3:19])).Unmap()
	port := binary.BigEndian.Uint16(hdr[19:])
	if port == 0 {
		return netip.AddrPort{}, nil, fmt.Errorf("udpframe: zero peer port")
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return netip.AddrPort{}, nil, err
	}
	return netip.AddrPortFrom(addr, port), buf[:n], nil
}
