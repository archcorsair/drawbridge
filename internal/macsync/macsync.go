// Package macsync is the Mac-side Phase 3 client: it enumerates native Mac
// TCP listeners and syncs them into the guest agent's mac_ports set over the
// transport ('M' events), and keeps parked reverse-stream connections ('D')
// that carry gateway-proxy traffic back to Mac loopback. Portable Go except
// the pcblist poller (darwin-only).
package macsync

import "net/netip"

// Listener describes one Mac socket endpoint. JSON shape matches the agent's
// transport events (netip.Addr marshals as its string form).
type Listener struct {
	Proto string     `json:"proto"` // "tcp" (UDP sync is future work)
	Port  uint16     `json:"port"`
	Addr  netip.Addr `json:"addr"` // bind address, unmapped

	// V6Only marks an IPv6 socket that does not also accept IPv4: its pcb's
	// inp_vflag lacks INP_IPV4. A dual-stack `::` (V6Only false) answers
	// 127.0.0.1 connects; a v6-only `::` does not, so it is neither synced
	// as v4-any (L23) nor counted as a holder of 127.0.0.1 (H1). Always
	// false for a v4 address. Never on the wire: normalize resolves it
	// before a listener is synced, so the 'M' payload is unchanged and a
	// synced key always carries false.
	V6Only bool `json:"-"`
}
