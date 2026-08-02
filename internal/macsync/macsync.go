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
}
