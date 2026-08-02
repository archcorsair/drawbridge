// Package proxy implements the per-port gateway listeners that carry
// intercepted loopback traffic to a backend. In Phase 1 the backend is a
// dummy target inside the guest (127.0.0.3:*); in Phase 3 the dialer is
// swapped for a vsock connection to the Mac daemon — everything else stays.
package proxy

import (
	"net"
	"sync/atomic"
)

// Proxy is one gateway listener (one Mac-owned port).
type Proxy interface {
	Close() error
	Addr() net.Addr
}

// DialFunc opens the backend connection for one accepted flow. Phase 3's
// dialer pulls a parked Mac reverse-stream conn; the fixed-address form
// below covers the harness's in-guest dummy backends.
type DialFunc func() (net.Conn, error)

// Backend returns a DialFunc that dials a fixed address.
func Backend(network, addr string) DialFunc {
	return func() (net.Conn, error) { return net.Dial(network, addr) }
}

// Stats counts traffic through all gateway proxies. The harness uses it to
// prove the proxy was (or was not) involved in a given flow.
type Stats struct {
	TCPConns   atomic.Int64 // TCP connections accepted on gateway listeners
	UDPPackets atomic.Int64 // datagrams relayed client->backend
	UDPFlows   atomic.Int64 // live client flows across relay tables (gauge)
}
