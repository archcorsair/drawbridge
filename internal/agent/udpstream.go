//go:build linux

package agent

import (
	"fmt"
	"net"

	"github.com/archcorsair/drawbridge/internal/udpframe"
)

// serveUDPStream handles one inbound proto-17 'S' stream (docs/udp.md):
// framed datagrams from Mac clients are relayed to the guest listener on
// 127.0.0.1:port through one relay socket per Mac client — distinct
// guest-side ephemeral source ports, so the guest server's own per-peer
// demux keeps working — and replies are framed back with the client's
// AddrPort. All state is per-stream: a reconnecting mirror gets a fresh,
// independent table.
func (a *Agent) serveUDPStream(c net.Conn, port uint16) {
	udpframe.RelayStream(c, func() (*net.UDPConn, error) {
		// Native under the connect4 hook: port is in guest_ports (that is
		// why it was mirrored).
		rc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return nil, err
		}
		return rc.(*net.UDPConn), nil
	})
}
