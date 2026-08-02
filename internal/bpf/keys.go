package bpf

import "net/netip"

// PortKey mirrors struct port_key on the BPF side. Padding is explicit there
// and zeroed here by construction — hash map lookups are byte-wise.
type PortKey = loopbackgwPortKey

const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// Gateway addresses reserved for drawbridge inside the guest.
// 127.0.0.2 needs no setup (all of 127/8 is on lo). fd77::2 must be added
// before IPv6 interception works: `ip addr add fd77::2/128 dev lo`.
const (
	GatewayV4 = "127.0.0.2"
	GatewayV6 = "fd77::2"
)

// KeyFor builds the map key for a listener bind address.
// IPv4 addresses are stored v4-mapped (netip.Addr.As16 does this).
func KeyFor(proto uint8, addr netip.Addr, port uint16) PortKey {
	var k PortKey
	k.Proto = proto
	k.Port = port
	b := addr.As16()
	copy(k.Addr[:], b[:])
	return k
}
