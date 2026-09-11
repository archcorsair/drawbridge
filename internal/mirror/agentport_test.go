package mirror

import (
	"testing"

	"github.com/archcorsair/drawbridge/internal/transport"
)

// The agent's own transport listener is infrastructure under both of the
// ports it can be named by: the endpoint this Mac dials, and the port the
// listener actually occupies inside the guest.
//
// On Lima and Colima those are the same number and this pins that nothing
// changed. On a podman machine they differ by construction (the Mac dials a
// gvproxy-published port, 4778 and up), and mirroring the guest's 4777 onto
// Mac 4777 is what the daemon used to do: visible on podman, and on Lima
// hidden behind a lost bind race with the SSH forward, which is not the same
// thing as being right.
func TestAgentTransportIsNeverMirrored(t *testing.T) {
	for _, tc := range []struct {
		name           string
		agentPort      uint16
		guestAgentPort uint16
		port           uint16
		want           bool
	}{
		{"lima: one port, both roles", 4777, 0, 4777, false},
		{"podman: the dialed endpoint", 4778, 4777, 4778, false},
		{"podman: the guest-side listener", 4778, 4777, 4777, false},
		{"an explicit guest port", 4778, 5555, 5555, false},
		{"an ordinary guest service", 4778, 4777, 8080, true},
		{"the default still applies when unset", 4778, 0, transport.DefaultAgentPort, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{GuestAgentPort: tc.guestAgentPort}
			c.agentPort = tc.agentPort
			got := c.mirrorable(listenerInfo{Proto: "tcp", Addr: "0.0.0.0", Port: tc.port})
			if got != tc.want {
				t.Fatalf("mirrorable(tcp :%d) = %v, want %v (agentPort=%d guestAgentPort=%d)",
					tc.port, got, tc.want, tc.agentPort, tc.guestAgentPort)
			}
		})
	}
}

// A guest port set explicitly wins over the default, so an agent started
// with a non-default -transport is still excluded once the daemon is told.
func TestGuestAgentPortDefault(t *testing.T) {
	if got := (&Client{}).guestAgentPort(); got != transport.DefaultAgentPort {
		t.Fatalf("zero value = %d, want the transport default %d", got, transport.DefaultAgentPort)
	}
	if got := (&Client{GuestAgentPort: 9999}).guestAgentPort(); got != 9999 {
		t.Fatalf("explicit value = %d, want 9999", got)
	}
}
