package vmprovider

// Podman's half of the coexistence detector (docs/podman.md §7 check 10).
//
// The Lima detector reads a materialized rule list out of `limactl list
// --json`. Podman has no such thing: its forwards are live entries in
// gvproxy's in-guest API, created by the user's own `-p` publications, and
// the only way to read them is from inside the guest. So this shells in and
// asks, which is why it is a live process fact and not a config parse.
//
// What the overlap means is also different in kind, and the caller's wording
// has to say so. A published container is *bridged*: it has its own netns,
// the tracker's host_netns_inum check excludes it, and it was never a mirror
// candidate. So a podman forward does not steal a mirror the way a Lima
// forward does. What it can do is hold a Mac-side port that a *host-netns*
// guest listener would otherwise be mirrored onto, which is a narrower and
// more specific hazard.

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// gvproxyForwardsURL is the in-guest endpoint. The subnet is gvproxy's own
// fixed one, the same constant the agent's publisher posts to; a machine
// where this does not answer is a machine with no gvproxy, which is not a
// state that exists while the machine is running.
const gvproxyForwardsURL = "http://192.168.127.1/services/forwarder/all"

// gvproxyForwardsScript reads the forward table. `curl` is in the podman
// machine image; a guest without it reports nothing forwarded rather than an
// error, because "I could not ask" and "nothing is forwarded" must not look
// the same to the caller and only one of them is worth a warning.
//
// It rides on stdin as one word of argv (`sh`), the rule every provider
// shell call in this repo follows.
const gvproxyForwardsScript = `
command -v curl >/dev/null 2>&1 || { echo drawbridge-gvproxy=absent; exit 0; }
body=$(curl -sS --max-time 3 ` + gvproxyForwardsURL + ` 2>/dev/null) || { echo drawbridge-gvproxy=unreachable; exit 0; }
echo drawbridge-gvproxy=ok
echo "$body"
exit 0
`

// gvproxyForward is one entry of the forwarder table.
type gvproxyForward struct {
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	Protocol string `json:"protocol"`
}

// Forwarding reports what gvproxy currently forwards for this machine.
//
// Two entries are always ours or podman's own and are excluded by their
// *remote* port, which is the guest-side port and the one thing a `-p`
// publication cannot collide with: `:22`, the ssh forward podman creates at
// machine start, and the agent transport port, which is drawbridge's own
// publish. Everything left is a `-p` the user asked for.
func (p *Podman) Forwarding(inst string) (Forwarding, error) {
	out, err := p.Shell(inst, strings.NewReader(gvproxyForwardsScript), "sh")
	if err != nil {
		return Forwarding{Instance: inst, Provider: ProviderPodman}, fmt.Errorf("reading gvproxy's forward table in %s: %w", inst, err)
	}
	return ParseGvproxyForwards(inst, string(out))
}

// ParseGvproxyForwards is the pure half: marker, then JSON, then
// classification. Exported so the table can be tested from a captured
// response without a machine.
func ParseGvproxyForwards(inst, out string) (Forwarding, error) {
	f := Forwarding{Instance: inst, Provider: ProviderPodman}
	marker, body, _ := strings.Cut(out, "\n")
	switch strings.TrimSpace(marker) {
	case "drawbridge-gvproxy=ok":
	case "drawbridge-gvproxy=absent":
		return f, fmt.Errorf("no curl in the guest, so gvproxy's forward table could not be read")
	case "drawbridge-gvproxy=unreachable":
		return f, fmt.Errorf("gvproxy's in-guest API (%s) did not answer", gvproxyForwardsURL)
	default:
		return f, fmt.Errorf("unexpected answer from the guest: %q", firstLineOf(out))
	}

	var entries []gvproxyForward
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &entries); err != nil {
		return f, fmt.Errorf("gvproxy's forward table is not the JSON array this build expects (%w)", err)
	}

	// gvproxy answered, so a forwarder is running and holding this machine.
	// That is true even with an empty table, and it is the state the caller
	// distinguishes from "this provider has no forwarder at all".
	f.HostAgent = true

	var loopback, wildcard []int
	for _, e := range entries {
		guestPort, ok := portOf(e.Remote)
		if !ok {
			continue
		}
		// Podman's own ssh forward, and drawbridge's own transport publish.
		// Neither is a user publication and neither is coexistence.
		if guestPort == 22 || guestPort == DefaultAgentPort {
			continue
		}
		localAddr, localPort, ok := hostPortOf(e.Local)
		if !ok {
			continue
		}
		switch localAddr {
		case "", "0.0.0.0", "::", "*":
			wildcard = append(wildcard, localPort)
		default:
			loopback = append(loopback, localPort)
		}
	}
	f.Loopback = portSetOf(loopback)
	f.Wildcard = portSetOf(wildcard)
	return f, nil
}

// DefaultAgentPort is the guest-side transport port, restated here so this
// package does not import internal/transport for one integer and so the
// exclusion above reads as what it is. A test pins the two together.
const DefaultAgentPort = 4777

func portOf(hostport string) (int, bool) {
	_, port, ok := hostPortOf(hostport)
	return port, ok
}

func hostPortOf(s string) (host string, port int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < minPort || n > maxPort {
		return "", 0, false
	}
	return h, n, true
}

// portSetOf turns a bag of ports into the sorted, merged shape a PortSet is.
func portSetOf(ports []int) PortSet {
	if len(ports) == 0 {
		return nil
	}
	sort.Ints(ports)
	var out PortSet
	for _, p := range ports {
		if n := len(out); n > 0 && p <= out[n-1].Hi+1 {
			if p > out[n-1].Hi {
				out[n-1].Hi = p
			}
			continue
		}
		out = append(out, PortRange{Lo: p, Hi: p})
	}
	return out
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
