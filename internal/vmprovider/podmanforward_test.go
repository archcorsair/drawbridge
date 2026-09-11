package vmprovider

import (
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/transport"
)

// The exclusion above is written against a literal, so it has to be the same
// literal the rest of the system means by "the agent's port".
func TestDefaultAgentPortMatchesTheTransport(t *testing.T) {
	if DefaultAgentPort != transport.DefaultAgentPort {
		t.Fatalf("vmprovider.DefaultAgentPort = %d, transport.DefaultAgentPort = %d: the gvproxy exclusion would stop matching drawbridge's own publish",
			DefaultAgentPort, transport.DefaultAgentPort)
	}
}

// A table captured from `podman:spike` while the agent was published and one
// container was running with `-p 8081:80`.
const liveForwards = `drawbridge-gvproxy=ok
[{"local":"127.0.0.1:4778","remote":"192.168.127.2:4777","protocol":"tcp"},
 {"local":"127.0.0.1:57446","remote":"192.168.127.2:22","protocol":"tcp"},
 {"local":"0.0.0.0:8081","remote":"192.168.127.2:8081","protocol":"tcp"}]
`

func TestParseGvproxyForwards(t *testing.T) {
	f, err := ParseGvproxyForwards("spike", liveForwards)
	if err != nil {
		t.Fatal(err)
	}
	if !f.HostAgent {
		t.Fatal("gvproxy answered, so a forwarder is holding this machine")
	}
	if f.Provider != ProviderPodman {
		t.Fatalf("provider = %q", f.Provider)
	}
	// Neither the ssh forward nor drawbridge's own publish is coexistence:
	// one is podman's machine plumbing, the other is ours.
	if got := f.Loopback.String(); got != "none" {
		t.Fatalf("loopback = %s, want none (only :22 and our own transport are on 127.0.0.1 here)", got)
	}
	if got := f.Wildcard.String(); got != "8081" {
		t.Fatalf("wildcard = %s, want 8081 (the -p publication)", got)
	}
	if !f.Active() {
		t.Fatal("a user publication is active coexistence")
	}
}

// A machine with the agent up and nothing published is the baseline: a live
// forwarder holding only what podman and drawbridge put there.
func TestParseGvproxyForwardsBaselineIsNotCoexistence(t *testing.T) {
	const baseline = `drawbridge-gvproxy=ok
[{"local":"127.0.0.1:4778","remote":"192.168.127.2:4777","protocol":"tcp"},{"local":"127.0.0.1:57446","remote":"192.168.127.2:22","protocol":"tcp"}]
`
	f, err := ParseGvproxyForwards("spike", baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !f.HostAgent {
		t.Fatal("the forwarder is running")
	}
	if f.Active() {
		t.Fatalf("the baseline forwards read as coexistence: loopback=%s wildcard=%s", f.Loopback, f.Wildcard)
	}
}

// Several publications merge into ranges the way a port list is written.
func TestParseGvproxyForwardsMerges(t *testing.T) {
	const many = `drawbridge-gvproxy=ok
[{"local":"0.0.0.0:8080","remote":"192.168.127.2:8080","protocol":"tcp"},
 {"local":"0.0.0.0:8082","remote":"192.168.127.2:8082","protocol":"tcp"},
 {"local":"0.0.0.0:8081","remote":"192.168.127.2:8081","protocol":"tcp"},
 {"local":"127.0.0.1:5432","remote":"192.168.127.2:5432","protocol":"tcp"}]
`
	f, err := ParseGvproxyForwards("spike", many)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Wildcard.String(); got != "8080-8082" {
		t.Fatalf("wildcard = %s, want 8080-8082", got)
	}
	if got := f.Loopback.String(); got != "5432" {
		t.Fatalf("loopback = %s, want 5432", got)
	}
}

// "I could not ask" must not read as "nothing is forwarded": one is a skip
// with a reason, the other suppresses a warning the user may need.
func TestParseGvproxyForwardsFailureModes(t *testing.T) {
	for _, tc := range []struct {
		name, out, want string
	}{
		{"no curl", "drawbridge-gvproxy=absent\n", "no curl in the guest"},
		{"api down", "drawbridge-gvproxy=unreachable\n", "did not answer"},
		{"garbage", "bash: curl: command not found\n", "unexpected answer"},
		{"not an array", "drawbridge-gvproxy=ok\n{\"error\":\"nope\"}\n", "not the JSON array"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := ParseGvproxyForwards("spike", tc.out)
			if err == nil {
				t.Fatalf("accepted %q", tc.out)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			if f.HostAgent || f.Active() {
				t.Fatalf("a failed read reported a forwarder: %+v", f)
			}
		})
	}
}
