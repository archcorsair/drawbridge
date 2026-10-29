package limaaddr

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// resolveEnv replaces the resolver's three machine inputs: no limactl answer,
// a lease db holding fixture text, and a probe that connects only to the
// addresses in reachable (everything else is refused). The returned slice
// records every address the resolver probed.
func resolveEnv(t *testing.T, leases string, reachable ...string) *[]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dhcpd_leases")
	if err := os.WriteFile(path, []byte(leases), 0o600); err != nil {
		t.Fatal(err)
	}
	origG, origL, origP := guestIPFn, leasesPath, probeDial
	t.Cleanup(func() { guestIPFn, leasesPath, probeDial = origG, origL, origP })

	guestIPFn = func(Target) (string, error) { return "", errors.New("limactl: not running as the VM owner") }
	leasesPath = path
	probed := new([]string)
	probeDial = func(_, addr string, _ time.Duration) (net.Conn, error) {
		*probed = append(*probed, addr)
		for _, ok := range reachable {
			if addr == ok {
				c, _ := net.Pipe()
				return c, nil
			}
		}
		return nil, dialErr(syscall.ECONNREFUSED)
	}
	return probed
}

const (
	limaLeases   = "{\n\tname=lima-drawbridge\n\tip_address=192.168.64.2\n\thw_address=1,52:55:55:a5:de:d2\n\tlease=0x6a6c420d\n}\n"
	colimaLeases = "{\n\tname=colima\n\tip_address=192.168.64.20\n\thw_address=1,52:55:55:a:de:2\n\tlease=0x6a6c4300\n}\n"
	loopback     = "tcp://127.0.0.1:4777"
)

// TestLoopbackFallbackIsLimaOnly pins decision E5 (audit NEW-X1). 127.0.0.1
// :4777 is the SSH forward of a Lima instance. A colima target that falls
// back to it dials whichever Lima VM owns the forward, and a root daemon
// aimed at colima:default with colima stopped attached to the dev VM.
func TestLoopbackFallbackIsLimaOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		target   Target
		leases   string
		reach    []string
		wantEP   string
		wantSrc  string
		wantNote []string // substrings; empty means no note expected
		noNote   bool
	}{
		{
			name:     "lima, no lease: loopback fallback as before",
			target:   Target{VM: "drawbridge", LeaseName: "lima-drawbridge", Provider: vmprovider.ProviderLima},
			wantEP:   loopback,
			wantSrc:  SourceSSHForwarder,
			wantNote: []string{NoteNoGuestIP},
		},
		{
			name:     "lima with the zero-value provider (historical Target): loopback fallback",
			target:   Target{VM: "drawbridge"},
			wantEP:   loopback,
			wantSrc:  SourceSSHForwarder,
			wantNote: []string{NoteNoGuestIP},
		},
		{
			name:     "lima, lease present but agent unreachable: loopback fallback",
			target:   Target{VM: "drawbridge", Provider: vmprovider.ProviderLima},
			leases:   limaLeases,
			wantEP:   loopback,
			wantSrc:  SourceSSHForwarder,
			wantNote: []string{NoteAgentNotListening},
		},
		{
			name:     "colima, no lease: no endpoint and a note that says why",
			target:   Target{VM: "colima", LeaseName: "colima", Provider: vmprovider.ProviderColima},
			wantEP:   "",
			wantSrc:  SourceUnresolved,
			wantNote: []string{"no endpoint for colima instance colima", causeNoGuestIP, "Not falling back to 127.0.0.1:4777", "Lima VM's SSH forward", "retries"},
		},
		{
			name:     "colima, stale lease whose address no longer answers: no endpoint",
			target:   Target{VM: "colima", LeaseName: "colima", Provider: vmprovider.ProviderColima},
			leases:   colimaLeases,
			wantEP:   "",
			wantSrc:  SourceUnresolved,
			wantNote: []string{"no endpoint for colima instance colima", causeAgentNotListening, "Not falling back to 127.0.0.1:4777"},
		},
		{
			name:    "colima, valid lease: the lease endpoint, as before",
			target:  Target{VM: "colima", LeaseName: "colima", Provider: vmprovider.ProviderColima},
			leases:  colimaLeases,
			reach:   []string{"192.168.64.20:4777"},
			wantEP:  "tcp://192.168.64.20:4777",
			wantSrc: SourceVZNATLeases,
			noNote:  true,
		},
		{
			name:    "lima, valid lease: the lease endpoint, as before",
			target:  Target{VM: "drawbridge", Provider: vmprovider.ProviderLima},
			leases:  limaLeases,
			reach:   []string{"192.168.64.2:4777"},
			wantEP:  "tcp://192.168.64.2:4777",
			wantSrc: SourceVZNATLeases,
			noNote:  true,
		},
		{
			// Podman never reaches the resolver (drawbridged and doctor
			// dispatch it to podmanaddr), so this is defense in depth: a
			// future caller that forgets the dispatch must not get Lima's
			// forward either.
			name:     "podman reaching the resolver anyway: no endpoint",
			target:   Target{VM: "spike", Provider: vmprovider.ProviderPodman},
			wantEP:   "",
			wantSrc:  SourceUnresolved,
			wantNote: []string{"no endpoint for podman instance spike", "Not falling back to 127.0.0.1:4777"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probed := resolveEnv(t, tc.leases, tc.reach...)
			got := ResolveTarget(tc.target, 4777)
			if got.Endpoint != tc.wantEP || got.Source != tc.wantSrc {
				t.Fatalf("got endpoint %q source %q, want %q %q (note %q)", got.Endpoint, got.Source, tc.wantEP, tc.wantSrc, got.Note)
			}
			if tc.noNote && got.Note != "" {
				t.Fatalf("unexpected note %q", got.Note)
			}
			for _, want := range tc.wantNote {
				if !strings.Contains(got.Note, want) {
					t.Fatalf("note %q missing %q", got.Note, want)
				}
			}
			// The unresolved shape never probes or names the loopback forward
			// as an endpoint: the only 127.0.0.1 text allowed is the refusal.
			if tc.wantEP == "" {
				for _, a := range *probed {
					if strings.HasPrefix(a, "127.0.0.1:") {
						t.Fatalf("resolver probed the Lima forward %s for a non-Lima target", a)
					}
				}
				if strings.Contains(got.Note, "Falling back") || strings.Contains(got.Note, "falling back to the SSH") {
					t.Fatalf("note promises a fallback it does not have: %q", got.Note)
				}
			}
		})
	}
}

// The no-lease-db-at-all shape (root daemon, Apple moved the file) takes the
// third fallback site; it must refuse the same way for colima.
func TestLoopbackFallbackLeaseDBUnreadable(t *testing.T) {
	resolveEnv(t, "")
	leasesPath = filepath.Join(t.TempDir(), "never-created")
	got := ResolveTarget(Target{VM: "colima", LeaseName: "colima", Provider: vmprovider.ProviderColima}, 4777)
	if got.Endpoint != "" || got.Source != SourceUnresolved {
		t.Fatalf("got %q %q, want no endpoint", got.Endpoint, got.Source)
	}
	for _, want := range []string{"DHCP lease db", "unreadable", "Not falling back"} {
		if !strings.Contains(got.Note, want) {
			t.Fatalf("note %q missing %q", got.Note, want)
		}
	}
	lima := ResolveTarget(Target{VM: "drawbridge", Provider: vmprovider.ProviderLima}, 4777)
	if lima.Endpoint != loopback || !strings.Contains(lima.Note, "falling back to the SSH forwarder") {
		t.Fatalf("lima: got %q note %q", lima.Endpoint, lima.Note)
	}
}

// The port the caller asked for is the port in the refusal, not a literal.
func TestNoFallbackNoteNamesTheRequestedPort(t *testing.T) {
	resolveEnv(t, "")
	got := ResolveTarget(Target{VM: "colima", LeaseName: "colima", Provider: vmprovider.ProviderColima}, 4790)
	if !strings.Contains(got.Note, "127.0.0.1:4790") {
		t.Fatalf("note %q does not name the requested port", got.Note)
	}
}

// Explicit endpoints never reach the resolver (drawbridged -agent host:port is
// parsed, not resolved); the only way an explicit address meets this package
// is through Resolve's wrapper, which is Lima by definition.
func TestResolveWrapperIsLima(t *testing.T) {
	resolveEnv(t, "")
	if got := Resolve("drawbridge", 4777); got.Endpoint != loopback || got.Source != SourceSSHForwarder {
		t.Fatalf("Resolve() = %q %q, want the Lima loopback fallback", got.Endpoint, got.Source)
	}
}

// limaaddr cannot import vmprovider in production code, so the provider name
// it keys on is a local constant; this keeps the two spellings from drifting.
func TestProviderLimaMatchesVMProvider(t *testing.T) {
	if providerLima != vmprovider.ProviderLima {
		t.Fatalf("providerLima = %q, vmprovider.ProviderLima = %q", providerLima, vmprovider.ProviderLima)
	}
	for _, p := range []string{vmprovider.ProviderColima, vmprovider.ProviderPodman, "something-new"} {
		if (Target{VM: "x", Provider: p}).mayUseLoopbackForward() {
			t.Fatalf("provider %q may use the Lima loopback forward", p)
		}
	}
}
