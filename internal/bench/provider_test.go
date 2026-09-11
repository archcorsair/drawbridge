package bench

// The provider dispatch, tested without a VM: the parts of the harness that
// decide which guest is driven and how it is reached (docs/podman.md §7.2).
// Everything else in this package needs DRAWBRIDGE_BENCH and a live VM.

import (
	"io"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/podmanaddr"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// recordingProvider captures what the harness asks a guest to run.
type recordingProvider struct {
	argv  []string
	stdin string
}

func (r *recordingProvider) List() ([]vmprovider.Instance, error) { return nil, nil }
func (r *recordingProvider) GuestArch(string) (string, error)     { return "aarch64", nil }

func (r *recordingProvider) Shell(_ string, stdin io.Reader, argv ...string) ([]byte, error) {
	r.argv = argv
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		r.stdin = string(b)
	}
	return nil, nil
}

// The script goes on stdin and every argv element is one space-free word.
// Both provider shells join argv into a single unquoted remote command
// string, so a multi-word element is re-split in the guest: `bash -c <script>`
// would arrive as `bash -c` plus the script's first word, with the rest as
// positional parameters.
func TestGuestExecPutsTheScriptOnStdin(t *testing.T) {
	p := &recordingProvider{}
	prevProvider, prevRef := vmProvider, vmRef
	t.Cleanup(func() { vmProvider, vmRef = prevProvider, prevRef })
	vmProvider, vmRef = p, vmprovider.Ref{Instance: "spike"}

	script := "systemd-run --unit=dbg --collect /path/to/agent benchserve -listen :47801 -mode echo"
	if _, err := guest(t, script); err != nil {
		t.Fatal(err)
	}
	if p.stdin != script {
		t.Fatalf("stdin = %q, want the script verbatim", p.stdin)
	}
	for _, a := range p.argv {
		if strings.ContainsAny(a, " \t\n") {
			t.Fatalf("argv element %q has whitespace; provider shells join argv unquoted", a)
		}
	}
	if strings.Join(p.argv, " ") != "sudo -n bash" {
		t.Fatalf("argv = %v, want `sudo -n bash` with the script on stdin", p.argv)
	}
}

// The "is it running" gate is the provider's own answer, so it means the same
// thing for a Lima instance and a podman machine.
func TestRunningGate(t *testing.T) {
	insts := []vmprovider.Instance{
		{Provider: "lima", Name: "drawbridge", Running: false},
		{Provider: "podman", Name: "spike", Running: true},
		{Provider: "podman", Name: "spike-hv", Running: false},
	}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"spike", true},
		{"drawbridge", false},
		{"spike-hv", false},
		{"absent", false},
	} {
		if got := running(insts, tc.name); got != tc.want {
			t.Fatalf("running(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Resolution dispatches the same way drawbridged's does. A podman ref must
// never reach the lease db: gvproxy is user-mode and writes no record, so
// limaaddr would match `lima-spike` and resolve some other VM or nothing.
//
// The HOME fixture leaves no per-VM record, so the podman resolver refuses,
// which is the observable half here: an empty endpoint carrying podman's
// source, produced without limactl being run at all.
func TestResolveDispatchesOnProvider(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	ref, err := vmprovider.ParseRef("podman:spike")
	if err != nil {
		t.Fatal(err)
	}
	got := resolve(ref)
	if got.Source != podmanaddr.Source {
		t.Fatalf("source = %q, want %q", got.Source, podmanaddr.Source)
	}
	if got.Endpoint != "" || !strings.Contains(got.Note, "drawbridge up podman:spike") {
		t.Fatalf("resolve(podman) = %+v, want the record-absent refusal", got)
	}
}

// The default VM is the dev VM, so `just bench` and every recorded Lima table
// keep meaning what they meant.
func TestDefaultVMIsTheDevVM(t *testing.T) {
	if defaultVM != "drawbridge" {
		t.Fatalf("defaultVM = %q", defaultVM)
	}
	ref, err := vmprovider.ParseRef(defaultVM)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Provider != vmprovider.ProviderLima || ref.Instance != "drawbridge" {
		t.Fatalf("defaultVM parses to %+v", ref)
	}
}
