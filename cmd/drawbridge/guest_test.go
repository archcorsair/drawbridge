package main

import (
	"flag"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func inst(provider, name, vmType string, running bool) vmprovider.Instance {
	return vmprovider.Instance{
		Provider: provider, Name: name, VMType: vmType, Running: running,
		LeaseName: vmprovider.LeaseName(provider, name),
	}
}

var (
	limaDev    = inst(vmprovider.ProviderLima, "drawbridge", "vz", true)
	limaQemu   = inst(vmprovider.ProviderLima, "old", "qemu", true)
	limaHalted = inst(vmprovider.ProviderLima, "parked", "vz", false)
	colimaDef  = inst(vmprovider.ProviderColima, "colima", "vz", true)
	// A Lima instance literally called `colima`: legal, and the reason a
	// bare name has to be checked for ambiguity rather than assumed to be
	// Lima's (Phase 3 pinned the same hazard from the lease-db side).
	limaNamedColima = inst(vmprovider.ProviderLima, "colima", "vz", true)
)

// Step 1 of §4.1, every branch. These messages are the entire first-run
// experience for anyone whose Mac is not the happy case.
func TestPickInstance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arg     string
		insts   []vmprovider.Instance
		want    string // qualified name, "" when an error is expected
		wantErr []string
	}{{
		name:  "single running vz instance is implicit",
		insts: []vmprovider.Instance{limaDev},
		want:  "lima:drawbridge",
	}, {
		name:  "stopped and qemu instances are not candidates",
		insts: []vmprovider.Instance{limaHalted, limaQemu, colimaDef},
		want:  "colima:colima",
	}, {
		name:    "no VM at all prints how to create one",
		wantErr: []string{"no running vz VM", "colima start", "limactl start"},
	}, {
		name:    "a stopped VM is named, with its own start command",
		insts:   []vmprovider.Instance{limaHalted},
		wantErr: []string{"lima:parked exists but is stopped", "limactl start parked"},
	}, {
		name:    "a qemu VM gets the vz switch instruction",
		insts:   []vmprovider.Instance{limaQemu},
		wantErr: []string{"runs on qemu", "vmType: vz"},
	}, {
		name:    "a qemu colima VM gets colima's spelling of it",
		insts:   []vmprovider.Instance{inst(vmprovider.ProviderColima, "colima", "qemu", true)},
		wantErr: []string{"colima start --vm-type vz"},
	}, {
		name:    "several candidates require the argument",
		insts:   []vmprovider.Instance{limaDev, colimaDef},
		wantErr: []string{"several VMs", "drawbridge up lima:drawbridge", "drawbridge up colima:colima"},
	}, {
		name:  "an explicit provider:name selects",
		arg:   "colima:colima",
		insts: []vmprovider.Instance{limaDev, colimaDef},
		want:  "colima:colima",
	}, {
		name:  "colima:default maps to the colima instance",
		arg:   "colima:default",
		insts: []vmprovider.Instance{colimaDef},
		want:  "colima:colima",
	}, {
		name:  "a bare name resolves across providers",
		arg:   "drawbridge",
		insts: []vmprovider.Instance{limaDev, colimaDef},
		want:  "lima:drawbridge",
	}, {
		name:    "a bare name two providers share is ambiguous",
		arg:     "colima",
		insts:   []vmprovider.Instance{limaNamedColima, colimaDef},
		wantErr: []string{"ambiguous", "drawbridge up lima:colima", "drawbridge up colima:colima"},
	}, {
		name:    "a named instance that is stopped says so",
		arg:     "lima:parked",
		insts:   []vmprovider.Instance{limaHalted},
		wantErr: []string{"is not running", "limactl start parked"},
	}, {
		name:    "a named qemu instance is refused with the switch",
		arg:     "lima:old",
		insts:   []vmprovider.Instance{limaQemu},
		wantErr: []string{"not vz", "host-reachable guest IP"},
	}, {
		name:    "an unknown name lists what there is",
		arg:     "nope",
		insts:   []vmprovider.Instance{limaDev},
		wantErr: []string{`no VM named "nope"`, "lima:drawbridge (vz, running)"},
	}, {
		name:    "an unparseable name fails the -vm grammar",
		arg:     "../etc",
		wantErr: []string{"invalid lima instance name"},
	}, {
		name:    "an unknown provider is named as such",
		arg:     "podman:default",
		wantErr: []string{"unknown VM provider"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pickInstance(tc.arg, tc.insts)
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("pickInstance = %s, want an error", qualify(got.Instance))
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q does not mention %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if qualify(got.Instance) != tc.want {
				t.Fatalf("pickInstance = %s, want %s", qualify(got.Instance), tc.want)
			}
			// The Ref has to carry the provider's lease name and LIMA_HOME,
			// or the endpoint resolution in step 6 looks in the wrong place.
			if got.Ref.LeaseName != vmprovider.LeaseName(got.Instance.Provider, got.Instance.Name) {
				t.Fatalf("Ref.LeaseName = %q, want the provider's own", got.Ref.LeaseName)
			}
		})
	}
}

// The user's own spelling is what gets echoed into the `drawbridge install
// -vm …` next-step line, so it must survive selection verbatim.
func TestPickInstanceKeepsUserSpelling(t *testing.T) {
	sel, err := pickInstance("colima:default", []vmprovider.Instance{colimaDef})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Ref.Spec != "colima:default" {
		t.Fatalf("Ref.Spec = %q, want the text the user typed", sel.Ref.Spec)
	}
	if sel.Ref.Instance != "colima" {
		t.Fatalf("Ref.Instance = %q, want the mapped Lima instance", sel.Ref.Instance)
	}
}

// Every preflight branch is a message someone reads instead of a stack
// trace; each one has to name the fix.
func TestCheckPreflight(t *testing.T) {
	ok := preflight{Arch: "aarch64", Kernel: "6.8.0-51-generic", BTF: true, CGroup2: true, Systemd: true, Sudo: true}
	for _, tc := range []struct {
		name    string
		p       preflight
		oci     bool
		wantErr []string
	}{
		{name: "a healthy guest passes", p: ok},
		{name: "an unreachable guest", p: preflight{}, wantErr: []string{"uname -m"}},
		{
			name: "no systemd names the Alpine case and the fix",
			p:    mutate(ok, func(p *preflight) { p.Systemd = false }),
			// §9 Q6: systemd is a v1 requirement, and colima's legacy image
			// is the way most users will hit it.
			wantErr: []string{"no systemctl", "OpenRC", "colima start"},
		},
		{
			name:    "no passwordless sudo",
			p:       mutate(ok, func(p *preflight) { p.Sudo = false }),
			wantErr: []string{"passwordless sudo", "sudoers"},
		},
		{
			name:    "no BTF names the kernel config",
			p:       mutate(ok, func(p *preflight) { p.BTF = false }),
			wantErr: []string{"/sys/kernel/btf/vmlinux", "CONFIG_DEBUG_INFO_BTF"},
		},
		{
			name:    "cgroup v1 names the boot parameter",
			p:       mutate(ok, func(p *preflight) { p.CGroup2 = false }),
			wantErr: []string{"cgroup v2", "systemd.unified_cgroup_hierarchy=1"},
		},
		{
			name:    "an architecture we do not ship",
			p:       mutate(ok, func(p *preflight) { p.Arch = "riscv64" }),
			wantErr: []string{"unsupported guest architecture"},
		},
		{
			// Informational without --oci: only the seccomp listenerPath
			// contract needs 5.7, and everything else works below it.
			name: "an old kernel is tolerated without --oci",
			p:    mutate(ok, func(p *preflight) { p.Kernel = "5.4.0-generic" }),
		},
		{
			name:    "an old kernel blocks --oci",
			p:       mutate(ok, func(p *preflight) { p.Kernel = "5.4.0-generic"; p.Docker = true }),
			oci:     true,
			wantErr: []string{"older than 5.7", "listenerPath", "Without --oci"},
		},
		{
			name:    "--oci needs an engine to register with",
			p:       ok,
			oci:     true,
			wantErr: []string{"no docker in the guest", "re-run without --oci"},
		},
		{
			name: "--oci is fine on a current kernel with docker",
			p:    mutate(ok, func(p *preflight) { p.Docker = true }),
			oci:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPreflight(tc.p, tc.oci)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("checkPreflight: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkPreflight succeeded, want a refusal")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

func mutate(p preflight, f func(*preflight)) preflight {
	f(&p)
	return p
}

func TestParsePreflight(t *testing.T) {
	got := parsePreflight("arch=x86_64\nkernel=6.1.0\nbtf=yes\ncgroup2=no\nsystemd=yes\ndocker=no\nsudo=yes\nfuture=yes\n")
	want := preflight{Arch: "x86_64", Kernel: "6.1.0", BTF: true, CGroup2: false, Systemd: true, Docker: false, Sudo: true}
	if got != want {
		t.Fatalf("parsePreflight = %+v, want %+v", got, want)
	}
}

func TestParseKernel(t *testing.T) {
	for _, tc := range []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"6.8.0-51-generic", 6, 8, true},
		{"5.15.0", 5, 15, true},
		{"6.1", 6, 1, true},
		{"5.7.0-rc1", 5, 7, true},
		{"weird", 0, 0, false},
		{"6", 0, 0, false},
	} {
		maj, min, ok := parseKernel(tc.in)
		if maj != tc.maj || min != tc.min || ok != tc.ok {
			t.Fatalf("parseKernel(%q) = %d, %d, %v; want %d, %d, %v", tc.in, maj, min, ok, tc.maj, tc.min, tc.ok)
		}
	}
}

// Go's flag package stops at the first non-flag token, so `drawbridge up
// colima:default --oci` would silently drop --oci without this.
func TestParsePositional(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		want    string
		wantOCI bool
		wantErr bool
	}{
		{args: nil},
		{args: []string{"colima:default"}, want: "colima:default"},
		{args: []string{"--oci"}, wantOCI: true},
		{args: []string{"colima:default", "--oci"}, want: "colima:default", wantOCI: true},
		{args: []string{"--oci", "colima:default"}, want: "colima:default", wantOCI: true},
		{args: []string{"a", "b"}, wantErr: true},
	} {
		fs := flag.NewFlagSet("up", flag.ContinueOnError)
		fs.SetOutput(discardWriter{})
		oci := fs.Bool("oci", false, "")
		got, err := parsePositional(fs, tc.args)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parsePositional(%v) = %q, want an error", tc.args, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parsePositional(%v): %v", tc.args, err)
		}
		if got != tc.want || *oci != tc.wantOCI {
			t.Fatalf("parsePositional(%v) = %q, oci=%v; want %q, oci=%v", tc.args, got, *oci, tc.want, tc.wantOCI)
		}
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// Guest paths are interpolated into `sh -c` strings; the quoting has to hold
// for anything that grows a space or a quote later.
func TestShquote(t *testing.T) {
	for in, want := range map[string]string{
		"/usr/local/bin/x": `'/usr/local/bin/x'`,
		"a b":              `'a b'`,
		`it's`:             `'it'\''s'`,
	} {
		if got := shquote(in); got != want {
			t.Fatalf("shquote(%q) = %s, want %s", in, got, want)
		}
	}
}
