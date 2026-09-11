package vmprovider

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	return b
}

// The fixtures are `podman machine list --format json` and `podman machine
// inspect spike` captured verbatim from podman 6.0.2 on macOS (only the home
// directory and the $TMPDIR path are anonymised). Unlike limactl's output
// this is a JSON *array*, so a decoder written to limactl's stream shape
// parses nothing at all.
func TestPodmanList(t *testing.T) {
	raw, err := decodePodmanList(readFixture(t, "podman-list.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]Instance, 0, len(raw))
	for _, m := range raw {
		got = append(got, m.instance())
	}
	want := []Instance{
		{Provider: ProviderPodman, Name: "spike", VMType: "libkrun", Running: true, Attachable: true},
		{Provider: ProviderPodman, Name: "spike-hv", VMType: "applehv", Running: false, Attachable: true},
	}
	assertInstances(t, got, want)

	// The lease name must be empty for every podman machine: gvproxy is
	// user-mode and writes no vmnet DHCP lease, so there is no record to
	// match and a `lima-`-style default would name one that cannot exist.
	for _, i := range got {
		if i.LeaseName != "" {
			t.Fatalf("%s: LeaseName = %q, want empty", i.Name, i.LeaseName)
		}
		if i.MACAddress != "" {
			t.Fatalf("%s: MACAddress = %q, want empty", i.Name, i.MACAddress)
		}
	}
}

// A machine mid-start answers neither ssh nor the transport.
func TestPodmanStartingIsNotRunning(t *testing.T) {
	m := podmanJSON{Name: "x", VMType: "libkrun", Running: true, Starting: true}
	if m.instance().Running {
		t.Fatal("a Starting machine reported Running")
	}
}

func TestPodmanListEdgeCases(t *testing.T) {
	for _, in := range []string{"", "  \n", "[]", "null"} {
		raw, err := decodePodmanList([]byte(in))
		if err != nil || len(raw) != 0 {
			t.Fatalf("decodePodmanList(%q) = %d, %v; want no machines", in, len(raw), err)
		}
	}
	if _, err := decodePodmanList([]byte("not json")); err == nil {
		t.Fatal("decodePodmanList accepted non-JSON")
	}
	// A record with no name names no machine.
	raw, err := decodePodmanList([]byte(`[{"Name":""},{"Name":"real","VMType":"applehv"}]`))
	if err != nil || len(raw) != 1 || raw[0].Name != "real" {
		t.Fatalf("decodePodmanList dropped the wrong record: %+v, %v", raw, err)
	}
}

// `podman machine inspect NAME` returns a one-element array. The record `up`
// writes is built from exactly these fields.
func TestPodmanInspect(t *testing.T) {
	got, err := decodePodmanInspect(readFixture(t, "podman-inspect.json"), "spike")
	if err != nil {
		t.Fatal(err)
	}
	want := PodmanInspect{
		Name:    "spike",
		State:   "running",
		Rootful: false,
		SSH: PodmanSSH{
			IdentityPath:   "/Users/u/.local/share/containers/podman/machine/machine",
			Port:           57446,
			RemoteUsername: "core",
		},
	}
	if got != want {
		t.Fatalf("inspect = %+v, want %+v", got, want)
	}
	if _, err := decodePodmanInspect([]byte("[]"), "spike"); err == nil {
		t.Fatal("an empty inspect array was accepted")
	}
}

// libkrun is podman 6's default macOS provider and the whole 7.0 spike ran on
// it; applehv behaves identically (same gvproxy, same FCOS). Both attach.
func TestAttachability(t *testing.T) {
	for _, tc := range []struct {
		provider, vmType string
		want             bool
		note             string
	}{
		{ProviderLima, "vz", true, ""},
		{ProviderLima, "qemu", false, "user-mode networking"},
		{ProviderColima, "vz", true, ""},
		{ProviderColima, "QEMU", false, "user-mode networking"},
		{ProviderPodman, "libkrun", true, ""},
		{ProviderPodman, "applehv", true, ""},
		{ProviderPodman, "qemu", false, "not a macOS provider"},
		{ProviderPodman, "", false, "did not report a machine type"},
	} {
		got, note := Attachability(tc.provider, tc.vmType)
		if got != tc.want {
			t.Fatalf("Attachability(%q, %q) = %v, want %v", tc.provider, tc.vmType, got, tc.want)
		}
		if tc.want && note != "" {
			t.Fatalf("Attachability(%q, %q) is attachable but carries a note %q", tc.provider, tc.vmType, note)
		}
		if !tc.want && !strings.Contains(note, tc.note) {
			t.Fatalf("Attachability(%q, %q) note = %q, want it to mention %q", tc.provider, tc.vmType, note, tc.note)
		}
	}
}

// Podman's machine state is per-user; as root podman would look in /var/root
// and report an empty machine list, which is silently wrong rather than
// loudly wrong. The refusal happens before exec so the message can say what
// to do instead.
func TestPodmanRootIsRefusedBeforeExec(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root: the refusal is asserted by inspection of the one seam (podman)")
	}
	if _, err := NewPodman().List(); err == nil || !strings.Contains(err.Error(), "user-scoped") {
		t.Fatalf("List() as root = %v, want ErrPodmanRootScoped", err)
	}
}

// Both provider shells join argv into one unquoted remote command string, so
// an element with whitespace is re-split in the guest.
func TestShellRefusesWhitespaceArgv(t *testing.T) {
	for _, p := range []Provider{NewLima(), NewPodman()} {
		if _, err := p.Shell("x", nil); err == nil {
			t.Fatal("Shell with no argv was accepted")
		}
		_, err := p.Shell("x", nil, "sh", "-c", "echo hello world")
		if err == nil || !strings.Contains(err.Error(), "whitespace") {
			t.Fatalf("Shell with a multi-word argv element = %v, want a refusal", err)
		}
	}
}

// The driver a Ref names. Podman refs get the podman driver and no LIMA_HOME
// anywhere near them.
func TestForRefDispatchesOnProvider(t *testing.T) {
	if _, ok := ForRef(mustRef(t, "podman:spike")).(*Podman); !ok {
		t.Fatal("ForRef(podman:…) did not return the podman driver")
	}
	if _, ok := ForRef(mustRef(t, "colima:default")).(*Lima); !ok {
		t.Fatal("ForRef(colima:…) did not return the lima driver")
	}
}

// The fallback path matters: the official pkg puts podman in /opt/podman/bin
// and adds it to PATH through /etc/paths.d, which a non-login shell does not
// read, so LookPath alone finds nothing on a perfectly good install.
func TestPodmanBinNamesWhereItLooked(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	bin, err := PodmanBin()
	if err == nil {
		if bin != PodmanFallbackBin {
			t.Fatalf("PodmanBin() = %q with an empty PATH, want the pkg location", bin)
		}
		return
	}
	if !strings.Contains(err.Error(), PodmanFallbackBin) {
		t.Fatalf("PodmanBin() error %q does not name where it looked", err)
	}
}

// `drawbridge install` runs as root, and root must never run `podman
// machine`: the state is per-user, and under euid 0 podman looks in /var/root
// and truthfully reports no machines. Reading the config file under the
// invoking user's home is the exec-free half, and the fixture is the real
// layout (one directory per provider, `<name>.json` inside it).
func TestReadPodmanMachineConfig(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(PodmanMachineDirIn(home), "libkrun")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The subset this package reads, in podman 6.0.2's shape. The rest of the
	// real file (hypervisor knobs, mounts, image paths) is deliberately
	// absent: a field we do not read is a field an upgrade cannot break.
	body := `{"Name":"spike","Version":1,
	  "HostUser":{"Rootful":false,"UID":501},
	  "SSH":{"IdentityPath":"/Users/u/.local/share/containers/podman/machine/machine","Port":57446,"RemoteUsername":"core"},
	  "LibKrunHypervisor":{"KRun":{"LogLevel":"panic"}}}`
	if err := os.WriteFile(filepath.Join(dir, "spike.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadPodmanMachineConfig(home, "spike")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "spike" || got.VMType != "libkrun" || got.Rootful {
		t.Fatalf("config = %+v", got)
	}
	if got.SSH.Port != 57446 || got.SSH.RemoteUsername != "core" || got.SSH.IdentityPath == "" {
		t.Fatalf("ssh = %+v", got.SSH)
	}
	// The path is in the refusal message, so a user can read the file we read.
	if !strings.HasSuffix(got.Path, filepath.Join("libkrun", "spike.json")) {
		t.Fatalf("Path = %q", got.Path)
	}

	// A machine that is gone is its own error, because its remedy is its own:
	// no drawbridge command brings a removed machine back.
	if _, err := ReadPodmanMachineConfig(home, "gone"); !errors.Is(err, ErrNoMachine) {
		t.Fatalf("missing machine = %v, want ErrNoMachine", err)
	}
	if _, err := ReadPodmanMachineConfig(t.TempDir(), "spike"); !errors.Is(err, ErrNoMachine) {
		t.Fatalf("no machine dir at all = %v, want ErrNoMachine", err)
	}

	// Every provider directory is searched: the machine's provider is not
	// knowable from the name, and is itself something callers compare.
	hv := filepath.Join(PodmanMachineDirIn(home), "applehv")
	if err := os.MkdirAll(hv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hv, "spike-hv.json"), []byte(`{"Name":"spike-hv","HostUser":{"Rootful":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = ReadPodmanMachineConfig(home, "spike-hv")
	if err != nil || got.VMType != "applehv" || !got.Rootful {
		t.Fatalf("applehv machine = %+v, %v", got, err)
	}

	// Podman's file format is podman's. A parse failure must be reportable as
	// "could not check", never as ErrNoMachine (which would read as "your
	// machine is gone" about a machine that is right there).
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadPodmanMachineConfig(home, "broken")
	if err == nil || errors.Is(err, ErrNoMachine) {
		t.Fatalf("malformed config = %v, want a distinct parse error", err)
	}
}
