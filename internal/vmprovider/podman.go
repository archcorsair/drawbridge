package vmprovider

// The Podman driver (docs/podman.md §4). Everything here shells out to
// `podman machine` and is therefore user-scoped, exactly like the limactl
// half, see the package comment. Podman keeps its machine state in the
// invoking user's home, so under euid 0 it would look in /var/root and find
// nothing; the root daemon never reaches this file, because `drawbridge
// install` pins the endpoint it resolved as the user into the plist.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ErrPodmanRootScoped is what every `podman machine` invocation returns under
// euid 0. Like the limactl refusal it fails before exec, so the message can
// say what to do instead: podman's own error would be an empty machine list,
// which diagnoses nothing.
// It wraps ErrRootScoped so a caller that only wants to know "is this
// absence just scoping" (doctor's check 1, which otherwise reads an empty
// list as `nothing running`) does not have to enumerate every provider's own
// spelling of the same refusal.
var ErrPodmanRootScoped = fmt.Errorf("%w: `podman machine` is user-scoped and must not run under euid 0 "+
	"(machine state lives in the invoking user's home; as root podman looks in /var/root and reports no machines); "+
	"run this as your own user, the root daemon dials the endpoint `drawbridge install` pinned into its plist", ErrRootScoped)

// PodmanFallbackBin is where the official podman `.pkg` puts the binary. It
// is on PATH only in a login shell (the pkg installs /etc/paths.d/podman-pkg),
// so a CLI invoked from launchd, a build tool or a non-login shell has to be
// told, observed live, 7.0 spike.
const PodmanFallbackBin = "/opt/podman/bin/podman"

// PodmanBin resolves the podman binary: PATH first, then the official pkg's
// location. The returned path is quoted in every error this package raises,
// so "podman said no" always names which podman.
func PodmanBin() (string, error) {
	if p, err := exec.LookPath("podman"); err == nil {
		return p, nil
	}
	if fi, err := os.Stat(PodmanFallbackBin); err == nil && !fi.IsDir() {
		return PodmanFallbackBin, nil
	}
	return "", fmt.Errorf("vmprovider: no `podman` on PATH and none at %s "+
		"(the official macOS pkg installs it there and adds it to PATH through /etc/paths.d/podman-pkg, "+
		"which a non-login shell does not read)", PodmanFallbackBin)
}

// Podman drives `podman machine`.
//
// It carries one piece of state: the machine→VMType map learned from List.
// `podman machine ssh` and `inspect` address a machine of a non-default
// provider only when CONTAINERS_MACHINE_PROVIDER names it, and the machine's
// own type is always the right value, so every invocation that names an
// instance sets it when it knows it.
type Podman struct {
	mu     sync.Mutex
	vmtype map[string]string
}

// NewPodman returns the driver for this user's podman machines.
func NewPodman() *Podman { return &Podman{} }

// Provider is the tag this driver stamps on the instances it reports.
func (p *Podman) Provider() string { return ProviderPodman }

// List enumerates this user's podman machines.
//
// `--all-providers` is deliberately absent: podman 6.0.2 has no such flag
// (the 7.0 spike checked), and plain `machine list --format json` already
// reports machines of every provider on this Mac.
func (p *Podman) List() ([]Instance, error) {
	out, err := p.podman(nil, nil, "machine", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	raw, err := decodePodmanList(out)
	if err != nil {
		return nil, err
	}
	insts := make([]Instance, 0, len(raw))
	for _, m := range raw {
		insts = append(insts, m.instance())
		p.remember(m.Name, m.VMType)
	}
	return insts, nil
}

// Inspect reads the machine's SSH configuration and rootful flag, what `up`
// writes into the Mac-side record (internal/vmrecord) and what doctor
// compares that record against.
func (p *Podman) Inspect(inst string) (PodmanInspect, error) {
	out, err := p.podman(nil, p.env(inst), "machine", "inspect", inst)
	if err != nil {
		return PodmanInspect{}, err
	}
	return decodePodmanInspect(out, inst)
}

// Shell runs argv inside the guest. stdin may be nil.
//
// `podman machine ssh NAME -- a b c` joins argv into one remote command
// string without quoting, exactly as `limactl shell` does (verified live in
// the 7.0 spike: `bash -s a b "c d"` arrived as four arguments). checkArgv is
// therefore the same gate for both drivers, and anything with structure goes
// on stdin.
func (p *Podman) Shell(inst string, stdin io.Reader, argv ...string) ([]byte, error) {
	if err := checkArgv(inst, argv); err != nil {
		return nil, err
	}
	return p.podman(stdin, p.env(inst), append([]string{"machine", "ssh", inst, "--"}, argv...)...)
}

// GuestArch reports the guest's own `uname -m`, for the same reason the Lima
// driver does: the embedded agent has to match what will actually execute.
func (p *Podman) GuestArch(inst string) (string, error) {
	out, err := p.Shell(inst, nil, "uname", "-m")
	if err != nil {
		return "", err
	}
	arch := strings.TrimSpace(string(out))
	if arch == "" {
		return "", fmt.Errorf("vmprovider: %s: `uname -m` returned nothing", inst)
	}
	return arch, nil
}

// remember records a machine's VMType for later env-scoped invocations.
func (p *Podman) remember(name, vmtype string) {
	if name == "" || vmtype == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.vmtype == nil {
		p.vmtype = map[string]string{}
	}
	p.vmtype[name] = vmtype
}

// env is the environment addition an instance-scoped invocation needs.
//
// CONTAINERS_MACHINE_PROVIDER selects which provider directory podman looks
// in; naming the machine's own type is always correct and is what makes an
// applehv machine addressable on a Mac whose default provider is libkrun.
// Unknown type ⇒ nothing added, which is podman's own default behaviour.
func (p *Podman) env(inst string) []string {
	p.mu.Lock()
	t := p.vmtype[inst]
	p.mu.Unlock()
	if t == "" {
		// One list is cheap next to an ssh round trip and it is the only way
		// to learn the type of a machine we were handed by name alone.
		if _, err := p.list(); err == nil {
			p.mu.Lock()
			t = p.vmtype[inst]
			p.mu.Unlock()
		}
	}
	if t == "" {
		return nil
	}
	return []string{"CONTAINERS_MACHINE_PROVIDER=" + t}
}

// list is List without the env-filling recursion env() would otherwise cause.
func (p *Podman) list() ([]Instance, error) {
	out, err := p.podman(nil, nil, "machine", "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	raw, err := decodePodmanList(out)
	if err != nil {
		return nil, err
	}
	insts := make([]Instance, 0, len(raw))
	for _, m := range raw {
		insts = append(insts, m.instance())
		p.remember(m.Name, m.VMType)
	}
	return insts, nil
}

// podman is the one seam every invocation goes through: the root refusal, the
// binary resolution, the per-machine provider environment, and stderr capture
// (podman's diagnosis is on stderr, and exec.Cmd.Output discards it into an
// opaque exit status).
func (p *Podman) podman(stdin io.Reader, env []string, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return nil, ErrPodmanRootScoped
	}
	bin, err := PodmanBin()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w%s", bin, strings.Join(args, " "), err, stderrTail(stderr.String()))
	}
	return out, nil
}

// podmanJSON is the subset of `podman machine list --format json` this
// package reads. Unknown fields are ignored, the same rule limaJSON follows:
// naming the fields is what keeps a podman upgrade from breaking the parse.
type podmanJSON struct {
	Name     string `json:"Name"`
	Default  bool   `json:"Default"`
	Running  bool   `json:"Running"`
	Starting bool   `json:"Starting"`
	VMType   string `json:"VMType"`

	// Port, RemoteUsername and IdentityPath are the SSH coordinates. `up`
	// takes them from `machine inspect` instead (one document, and the one
	// doctor compares the record against), but they are read here too so a
	// caller with a listing in hand needs no second exec.
	Port               int    `json:"Port"`
	RemoteUsername     string `json:"RemoteUsername"`
	IdentityPath       string `json:"IdentityPath"`
	UserModeNetworking bool   `json:"UserModeNetworking"`
}

// instance maps a listing entry to the provider-neutral shape.
//
// Running && !Starting, because a machine mid-start answers neither ssh nor
// the transport, and "attach to it now" is the question this flag answers.
func (m podmanJSON) instance() Instance {
	attachable, note := Attachability(ProviderPodman, m.VMType)
	return Instance{
		Provider:   ProviderPodman,
		Name:       m.Name,
		VMType:     m.VMType,
		LeaseName:  LeaseName(ProviderPodman, m.Name),
		Running:    m.Running && !m.Starting,
		Attachable: attachable,
		AttachNote: note,
	}
}

// PodmanInspect is the subset of `podman machine inspect NAME` that the
// Mac-side record is written from (docs/podman.md §3.4).
// The machine's VMType is deliberately absent: the inspect document does not
// carry it (the listing does), and a field that is sometimes filled is worse
// than one that is never there.
type PodmanInspect struct {
	Name    string
	State   string
	Rootful bool
	SSH     PodmanSSH
}

// PodmanSSH is the machine's ssh coordinate triple. The port is chosen at
// `podman machine init` and is stable across stop/start; the identity is one
// key file shared by every machine of this user.
type PodmanSSH struct {
	IdentityPath   string
	Port           int
	RemoteUsername string
}

// podmanInspectJSON mirrors `podman machine inspect`'s document. Keys
// observed live on podman 6.0.2: ConfigDir, ConnectionInfo, Created, LastUp,
// Name, Resources, SSHConfig, State, UserModeNetworking, Rootful, Rosetta.
type podmanInspectJSON struct {
	Name      string `json:"Name"`
	State     string `json:"State"`
	Rootful   bool   `json:"Rootful"`
	SSHConfig struct {
		IdentityPath   string `json:"IdentityPath"`
		Port           int    `json:"Port"`
		RemoteUsername string `json:"RemoteUsername"`
	} `json:"SSHConfig"`
}

// decodePodmanList reads `podman machine list --format json`. Unlike
// limactl's stream of objects this is a single JSON array, and an empty
// machine list is `[]`, not the empty string.
func decodePodmanList(b []byte) ([]podmanJSON, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, nil
	}
	var raw []podmanJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("vmprovider: parsing `podman machine list --format json`: %w", err)
	}
	out := raw[:0]
	for _, m := range raw {
		if m.Name == "" {
			continue // a record with no name names no machine
		}
		out = append(out, m)
	}
	return out, nil
}

// decodePodmanInspect reads `podman machine inspect NAME`, which returns a
// one-element array even for a single machine.
func decodePodmanInspect(b []byte, inst string) (PodmanInspect, error) {
	var raw []podmanInspectJSON
	if err := json.Unmarshal(b, &raw); err != nil {
		return PodmanInspect{}, fmt.Errorf("vmprovider: parsing `podman machine inspect %s`: %w", inst, err)
	}
	for _, m := range raw {
		if m.Name != inst && m.Name != "" && len(raw) > 1 {
			continue
		}
		return PodmanInspect{
			Name:    m.Name,
			State:   m.State,
			Rootful: m.Rootful,
			SSH: PodmanSSH{
				IdentityPath:   m.SSHConfig.IdentityPath,
				Port:           m.SSHConfig.Port,
				RemoteUsername: m.SSHConfig.RemoteUsername,
			},
		}, nil
	}
	return PodmanInspect{}, fmt.Errorf("vmprovider: `podman machine inspect %s` described no machine", inst)
}

// ---------------------------------------------------------------------------
// The machine config on disk: podman's own state, read without running podman
// ---------------------------------------------------------------------------

// ErrNoMachine is what ReadPodmanMachineConfig returns when no machine of
// that name has a config file. It is a distinct error because the remedy is
// distinct: the machine was removed or renamed, and no `drawbridge` command
// will bring it back.
var ErrNoMachine = errors.New("no podman machine config")

// MachineConfig is a podman machine as its own config file describes it.
//
// Reading the file rather than running `podman machine inspect` is what makes
// this usable from `drawbridge install`, which runs as root. Root must never
// run `podman machine` (the state is per-user, and under euid 0 podman looks
// in /var/root and truthfully reports nothing), but reading a file under the
// invoking user's home is exactly the move install already makes for the
// transport secret path: the SUDO_USER home is resolved, the file is read,
// and no user tooling is executed.
//
// The fields are the ones the Mac-side record is written from, so a record
// and a config can be compared for disagreement (docs/podman.md §7.2).
// Everything else podman keeps there (hypervisor knobs, mounts, image paths)
// is deliberately not read: a field this package does not use is a field a
// podman upgrade cannot break.
type MachineConfig struct {
	Name    string
	VMType  string // the provider directory the config lives in
	Rootful bool
	SSH     PodmanSSH
	Path    string // where it was read from, for the message
}

// podmanConfigJSON is the subset of `<machine>.json` this package reads.
// Observed on podman 6.0.2 (`Version: 1`).
type podmanConfigJSON struct {
	Name     string `json:"Name"`
	HostUser struct {
		Rootful bool `json:"Rootful"`
	} `json:"HostUser"`
	SSH struct {
		IdentityPath   string `json:"IdentityPath"`
		Port           int    `json:"Port"`
		RemoteUsername string `json:"RemoteUsername"`
	} `json:"SSH"`
}

// PodmanMachineDirIn is podman's machine state directory under a given home.
// One subdirectory per provider (`libkrun`, `applehv`), each holding the
// machines' JSON configs.
func PodmanMachineDirIn(home string) string {
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".config", "containers", "podman", "machine")
}

// PodmanMachineDir is PodmanMachineDirIn for the current user's home.
func PodmanMachineDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return PodmanMachineDirIn(home)
}

// ReadPodmanMachineConfig finds and reads one machine's config under home.
//
// Every provider directory is searched, because the machine's provider is not
// knowable from the name alone and is itself one of the things a caller wants
// to compare. Two providers holding a machine of the same name is not a state
// podman can produce (names are unique across providers: `init` refuses a
// duplicate), so the first match wins and the directory name is the VMType.
func ReadPodmanMachineConfig(home, name string) (MachineConfig, error) {
	dir := PodmanMachineDirIn(home)
	if dir == "" {
		return MachineConfig{}, fmt.Errorf("vmprovider: no home directory to read podman machine config from")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return MachineConfig{}, fmt.Errorf("%w for %q: %s does not exist", ErrNoMachine, name, dir)
		}
		return MachineConfig{}, fmt.Errorf("vmprovider: reading %s: %w", dir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), name+".json")
		blob, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return MachineConfig{}, fmt.Errorf("vmprovider: reading %s: %w", path, err)
		}
		var raw podmanConfigJSON
		if err := json.Unmarshal(blob, &raw); err != nil {
			return MachineConfig{}, fmt.Errorf("vmprovider: parsing %s: %w", path, err)
		}
		return MachineConfig{
			Name:    raw.Name,
			VMType:  e.Name(),
			Rootful: raw.HostUser.Rootful,
			SSH: PodmanSSH{
				IdentityPath:   raw.SSH.IdentityPath,
				Port:           raw.SSH.Port,
				RemoteUsername: raw.SSH.RemoteUsername,
			},
			Path: path,
		}, nil
	}
	return MachineConfig{}, fmt.Errorf("%w for %q under %s", ErrNoMachine, name, dir)
}
