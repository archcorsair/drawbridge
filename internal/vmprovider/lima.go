package vmprovider

// The Lima driver, and the Colima driver, which is the same one. Everything
// here shells out to `limactl` and is therefore user-scoped — see the
// package comment.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ErrRootScoped is what every limactl invocation returns under euid 0.
// Failing here rather than at exec is deliberate: limactl's refusal message
// ("running lima as root is not supported") does not say what a caller
// should do instead, and the answer differs by caller — the daemon resolves
// from the lease db, the CLI re-runs as the user.
var ErrRootScoped = errors.New("vmprovider: limactl is user-scoped and refuses euid 0 (its state lives in the invoking user's LIMA_HOME); " +
	"run this as your own user — the root daemon resolves its peer from the DHCP lease db instead")

// Lima drives one limactl state directory. Colima gets its own value rather
// than its own type: same binary, same JSON, different LIMA_HOME and a
// different tag on what comes back.
type Lima struct {
	provider string // ProviderLima | ProviderColima
	home     string // LIMA_HOME override; "" means the ambient environment
}

// NewLima drives the user's own Lima instances, under whatever LIMA_HOME the
// environment already says. The home is deliberately *not* resolved here:
// inheriting the caller's environment is the historical behaviour of every
// limactl call in this repo, and pinning it would break a user who sets the
// variable per shell.
func NewLima() *Lima { return &Lima{provider: ProviderLima} }

// NewColima drives colima's instances, which live under their own LIMA_HOME.
func NewColima() *Lima { return &Lima{provider: ProviderColima, home: ColimaHome()} }

// NewLimaHome drives an explicit state directory. It is what a parsed Ref
// turns into, and what tests use.
func NewLimaHome(provider, home string) *Lima { return &Lima{provider: provider, home: home} }

// ForRef returns the driver a parsed -vm value names.
func ForRef(r Ref) *Lima { return NewLimaHome(r.Provider, r.LimaHome) }

// Provider is the tag this driver stamps on the instances it reports.
func (l *Lima) Provider() string { return l.provider }

// Home is the LIMA_HOME this driver runs limactl under; "" means ambient.
func (l *Lima) Home() string { return l.home }

// List enumerates the instances in this driver's state directory.
func (l *Lima) List() ([]Instance, error) {
	out, err := l.limactl(nil, "list", "--json")
	if err != nil {
		return nil, err
	}
	raw, err := decodeList(bytes.NewReader(out))
	if err != nil {
		return nil, err
	}
	insts := make([]Instance, 0, len(raw))
	for _, li := range raw {
		insts = append(insts, li.instance(l.provider))
	}
	return insts, nil
}

// Shell runs argv inside the guest. stdin may be nil.
func (l *Lima) Shell(inst string, stdin io.Reader, argv ...string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("vmprovider: Shell(%q): no command given", inst)
	}
	return l.limactl(stdin, append([]string{"shell", inst, "--"}, argv...)...)
}

// GuestArch reports the guest's own `uname -m`. It is the guest kernel's
// answer and not the provider's metadata on purpose: the embedded agent has
// to match what will actually execute.
func (l *Lima) GuestArch(inst string) (string, error) {
	out, err := l.Shell(inst, nil, "uname", "-m")
	if err != nil {
		return "", err
	}
	arch := strings.TrimSpace(string(out))
	if arch == "" {
		return "", fmt.Errorf("vmprovider: %s: `uname -m` returned nothing", inst)
	}
	return arch, nil
}

// limactl is the one seam every invocation goes through: the root refusal,
// the LIMA_HOME override, and stderr capture (limactl's diagnosis is on
// stderr, and exec.Cmd.Output alone discards it into an opaque exit status).
func (l *Lima) limactl(stdin io.Reader, args ...string) ([]byte, error) {
	if os.Geteuid() == 0 {
		return nil, ErrRootScoped
	}
	cmd := exec.Command("limactl", args...)
	if l.home != "" {
		cmd.Env = append(os.Environ(), "LIMA_HOME="+l.home)
	}
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("limactl %s: %w%s", strings.Join(args, " "), err, stderrTail(stderr.String()))
	}
	return out, nil
}

// stderrTail appends limactl's last words to an exec error, bounded so a
// pathological failure cannot turn one error into a screenful.
func stderrTail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	return ": " + strings.Join(lines, "; ")
}

// limaJSON is the subset of `limactl list --json` this package reads.
// Unknown fields are ignored, which is what keeps a Lima upgrade from
// breaking the parse — and the reason to name fields rather than take the
// whole document.
type limaJSON struct {
	Name string `json:"name"`

	// Hostname is Lima's *expectation* of the guest hostname, and it is
	// decorative here — deliberately unused by instance(). For a colima
	// instance Lima reports `lima-colima` while the guest answers `colima`
	// and writes that into the DHCP lease db. Read LeaseName, not this.
	Hostname     string `json:"hostname"`
	Status       string `json:"status"`
	Dir          string `json:"dir"`
	VMType       string `json:"vmType"`
	HostAgentPID int    `json:"hostAgentPID"`
	Network      []struct {
		VZNAT      bool   `json:"vzNAT"`
		MACAddress string `json:"macAddress"`
	} `json:"network"`
	// Config is the *materialized* instance config: limactl has already
	// merged the template, the defaults and the overrides, so the rules in
	// here are the rules the hostagent runs (forwarding.go depends on that).
	Config struct {
		PortForwards []portForward `json:"portForwards"`
	} `json:"config"`
}

func (li limaJSON) instance(provider string) Instance {
	return Instance{
		Provider:   provider,
		Name:       li.Name,
		VMType:     li.VMType,
		LeaseName:  LeaseName(provider, li.Name),
		Running:    li.running(),
		MACAddress: li.macAddress(),
	}
}

func (li limaJSON) running() bool { return strings.EqualFold(li.Status, "running") }

// macAddress reports the vzNAT interface's hardware address, which is the
// only one whose lease record the resolver would ever match. A non-vzNAT
// network's MAC would pin the wrong interface.
func (li limaJSON) macAddress() string {
	for _, n := range li.Network {
		if n.VZNAT && n.MACAddress != "" {
			return n.MACAddress
		}
	}
	return ""
}

// decodeList reads limactl's output. It is a *stream* of JSON objects, one
// per instance, not an array — json.Decoder consumes both that and a
// pretty-printed single object, so nothing here depends on the whitespace.
func decodeList(r io.Reader) ([]limaJSON, error) {
	dec := json.NewDecoder(r)
	var out []limaJSON
	for {
		var li limaJSON
		err := dec.Decode(&li)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("vmprovider: parsing `limactl list --json`: %w", err)
		}
		if li.Name == "" {
			continue // a record with no name names no instance
		}
		out = append(out, li)
	}
}
