// Package vmprovider enumerates the container VMs drawbridge can attach to
// and answers the questions the attach path asks of them: which instances
// exist, what the guest's architecture is, and whether the provider is
// already forwarding guest ports to Mac localhost itself (docs/ergonomics.md
// §3.2, §3.4).
//
// Two halves, deliberately separable:
//
//   - Ref (this file) is pure. It turns a `provider:name` -vm value into a
//     Lima instance name, a DHCP lease name and a LIMA_HOME. No process is
//     run, so drawbridged — the root LaunchDaemon included — can use it to
//     build a limaaddr.Target without acquiring a dependency on tooling it
//     may not run.
//   - Provider (lima.go) is impure: it shells out to limactl, and only ever
//     as the user who owns the VM. `limactl` refuses euid 0 and its state
//     lives in the invoking user's LIMA_HOME, so the root daemon never calls
//     into this half — it resolves its peer from the DHCP lease db
//     (internal/limaaddr/leases.go) exactly as before.
//
// Colima is Lima. It is the same limactl driven against colima's own
// LIMA_HOME (ColimaHome, which discovers rather than assumes — colima has
// moved that directory), with instance names `colima` (the `default`
// profile) and `colima-<profile>` — one implementation with a different home
// and a different provider tag for the UX, not a second driver.
package vmprovider

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Provider tags. They are the `provider` half of a -vm value and the word
// used when naming an instance to the user.
const (
	ProviderLima   = "lima"
	ProviderColima = "colima"
	ProviderPodman = "podman"
)

// Instance is one VM as the provider reports it.
type Instance struct {
	Provider  string // ProviderLima | ProviderColima | ProviderPodman
	Name      string // provider-scoped instance name
	VMType    string // "vz" | "qemu" | "libkrun" | "applehv" | ...
	LeaseName string // dhcpd_leases match: "lima-<name>" for lima, "<name>" for colima, "" for podman
	Running   bool

	// MACAddress is the vzNAT interface's hardware address — the value
	// `drawbridge install -vm-mac` pins, and the one field of a DHCP lease
	// record a guest cannot choose (leases.go). Empty when the instance has
	// no vzNAT network, which is also how a qemu instance reads, and always
	// empty for podman (gvproxy is user-mode: there is no vmnet lease).
	MACAddress string

	// Attachable is the provider's own verdict on this VMType, and the half
	// of `up`'s eligibility test that is not "is it running" (docs/podman.md
	// §4.2). It is a provider fact rather than a CLI one because "vz" is Lima
	// vocabulary: a podman machine is attachable on libkrun and applehv, and
	// neither word means anything to Lima.
	Attachable bool

	// AttachNote says why not, in the user's terms. Empty when Attachable.
	// The remediation command is the caller's to spell, it is per-provider
	// and per-instance, and lives with the other user-facing text.
	AttachNote string
}

// Attachability is the per-provider verdict on a VMType: whether drawbridge
// can attach to a guest of that kind, and why not when it cannot.
//
// Pure and exported so the CLI, doctor and their tests all reach the same
// answer instead of each reimplementing "is it vz".
func Attachability(provider, vmType string) (bool, string) {
	t := strings.ToLower(strings.TrimSpace(vmType))
	switch provider {
	case ProviderPodman:
		// Both macOS providers are attachable: the transport is gvproxy
		// either way, and the 7.0 spike ran end to end on libkrun (podman 6's
		// default) with the applehv cross-check showing the same shape.
		switch t {
		case "libkrun", "applehv":
			return true, ""
		case "":
			return false, "podman did not report a machine type for this machine"
		default:
			return false, "podman machine type " + t + " is not a macOS provider: drawbridge attaches to libkrun and applehv machines"
		}
	default:
		if t == "vz" {
			return true, ""
		}
		return false, "runs on " + t + ", which has no host-reachable guest IP (user-mode networking)"
	}
}

// Provider is the driver surface. List and Shell are user-scoped: see the
// package comment for why the root daemon must not reach them.
type Provider interface {
	List() ([]Instance, error)
	Shell(inst string, stdin io.Reader, argv ...string) ([]byte, error)
	GuestArch(inst string) (string, error)
}

// Forwarder is the optional half a provider implements when it runs a port
// forwarder of its own that drawbridge has to coexist with (§3.4). It is not
// part of Provider because the answer is provider-shaped: podman's gvproxy
// is not Lima's hostagent, and pretending otherwise would put a Lima concept
// in the interface every driver has to satisfy.
type Forwarder interface {
	Forwarding(inst string) (Forwarding, error)
}

// Ref is a parsed -vm value: which provider, which Lima instance, and the
// two things resolution needs from that pairing.
type Ref struct {
	Provider  string // ProviderLima | ProviderColima
	Instance  string // Lima instance name; a colima profile is already mapped
	LeaseName string // DHCP record name to match — never evidence of identity
	LimaHome  string // LIMA_HOME for limactl; "" means the ambient environment
	Spec      string // the -vm text, verbatim: what install renders back out
}

// instanceNameRE is what a Lima instance may be called. It is an allowlist
// rather than a metacharacter blocklist because this value reaches root's
// ProgramArguments through the install plist (internal/install).
var instanceNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// maxNameLen matches install's own bound on a VM name.
const maxNameLen = 64

// ParseRef reads a -vm value. `provider:name` names the provider explicitly
// (`colima:default`, `lima:myvm`); a bare name keeps its historical meaning
// of a Lima instance, so every existing invocation and every installed plist
// parses unchanged.
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	provider, name := ProviderLima, s
	if p, n, ok := strings.Cut(s, ":"); ok {
		provider, name = strings.TrimSpace(p), strings.TrimSpace(n)
	}
	switch provider {
	case ProviderLima, ProviderColima, ProviderPodman:
	default:
		return Ref{}, fmt.Errorf("unknown VM provider %q in %q: want %s:, %s: or %s: (a bare name means a Lima instance)",
			provider, s, ProviderLima, ProviderColima, ProviderPodman)
	}
	if !instanceNameRE.MatchString(name) || len(name) > maxNameLen {
		return Ref{}, fmt.Errorf("invalid %s instance name %q in %q: expected letters, digits, '.', '_' or '-'", provider, name, s)
	}

	r := Ref{Provider: provider, Instance: name, Spec: s}
	if provider == ProviderColima {
		r.Instance = ColimaInstance(name)
		r.LimaHome = ColimaHome()
	}
	r.LeaseName = LeaseName(r.Provider, r.Instance)
	return r, nil
}

// ColimaInstance maps a colima profile to the Lima instance colima creates
// for it: the `default` profile is `colima`, any other is `colima-<profile>`.
//
// A name that already spells the instance maps to itself, so `colima:default`
// and `colima:colima` are the same VM. Both spellings are in circulation —
// `colima start -p work` talks about profiles, while limactl, the instance
// directory and the DHCP lease record all say `colima-work` — and a user who
// pastes the name they can see should not land on a VM that does not exist.
func ColimaInstance(profile string) string {
	switch {
	case profile == "" || profile == "default":
		return "colima"
	case profile == "colima" || strings.HasPrefix(profile, "colima-"):
		return profile
	default:
		return "colima-" + profile
	}
}

// LeaseName is the DHCP record name a guest of this provider claims.
//
// The record's name is DHCP option 12 — the guest's *hostname* — so this is
// per-provider and not Lima arithmetic:
//
//   - lima: the default guest hostname is `lima-<instance>`.
//   - colima: colima's own cloud-init sets the hostname to the instance
//     name, so the record is `colima` / `colima-<profile>` with no prefix.
//
// Do not be tempted by the `hostname` field of `limactl list --json`. For a
// colima instance Lima reports `lima-colima` there while the guest actually
// answers `colima` and writes `name=colima` into the lease db (observed on
// colima 0.10.3 / lima 2.2.0): that field is Lima's expectation, not the
// guest's behaviour, and the two disagree exactly where it matters.
//
// Verified live for colima's default profile. The `colima-<profile>` form
// follows from the same hostname-equals-instance-name rule but has not been
// observed — see docs/verify-colima.md, which asks whoever next runs the
// recipe with a named profile to confirm it.
//
// Being the guest's own choice, this is a *match key* and never evidence of
// identity — and, for the same reason, a model of a default rather than a
// guarantee: a user who sets a hostname by hand invalidates it. What makes a
// matched record trustworthy is the subnet gate and the MAC pin in
// internal/limaaddr/leases.go.
//
//   - podman: the empty string. A podman machine's networking is gvproxy,
//     which is user-mode and writes no vmnet DHCP lease at all, so there is
//     no record to match and nothing for limaaddr to resolve. Resolution for
//     podman goes through internal/podmanaddr instead (docs/podman.md §3.2);
//     the empty name is the statement that a podman ref has no business
//     reaching the lease db, and the dispatch that keeps it out is pinned by
//     a test in cmd/drawbridged.
func LeaseName(provider, instance string) string {
	switch provider {
	case ProviderColima:
		return instance
	case ProviderPodman:
		return ""
	default:
		return "lima-" + instance
	}
}

// LimaHome is Lima's own state directory: $LIMA_HOME when set, else
// ~/.lima. Empty when neither can be determined.
func LimaHome() string {
	if h := strings.TrimSpace(os.Getenv("LIMA_HOME")); h != "" {
		return h
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".lima")
}

// limaSubdir is the directory colima keeps its Lima state in, under whichever
// config directory it settled on.
const limaSubdir = "_lima"

// ColimaHome discovers colima's LIMA_HOME. Discovery, not a constant, because
// colima moved the directory: v0.9 switched from ~/.colima to
// $XDG_CONFIG_HOME/colima (default ~/.config/colima), so a hardcoded legacy
// path finds nothing on a current install — and "nothing" here is silent, it
// degrades to lease-db-only resolution, which is the exact failure the
// LIMA_HOME parameter was added to prevent.
//
// Precedence, matching colima 0.10's own (its binary carries the strings
// "found ~/.colima, ignoring $XDG_CONFIG_HOME..." and "delete ~/.colima to
// use $XDG_CONFIG_HOME as config directory" — so the legacy directory wins
// when it exists, and an upgraded install keeps working):
//
//  1. $COLIMA_HOME/_lima. Older colima honoured the variable; 0.10 appears
//     not to. Honouring it only when that directory actually exists is right
//     under either reading, and a stale value falls through instead of
//     winning.
//  2. ~/.colima/_lima — the legacy layout.
//  3. $XDG_CONFIG_HOME/colima/_lima (default ~/.config/colima/_lima).
//
// Every step is existence-gated, so the answer is a directory that is really
// there. With none of them present the XDG default is returned rather than
// "": it is what a current colima will create, and every caller either gates
// on existence (Detect) or degrades safely — limactl simply reports no such
// instance, and the root daemon never runs limactl at all.
//
// Unlike LimaHome this ignores $LIMA_HOME: colima sets that variable itself
// when it invokes limactl, so inheriting a user's value would point us at the
// wrong instance set.
func ColimaHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return colimaHome(home)
}

// colimaHome is ColimaHome with the home directory injected, so the
// precedence can be tested against a fake layout instead of the tester's own
// machine.
func colimaHome(home string) string {
	xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if xdg == "" && home != "" {
		xdg = filepath.Join(home, ".config")
	}
	var xdgHome string
	if xdg != "" {
		xdgHome = filepath.Join(xdg, "colima", limaSubdir)
	}

	var candidates []string
	if v := strings.TrimSpace(os.Getenv("COLIMA_HOME")); v != "" {
		candidates = append(candidates, filepath.Join(v, limaSubdir))
	}
	if home != "" {
		candidates = append(candidates, filepath.Join(home, ".colima", limaSubdir))
	}
	if xdgHome != "" {
		candidates = append(candidates, xdgHome)
	}
	for _, c := range candidates {
		if dirExists(c) {
			return c
		}
	}
	// Empty only when there is no home *and* no $XDG_CONFIG_HOME, which is
	// not an error: the root daemon does not use limactl, and an empty
	// LimaHome is exactly "use the ambient environment".
	return xdgHome
}

// Detect returns a provider for every state directory that exists on this
// Mac, Lima first.
//
// Presence of the directory — not of a running instance — is the test: an
// installed-but-stopped provider still has instances worth listing, and List
// reports Running per instance. A Mac with neither gets an empty slice,
// which is the "no candidate VM" case the attach path prints creation
// instructions for.
// Podman adds a second gate: the binary. Its machine directory can outlive
// an uninstalled podman, and listing instances no command can reach would
// turn a leftover directory into a menu of VMs that cannot be attached.
func Detect() []Provider {
	var out []Provider
	if dirExists(LimaHome()) {
		out = append(out, NewLima())
	}
	if dirExists(ColimaHome()) {
		out = append(out, NewColima())
	}
	if _, err := PodmanBin(); err == nil && dirExists(PodmanMachineDir()) {
		out = append(out, NewPodman())
	}
	return out
}

// ForRef returns the driver a parsed -vm value names.
func ForRef(r Ref) Provider {
	if r.Provider == ProviderPodman {
		return NewPodman()
	}
	return NewLimaHome(r.Provider, r.LimaHome)
}

func dirExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
