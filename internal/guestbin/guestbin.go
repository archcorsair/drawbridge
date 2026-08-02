// Package guestbin carries everything `drawbridge up` has to put inside a
// guest: the two Linux binaries (agent and runc wrapper) for both
// architectures, the systemd unit that supervises the agent, and the
// provisioning script the `--oci` path runs (docs/ergonomics.md §2.2, §4.3).
//
// Embedding, and its build ordering, is the whole point. The CLI a user
// installs from a release archive must be able to provision a guest with no
// network and no second download, and the agent it provisions has to be the
// one that matches the CLI — that is the entire version-skew policy (§6),
// achieved by construction rather than by negotiation.
//
// The cost is that `go build ./cmd/drawbridge` now depends on artifacts a
// plain `go build` does not produce. Two mechanisms keep a fresh checkout
// buildable:
//
//   - the embed pattern is `all:bin` over a directory holding a committed
//     `.keep`, so the pattern always matches something. A bare `//go:embed
//     bin` would fail to compile on a checkout where the binaries have not
//     been built yet (embed skips dot-prefixed files, so the directory would
//     read as empty), and `//go:embed bin/agent_linux_arm64` would fail
//     outright.
//   - a missing binary is ErrNotBundled — a typed, printable diagnosis —
//     not a compile error and not a panic. `drawbridge up` from a dev build
//     therefore *runs*, and says what to do about it.
//
// `just build` populates bin/; its contents are gitignored.
package guestbin

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"text/template"

	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// ErrNotBundled is what a dev build of the CLI has instead of guest
// binaries. Its text is the remedy, because that is all the user can do with
// it — the same discipline internal/install.ErrNeedRoot follows.
var ErrNotBundled = errors.New("dev build without bundled agent — run `just build` first or pass `-agent-bin`")

// The two guest binaries, by role. These are the `name` half of Binary and
// the basenames the guest ends up with under /usr/local/bin.
const (
	NameAgent = "agent"
	NameRunc  = "runc"
)

// GuestPath is where a role's binary lives in the guest. /usr/local/bin
// rather than /usr/bin: it is the sanctioned local-admin location, it is on
// root's PATH under systemd, and it is not managed by the guest's package
// manager, so an apt upgrade can neither replace nor remove what we put
// there.
func GuestPath(name string) string {
	return "/usr/local/bin/drawbridge-" + name
}

// Arch maps a guest's `uname -m` to the GOARCH half of a bundled binary's
// name.
//
// The guest's own answer is the input on purpose (vmprovider.GuestArch runs
// `uname -m` inside the VM, not on the Mac): a vz guest normally matches the
// host, but Rosetta guests and amd64 images on Apple silicon both exist, and
// the binary has to match what will actually execute.
func Arch(unameM string) (string, error) {
	switch strings.TrimSpace(unameM) {
	case "aarch64", "arm64":
		return "arm64", nil
	case "x86_64", "amd64":
		return "amd64", nil
	default:
		return "", fmt.Errorf("unsupported guest architecture %q: drawbridge ships linux/arm64 and linux/amd64", strings.TrimSpace(unameM))
	}
}

// Binary returns the bundled binary for one role and architecture.
//
// A dev build — or a release that somehow shipped without the artifact —
// gets ErrNotBundled wrapped with which artifact was missing, so the message
// names the gap rather than describing it in general.
func Binary(name, arch string) ([]byte, error) {
	switch name {
	case NameAgent, NameRunc:
	default:
		return nil, fmt.Errorf("guestbin: unknown binary %q (want %q or %q)", name, NameAgent, NameRunc)
	}
	file := path.Join("bin", fmt.Sprintf("%s_linux_%s", name, arch))
	b, err := bundled.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s (%s): %w", file, err, ErrNotBundled)
	case err != nil:
		return nil, err
	case len(b) == 0:
		// A zero-length placeholder is the shape a half-finished build
		// leaves behind. Treating it as present would push the failure into
		// the guest as an exec format error, which diagnoses nothing.
		return nil, fmt.Errorf("%s is empty: %w", file, ErrNotBundled)
	}
	return b, nil
}

// Bundled reports whether this build carries guest binaries at all. `up`
// uses it to decide whether an -agent-bin override is required rather than
// optional, so the diagnosis arrives before any guest is touched.
func Bundled() bool {
	_, err := Binary(NameAgent, "arm64")
	if errors.Is(err, ErrNotBundled) {
		_, err = Binary(NameAgent, "amd64")
	}
	return !errors.Is(err, ErrNotBundled)
}

// UnitName is the systemd unit `up` installs, and the one `just agent-up`
// runs transiently. They share a name deliberately: two units supervising
// the same binary would fight over the same BPF attachments and the same
// transport port, and sharing the name makes the collision impossible to
// miss (`systemctl` refuses, or one replaces the other) instead of silently
// doubling the agent.
const UnitName = "drawbridge-agent.service"

// UnitPath is where the persistent unit is installed. /etc/systemd/system
// rather than /usr/lib/systemd/system: this is local admin configuration,
// and it is the directory `systemctl edit` and every guest's own tooling
// expect to find a hand-installed unit in.
const UnitPath = "/etc/systemd/system/" + UnitName

// StateDir is where `up` records what it changed in the guest, so `down`
// reverts exactly that and never guesses. ProvisionPath is the `--oci`
// half — see provision.go.
const (
	StateDir      = "/etc/drawbridge"
	ProvisionPath = StateDir + "/provision.json"

	// SecretPath is the guest half of the transport secret (0600 root:root,
	// docs/transport-auth.md §5). It is the agent's -secret-file default,
	// which is why the constant lives in transportauth — the agent links
	// that package and must not link this one, which embeds guest binaries.
	// `down` removes StateDir wholesale, so the secret needs no teardown
	// code of its own.
	SecretPath = transportauth.GuestPath
)

// ProvisionScriptPath is where the embedded provisioning script is staged in
// the guest before it runs. /tmp, not a persistent path: it is an artifact
// of one `up`, and leaving a copy behind would be a file `down` has to know
// about.
const ProvisionScriptPath = "/tmp/drawbridge-provision-docker.sh"

// unitTmpl renders the unit. Only the binary path is substituted — the
// supervision policy is not configurable, because a user who needs a
// different one needs `systemctl edit`, which is exactly what installing to
// /etc/systemd/system enables.
var unitTmpl = template.Must(template.New("unit").Parse(mustAsset("assets/drawbridge-agent.service")))

// Unit renders the agent unit for a binary path.
func Unit(binPath string) (string, error) {
	var sb strings.Builder
	if err := unitTmpl.Execute(&sb, struct{ ExecStart string }{binPath}); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// ProvisionScript is the guest-side OCI provisioning script — the same file
// `just vm-docker` runs through scripts/provision-docker.sh, so the two
// paths cannot drift in what they install or how they restart docker.
//
// What it deliberately does *not* do is edit /etc/docker/daemon.json: that
// is provision.go's job, on the Mac, in Go. See the comment there.
func ProvisionScript() string { return mustAsset("assets/provision-docker.sh") }

func mustAsset(name string) string {
	b, err := assets.ReadFile(name)
	if err != nil {
		panic("guestbin: missing committed asset " + name + ": " + err.Error())
	}
	return string(b)
}
