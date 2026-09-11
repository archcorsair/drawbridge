package main

// The guest-side half of `up` and `down`: choosing which VM to attach to,
// and the handful of shell primitives everything else is built from
// (docs/ergonomics.md §4).
//
// Two rules shape all of it:
//
//   - Nothing here runs as root on the Mac. `up` is explicitly no-sudo:
//     vmprovider's limactl half refuses euid 0, and every privileged action
//     happens *inside* the guest, where `sudo` is the guest's own.
//   - The failure posture is "nothing changed" (§4.2). Every mutation is
//     preceded by the preflight that would have caught it, and each step
//     reports a diagnosis rather than an exec error.

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// guest is one VM, addressed through its provider.
type guest struct {
	p    vmprovider.Provider
	inst string
	out  io.Writer

	// relabel is set from the preflight when the guest has `restorecon`,
	// i.e. when it is SELinux-managed (Fedora CoreOS, the podman machine
	// image, runs Enforcing). Every file we install then gets its label
	// restored; on a guest without it, nothing is attempted and no round
	// trip is spent (docs/podman.md §5.2).
	relabel bool
}

// Every invocation below passes its argv as single, space-free words and
// puts anything with structure on stdin.
//
// Not because lima mis-handles quoting — 2.2.0 verifiably round-trips a
// multi-word `sh -c '<script>'` argv intact (tested live 2026-07-31) — but
// because this package's guest calls must survive *any* provider shell,
// including versions and providers we have not met. A script on stdin has
// no argv words to lose, so it cannot depend on the shell-quoting behavior
// of the transport that carries it. The fakeguest tests enforce the
// convention so a future call cannot quietly start depending on one
// provider's quoting.

// shRaw runs a script in the guest and returns its stdout untouched.
func (g *guest) shRaw(script string) ([]byte, error) {
	return g.p.Shell(g.inst, strings.NewReader(script), "sh")
}

// sh runs a script and returns its trimmed stdout. Used where the
// alternative is several round trips: every `limactl shell` is a fresh ssh
// session, and the preflight in particular is one exchange rather than six.
func (g *guest) sh(script string) (string, error) {
	out, err := g.shRaw(script)
	return strings.TrimRight(string(out), "\n"), err
}

// sudoSh runs a script as root in the guest. `-n` because there is no
// terminal to prompt on: a guest without passwordless sudo has to fail here
// rather than hang, and the preflight already says so in words.
func (g *guest) sudoSh(script string) (string, error) {
	out, err := g.p.Shell(g.inst, strings.NewReader(script), "sudo", "-n", "sh")
	return strings.TrimRight(string(out), "\n"), err
}

// try runs a script as root and swallows failure, for steps whose failure
// mode is "it was already not there". Idempotent teardown is built out of
// these; anything whose failure matters uses sudoSh.
func (g *guest) try(script string) {
	_, _ = g.sudoSh(script + " >/dev/null 2>&1 || true")
}

// stage streams data into a guest path. It is the only way in: there is no
// shared filesystem with an arbitrary user's VM, and a base64-in-argv hack
// would hit ARG_MAX at a fraction of the agent's size.
//
// `dd of=…` rather than a redirect because stdin is carrying the payload, so
// the destination has to be expressed in argv — and `of=<path>` is one word,
// which is the only shape that survives lima's argv joining.
func (g *guest) stage(data []byte, path string) error {
	if strings.ContainsAny(path, " \t\n'\"\\$") {
		// Every staging path is a constant in this package; this is here so
		// that stops being true loudly rather than silently.
		return fmt.Errorf("guest path %q needs quoting, which argv to `limactl shell` cannot express", path)
	}
	if _, err := g.p.Shell(g.inst, bytes.NewReader(data), "dd", "of="+path, "status=none"); err != nil {
		return fmt.Errorf("staging %s in the guest: %w", path, err)
	}
	return nil
}

// installFile moves a staged file into place as root, atomically.
//
// The rename is not decoration. `install` opens its destination with
// O_TRUNC, and truncating a binary that is currently executing fails with
// ETXTBSY — which is exactly the state /usr/local/bin/drawbridge-agent is in
// on every re-run of `up`. Writing beside the target and renaming over it
// works while the old binary runs, and is atomic, so a failure mid-copy
// leaves the running agent's file intact (§4.2).
func (g *guest) installFile(staged, dst, mode string) error {
	tmp := dst + ".drawbridge-new"
	script := fmt.Sprintf("install -m %s -o root -g root %s %s && mv -f %s %s",
		mode, shquote(staged), shquote(tmp), shquote(tmp), shquote(dst))
	if _, err := g.sudoSh(script); err != nil {
		return fmt.Errorf("installing %s in the guest: %w", dst, err)
	}
	g.relabelPath(dst)
	return nil
}

// relabelPath restores a staged file's SELinux label.
//
// The install-beside-then-rename already gives the new file the destination
// directory's type, which is why this is a belt-and-braces step rather than
// the thing that makes the file work, but /tmp staging and a policy that
// distinguishes `bin_t` from `user_tmp_t` are exactly the pair that produces
// an executable systemd refuses to run, with an AVC denial as the only clue.
//
// A separate invocation rather than a link in installFile's `&&` chain: a
// tolerant tail (`|| true`) on that chain would make the install itself
// tolerant, and the install failing is not something to swallow.
func (g *guest) relabelPath(dst string) {
	if !g.relabel {
		return
	}
	g.try("restorecon -F " + shquote(dst))
}

// sha256 reads a guest file's digest, empty when the file is absent. This is
// what makes a re-run of `up` cheap: an unchanged binary is never streamed.
func (g *guest) sha256(path string) (string, error) {
	out, err := g.sh("sha256sum " + shquote(path) + " 2>/dev/null | cut -d' ' -f1")
	if err != nil {
		// sha256sum failing on a missing file is not an error we report:
		// `|| true` semantics are baked in by the pipe, so a real error here
		// is the shell itself failing.
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// sudoSha256 is sha256 for a file only root can read — the transport secret
// is 0600 root:root. The digest, not the contents, crosses back: a digest of
// 32 random bytes tells an observer nothing, which is what makes comparing
// them an acceptable substitute for reading the file (docs/transport-auth.md
// §5).
func (g *guest) sudoSha256(path string) (string, error) {
	out, err := g.sudoSh("sha256sum " + shquote(path) + " 2>/dev/null | cut -d' ' -f1")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// readFile returns a guest file's contents, and false when it does not
// exist. The distinction is load-bearing for daemon.json: "absent" and
// "empty" revert differently (internal/guestbin/provision.go).
// It reads the bytes *exactly*: no trimming, unlike every other helper here.
// daemon.json's revert compares a sha256 of what `up` wrote against what is
// on disk, and a swallowed trailing newline turns every exact restore into a
// surgical one — silently, and only visible as a reformatted config file.
// The unit-file comparison has the same sensitivity.
func (g *guest) readFile(path string) ([]byte, bool, error) {
	// The marker line is how presence survives a command whose stdout is
	// otherwise indistinguishable from an empty file.
	out, err := g.shRaw("if [ -e " + shquote(path) + " ]; then echo present; cat " + shquote(path) + "; else echo absent; fi")
	if err != nil {
		return nil, false, fmt.Errorf("reading %s from the guest: %w", path, err)
	}
	marker, rest, _ := strings.Cut(string(out), "\n")
	switch strings.TrimSpace(marker) {
	case "absent":
		return nil, false, nil
	case "present":
		return []byte(rest), true, nil
	default:
		return nil, false, fmt.Errorf("reading %s from the guest: unexpected output %q", path, out)
	}
}

// writeFile stages content and installs it as root in one step.
func (g *guest) writeFile(data []byte, dst, mode string) error {
	staged := "/tmp/drawbridge-stage-" + sanitizeName(dst)
	if err := g.stage(data, staged); err != nil {
		return err
	}
	defer g.try("rm -f " + shquote(staged))
	// The destination's directory may not exist yet (/etc/drawbridge on a
	// first run); creating it here keeps the caller from having to know.
	if _, err := g.sudoSh("mkdir -p " + shquote(parentDir(dst))); err != nil {
		return fmt.Errorf("creating %s in the guest: %w", parentDir(dst), err)
	}
	return g.installFile(staged, dst, mode)
}

func parentDir(p string) string {
	if i := strings.LastIndex(p, "/"); i > 0 {
		return p[:i]
	}
	return "/"
}

// sanitizeName turns a path into a staging basename. Not a security control
// — shquote is — just a way to keep concurrent `up` runs against different
// paths from colliding in /tmp.
func sanitizeName(p string) string {
	return strings.Trim(strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '-'
		}
	}, p), "-")
}

// shquote single-quotes a value for the guest shell. Every path we pass is
// one we chose, but they are interpolated into `sh -c` strings, and a
// constant that grows a space later is not the kind of thing to leave to
// review.
func shquote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ---------------------------------------------------------------------------
// Instance selection (§4.1 step 1)
// ---------------------------------------------------------------------------

// selection is a chosen VM: the Ref that names it in the grammar the user
// types (and that `drawbridge install -vm` takes back), plus what the
// provider reported about it.
type selection struct {
	Ref      vmprovider.Ref
	Instance vmprovider.Instance
}

// listAll enumerates every instance every detected provider knows about.
//
// A provider that fails to list is reported, not fatal: a broken colima
// install must not stop a user attaching to their Lima VM, and the reverse.
func listAll(providers []vmprovider.Provider, out io.Writer) []vmprovider.Instance {
	var all []vmprovider.Instance
	for _, p := range providers {
		insts, err := p.List()
		if err != nil {
			fmt.Fprintf(out, "drawbridge: warning: listing instances failed: %v\n", err)
			continue
		}
		all = append(all, insts...)
	}
	return all
}

// eligible is the set `up` can attach to: running, and attachable. Both
// halves are hard requirements, a stopped VM has no guest to provision, and
// a machine type with no path from the Mac has nothing to attach over (§3.1).
//
// Attachability is the provider's verdict, not this package's: "vz" is Lima
// vocabulary and means nothing to podman, whose libkrun and applehv machines
// are reached through gvproxy instead (docs/podman.md §4.2).
func eligible(insts []vmprovider.Instance) []vmprovider.Instance {
	var out []vmprovider.Instance
	for _, i := range insts {
		if i.Running && i.Attachable {
			out = append(out, i)
		}
	}
	return out
}

// pickInstance is the whole of §4.1 step 1, as a pure function over what the
// providers reported — the part worth a table test, since every branch of it
// is a message a user will read on their first run.
//
// `arg` takes the same grammar as -vm: `provider:name` selects explicitly, a
// bare name is resolved across providers and is an error when two providers
// both have it. That last case is not hypothetical — `colima` is a perfectly
// legal Lima instance name, and Phase 3 pinned the hazard from the lease-db
// side (TestLeaseNameNamespacesDoNotCross).
func pickInstance(arg string, insts []vmprovider.Instance) (selection, error) {
	if strings.TrimSpace(arg) == "" {
		return pickImplicit(insts)
	}
	match, err := matchNamed(arg, insts)
	if err != nil {
		return selection{}, err
	}
	if !match.Running {
		return selection{}, fmt.Errorf("%s is not running — start it first:\n  %s", qualify(match), startHint(match))
	}
	if !match.Attachable {
		return selection{}, notAttachableError(match)
	}
	ref, err := refFor(match)
	if err != nil {
		return selection{}, err
	}
	// The user's own spelling is what gets echoed back in the next-step line
	// and what they will paste into `drawbridge install -vm`.
	ref.Spec = strings.TrimSpace(arg)
	return selection{Ref: ref, Instance: match}, nil
}

func pickImplicit(insts []vmprovider.Instance) (selection, error) {
	ok := eligible(insts)
	switch len(ok) {
	case 0:
		return selection{}, noCandidateError(insts)
	case 1:
		ref, err := refFor(ok[0])
		if err != nil {
			return selection{}, err
		}
		return selection{Ref: ref, Instance: ok[0]}, nil
	}
	var sb strings.Builder
	sb.WriteString("several VMs could be attached to — name one:\n")
	for _, i := range ok {
		fmt.Fprintf(&sb, "  drawbridge up %s\n", qualify(i))
	}
	// No prompt, deliberately: `up` has to be scriptable, and a CLI that
	// blocks on a menu is a CLI that hangs in CI.
	sb.WriteString("(no prompt: `up` is scriptable)")
	return selection{}, fmt.Errorf("%s", sb.String())
}

// matchNamed resolves an instance argument against what the providers
// reported.
func matchNamed(arg string, insts []vmprovider.Instance) (vmprovider.Instance, error) {
	arg = strings.TrimSpace(arg)
	if _, _, qualified := strings.Cut(arg, ":"); qualified {
		ref, err := vmprovider.ParseRef(arg)
		if err != nil {
			return vmprovider.Instance{}, err
		}
		for _, i := range insts {
			if i.Provider == ref.Provider && i.Name == ref.Instance {
				return i, nil
			}
		}
		return vmprovider.Instance{}, fmt.Errorf("no %s instance named %q%s", ref.Provider, ref.Instance, knownList(insts))
	}

	// A bare name. Validate it through the same grammar so a malformed one
	// fails identically whether or not the provider was spelled out, then
	// look for it everywhere.
	if _, err := vmprovider.ParseRef(arg); err != nil {
		return vmprovider.Instance{}, err
	}
	var hits []vmprovider.Instance
	for _, i := range insts {
		if i.Name == arg || (i.Provider == vmprovider.ProviderColima && i.Name == vmprovider.ColimaInstance(arg)) {
			hits = append(hits, i)
		}
	}
	switch len(hits) {
	case 0:
		return vmprovider.Instance{}, fmt.Errorf("no VM named %q%s", arg, knownList(insts))
	case 1:
		return hits[0], nil
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%q is ambiguous — %d providers have an instance by that name:\n", arg, len(hits))
	for _, i := range hits {
		fmt.Fprintf(&sb, "  drawbridge up %s\n", qualify(i))
	}
	sb.WriteString("(a bare name is resolved across providers; qualify it)")
	return vmprovider.Instance{}, fmt.Errorf("%s", sb.String())
}

// refFor turns a discovered instance back into a Ref by going through the
// same parser a typed -vm value takes, so discovery and the command line
// cannot produce different lease names or LIMA_HOMEs for the same VM.
func refFor(i vmprovider.Instance) (vmprovider.Ref, error) {
	return vmprovider.ParseRef(qualify(i))
}

// qualify is an instance's canonical `provider:name` spelling — the form
// every message uses, because it is the form `drawbridge install -vm` takes.
func qualify(i vmprovider.Instance) string { return i.Provider + ":" + i.Name }

func knownList(insts []vmprovider.Instance) string {
	if len(insts) == 0 {
		return " (no Lima, Colima or Podman VMs found on this Mac)"
	}
	names := make([]string, 0, len(insts))
	for _, i := range insts {
		state := "stopped"
		if i.Running {
			state = "running"
		}
		names = append(names, fmt.Sprintf("%s (%s, %s)", qualify(i), i.VMType, state))
	}
	return ". Known: " + strings.Join(names, ", ")
}

// noCandidateError is the first-run message: what to create, spelled per
// provider, and never a prompt to create it for them. `up` is attach-only
// (§4.1) — creating a VM decides CPU, memory, disk and image on a user's
// behalf, none of which drawbridge has any business deciding.
func noCandidateError(insts []vmprovider.Instance) error {
	var sb strings.Builder
	sb.WriteString("no running VM to attach to.\n")

	var stopped, unattachable []vmprovider.Instance
	for _, i := range insts {
		switch {
		case !i.Attachable:
			unattachable = append(unattachable, i)
		case !i.Running:
			stopped = append(stopped, i)
		}
	}
	for _, i := range stopped {
		fmt.Fprintf(&sb, "\n%s exists but is stopped:\n  %s\n", qualify(i), startHint(i))
	}
	for _, i := range unattachable {
		fmt.Fprintf(&sb, "\n%s\n", attachRefusal(i))
	}
	if len(stopped) == 0 && len(unattachable) == 0 {
		sb.WriteString("\nCreate one, then re-run `drawbridge up`:\n" +
			"  colima start --vm-type vz --cpu 4 --memory 8      # Colima (Docker CLI included)\n" +
			"  limactl start --vm-type vz template://ubuntu-lts  # Lima\n" +
			"  podman machine init --now                         # Podman\n")
	}
	return fmt.Errorf("%s", strings.TrimRight(sb.String(), "\n"))
}

// attachRefusal is the one-instance form printed in the candidate list: what
// is wrong with this VM, and the command that would fix it.
//
// Lima and Colima keep their exact wording. A qemu instance is the case this
// text was written for, and it has been in front of users since Phase 3.
func attachRefusal(i vmprovider.Instance) string {
	if i.Provider == vmprovider.ProviderPodman {
		return fmt.Sprintf("%s: %s\n  %s", qualify(i), i.AttachNote, podmanSwitchHint(i))
	}
	return fmt.Sprintf("%s runs on %s, which has no host-reachable guest IP (user-mode networking):\n  %s",
		qualify(i), i.VMType, vzSwitchHint(i))
}

// notAttachableError is the named-instance form: the user asked for this VM
// by name, so the refusal leads with what it runs on.
func notAttachableError(i vmprovider.Instance) error {
	if i.Provider == vmprovider.ProviderPodman {
		return fmt.Errorf("%s: %s.\n  %s", qualify(i), i.AttachNote, podmanSwitchHint(i))
	}
	return vzSwitchError(i)
}

// podmanSwitchHint recreates the machine on a provider drawbridge attaches
// to. Both macOS providers work, so this is only ever reached by a machine
// created on something else (a qemu machine carried over from Linux).
func podmanSwitchHint(i vmprovider.Instance) string {
	return fmt.Sprintf("podman machine rm %s && podman machine init --now %s", i.Name, i.Name)
}

// vzSwitchError is the §3.1 rejection for a qemu instance. qemu's user-mode
// stack gives the guest no address the Mac can dial and writes no DHCP lease
// record, so neither of the transport's two resolution sources exists —
// there is nothing to degrade to.
func vzSwitchError(i vmprovider.Instance) error {
	return fmt.Errorf("%s runs on %s, not vz.\n"+
		"  drawbridge needs a host-reachable guest IP; qemu's user-mode networking has none.\n"+
		"  %s", qualify(i), i.VMType, vzSwitchHint(i))
}

func vzSwitchHint(i vmprovider.Instance) string {
	if i.Provider == vmprovider.ProviderColima {
		profile := strings.TrimPrefix(i.Name, "colima-")
		if profile == "colima" {
			return "colima stop && colima start --vm-type vz"
		}
		return fmt.Sprintf("colima stop -p %s && colima start -p %s --vm-type vz", profile, profile)
	}
	return fmt.Sprintf("limactl stop %s && limactl edit %s   # set vmType: vz, then: limactl start %s", i.Name, i.Name, i.Name)
}

func startHint(i vmprovider.Instance) string {
	if i.Provider == vmprovider.ProviderPodman {
		return "podman machine start " + i.Name
	}
	if i.Provider == vmprovider.ProviderColima {
		profile := strings.TrimPrefix(i.Name, "colima-")
		if profile == "colima" {
			return "colima start"
		}
		return "colima start -p " + profile
	}
	return "limactl start " + i.Name
}

// ---------------------------------------------------------------------------
// Preflight (§4.1 step 2)
// ---------------------------------------------------------------------------

// preflight is what one round trip into the guest learns about it. Field
// names match the keys the probe script emits.
type preflight struct {
	Arch    string
	Kernel  string
	BTF     bool
	CGroup2 bool
	Systemd bool
	Sudo    bool

	// Engine is the container engine that is actually there: EngineDocker,
	// EnginePodman or EngineNone.
	//
	// It replaced a bare `command -v docker`, which is wrong on exactly the
	// guest this phase adds: the podman machine image symlinks
	// /usr/local/bin/docker to podman, so `command -v docker` succeeds on a
	// guest with no Docker Engine anywhere (docs/podman.md §5.1).
	Engine string

	// Rootful reports an in-guest podman running as root (the root
	// podman.socket is present). Recorded rather than acted on in this phase:
	// it is what decides the `--oci` socket-ownership contract in 7.4.
	Rootful bool

	// SELinux is `getenforce`: Enforcing, Permissive, Disabled, or "" on a
	// guest with no SELinux at all. Restorecon says whether labels can be
	// restored, which is the half `up` acts on.
	SELinux    string
	Restorecon bool

	// OSTree marks an rpm-ostree guest (Fedora CoreOS). /usr is read-only
	// there; /usr/local is a symlink into /var and is what we write to.
	OSTree bool

	// Crun is `crun --version`'s version field, empty when absent, and
	// CrunPath is where `command -v crun` finds it. The `--oci` path needs
	// >= 0.19 for the seccomp notify listener, and the path is the fallback
	// entry in the containers.conf drop-in (docs/podman.md §6.2).
	//
	// `command -v crun` rather than `podman info`'s OCIRuntime.Path, which
	// is the acceptance line and not a source: after the first `up --oci`
	// podman reports the *wrapper* there, so a second run would render a
	// drop-in whose fallback pointed at drawbridge-crun itself. The wrapper
	// is never installed under the bare name `crun`, so this probe cannot
	// find it whatever has been provisioned.
	Crun     string
	CrunPath string

	// ContainersFS is the filesystem type carrying /etc/containers.
	//
	// It exists because of a live finding, not a design decision: a podman
	// machine mounts the *Mac's* ~/.config/containers there over virtiofs
	// (an `etc-containers.mount` unit in the image), so the drop-in `up
	// --oci` writes "in the guest" is a file on the Mac, shared by every
	// podman machine and read by the Mac's own podman client. Nothing about
	// what is written changes; what changes is what `up` has to say about
	// it (docs/podman.md §7.4 results).
	ContainersFS string

	// User is the login user the provider shells in as — `core` on a podman
	// machine — and therefore the uid a rootless engine's runtime runs as.
	// It is what `-oci-sock-owner` is set from (docs/podman.md §6.3).
	User string

	// UnprivPort is net.ipv4.ip_unprivileged_port_start, "" when unreadable.
	// It decides whether a rootless container can bind :80 at all, long
	// before drawbridge is involved.
	UnprivPort string
}

// The engines the preflight can find. Spelled once, in guestbin, because the
// wrapper's installed name turns on them (guestbin.WrapperPath).
const (
	EngineNone   = guestbin.EngineNone
	EngineDocker = guestbin.EngineDocker
	EnginePodman = guestbin.EnginePodman
)

// probeScript asks every question at once. Six `limactl shell` invocations
// would be six ssh sessions; the answers are independent, so there is
// nothing to gain from asking them one at a time and a visible pause to lose.
const probeScript = `
echo "arch=$(uname -m)"
echo "kernel=$(uname -r)"
[ -r /sys/kernel/btf/vmlinux ] && echo btf=yes || echo btf=no
[ -e /sys/fs/cgroup/cgroup.controllers ] && echo cgroup2=yes || echo cgroup2=no
command -v systemctl >/dev/null 2>&1 && echo systemd=yes || echo systemd=no
sudo -n true >/dev/null 2>&1 && echo sudo=yes || echo sudo=no
command -v restorecon >/dev/null 2>&1 && echo restorecon=yes || echo restorecon=no
[ -e /run/ostree-booted ] && echo ostree=yes || echo ostree=no
echo "selinux=$(getenforce 2>/dev/null || true)"
echo "crun=$(crun --version 2>/dev/null | head -1 | awk '{print $3}')"
echo "crun_path=$(command -v crun 2>/dev/null || true)"
echo "containers_fs=$(findmnt -no FSTYPE --target /etc/containers 2>/dev/null || true)"
echo "user=$(id -un 2>/dev/null || true)"
echo "unpriv_port=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || true)"
[ -S /run/podman/podman.sock ] && echo rootful=yes || echo rootful=no
engine=none
db_docker=$(command -v docker 2>/dev/null || true)
if [ -n "$db_docker" ]; then
  db_real=$(readlink -f "$db_docker" 2>/dev/null || echo "$db_docker")
  case "$db_real" in
    */podman) engine=podman ;;
    *) if command -v dockerd >/dev/null 2>&1 || systemctl cat docker.service >/dev/null 2>&1; then engine=docker; fi ;;
  esac
fi
if [ "$engine" = none ] && command -v podman >/dev/null 2>&1; then engine=podman; fi
echo "engine=$engine"
`

func (g *guest) probe() (preflight, error) {
	out, err := g.sh(probeScript)
	if err != nil {
		return preflight{}, fmt.Errorf("probing the guest: %w", err)
	}
	return parsePreflight(out), nil
}

// parsePreflight reads the probe output. Unknown keys are ignored so a newer
// probe script against an older parse is a missing check, not a crash.
func parsePreflight(out string) preflight {
	var p preflight
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		yes := v == "yes"
		switch k {
		case "arch":
			p.Arch = v
		case "kernel":
			p.Kernel = v
		case "btf":
			p.BTF = yes
		case "cgroup2":
			p.CGroup2 = yes
		case "systemd":
			p.Systemd = yes
		case "sudo":
			p.Sudo = yes
		case "engine":
			p.Engine = v
		case "rootful":
			p.Rootful = yes
		case "selinux":
			p.SELinux = v
		case "restorecon":
			p.Restorecon = yes
		case "ostree":
			p.OSTree = yes
		case "crun":
			p.Crun = v
		case "crun_path":
			p.CrunPath = v
		case "user":
			p.User = v
		case "containers_fs":
			p.ContainersFS = v
		case "unpriv_port":
			p.UnprivPort = v
		}
	}
	if p.Engine == "" {
		p.Engine = EngineNone
	}
	return p
}

// hasDocker is the question `--oci` asks, and it is deliberately not "is
// there a `docker` on PATH": on a podman machine that command is a symlink to
// podman, and registering a runc wrapper in /etc/docker/daemon.json there
// would edit a file no engine reads.
func (p preflight) hasDocker() bool { return p.Engine == EngineDocker }

// hasPodman is the other engine `--oci` can register with, through a
// containers.conf drop-in rather than a merge (docs/podman.md §6.2).
func (p preflight) hasPodman() bool { return p.Engine == EnginePodman }

// minCrun is the floor for crun's seccomp notify listener — `listenerPath`
// and `listenerMetadata` in the OCI seccomp config, which is what makes a
// container's bind reach the agent at all. 0.19 is where crun's NEWS
// records it.
var minCrun = [2]int{0, 19}

// minKernel is the seccomp `listenerPath` contract's floor: SECCOMP_IPC
// listener support in runc's OCI seccomp config landed against 5.7's
// user-notify addressing. Below it the OCI wrapper cannot arbitrate a
// container's binds at all.
var minKernel = [2]int{5, 7}

// checkPreflight turns the probe into a verdict. Pure, so every message
// below is reachable from a test rather than only from a broken VM.
//
// Ordering is deliberate: the checks that would make a later step fail
// obscurely come first, and each message names the fix rather than the
// symptom — the discipline internal/install's errors follow.
func checkPreflight(p preflight, oci bool) error {
	if p.Arch == "" {
		return fmt.Errorf("the guest did not answer `uname -m` — is the VM really running?")
	}
	if !p.Systemd {
		return fmt.Errorf("no systemctl in the guest: drawbridge supervises its agent with systemd.\n" +
			"  Alpine-based guests (colima's legacy image) run OpenRC and are not supported in v1 —\n" +
			"  recreate the VM with an Ubuntu image, e.g. `colima start --vm-type vz` on a current colima")
	}
	if !p.Sudo {
		return fmt.Errorf("passwordless sudo is not available in the guest.\n" +
			"  `drawbridge up` installs a root-owned binary and a systemd unit inside the VM and cannot\n" +
			"  prompt for a password through the provider shell. Lima and Colima images grant it by\n" +
			"  default; check /etc/sudoers.d in the guest if this VM was customized")
	}
	if !p.BTF {
		return fmt.Errorf("no /sys/kernel/btf/vmlinux in the guest: the agent's BPF programs are CO-RE and need BTF.\n" +
			"  Ubuntu LTS kernels ship it; a custom or minimal kernel needs CONFIG_DEBUG_INFO_BTF=y")
	}
	if !p.CGroup2 {
		return fmt.Errorf("the guest is not on cgroup v2 (/sys/fs/cgroup/cgroup.controllers is missing):\n" +
			"  the agent's cgroup-attached BPF programs need the unified hierarchy.\n" +
			"  Boot the guest with systemd.unified_cgroup_hierarchy=1, or use a current Ubuntu image")
	}
	if _, err := guestArchOf(p); err != nil {
		return err
	}
	maj, min, ok := parseMajorMinor(p.Kernel)
	switch {
	case !ok:
		// Informational either way: an unparsable version is not evidence of
		// an old kernel, and refusing on it would fail closed against a
		// distro that decorates its release string.
		if oci {
			return fmt.Errorf("cannot read the guest kernel version from %q, and --oci needs >= %d.%d for the\n"+
				"  seccomp listenerPath contract the runc wrapper relies on", p.Kernel, minKernel[0], minKernel[1])
		}
	case maj < minKernel[0] || (maj == minKernel[0] && min < minKernel[1]):
		if oci {
			return fmt.Errorf("guest kernel %s is older than %d.%d: --oci registers a runc wrapper that arbitrates\n"+
				"  container binds through seccomp user-notify (listenerPath), which needs %d.%d or newer.\n"+
				"  Without --oci, inbound mirroring, outbound and host-process EADDRINUSE all still work",
				p.Kernel, minKernel[0], minKernel[1], minKernel[0], minKernel[1])
		}
	}
	if oci && p.hasPodman() {
		return checkPodmanOCI(p)
	}
	if oci && !p.hasDocker() {
		return fmt.Errorf("no docker in the guest: --oci registers the drawbridge runc wrapper in Docker Engine's\n" +
			"  /etc/docker/daemon.json and has nothing to register it with.\n" +
			"  Install Docker Engine in the VM (a Colima VM already has one), or re-run without --oci")
	}
	return nil
}

// checkPodmanOCI is the `--oci` verdict on a podman guest: the two things
// that have to be true before anything is written, each named with what the
// user can do about it.
//
// The SELinux mode is deliberately not a verdict. Fedora CoreOS runs
// Enforcing and every file `up` installs is relabelled; a guest that broke
// on a denial is a question for docs/podman.md §10, never a reason for
// drawbridge to reach for `setenforce`.
func checkPodmanOCI(p preflight) error {
	if p.CrunPath == "" {
		return fmt.Errorf("no crun in the guest: --oci on a podman machine registers the drawbridge wrapper as\n" +
			"  podman's `crun` runtime and execs the real crun behind it, and there is none on PATH.\n" +
			"  Without --oci, inbound mirroring, outbound and host-process EADDRINUSE all still work")
	}
	maj, min, ok := parseMajorMinor(p.Crun)
	switch {
	case !ok:
		return fmt.Errorf("cannot read crun's version from %q, and --oci needs >= %d.%d for the seccomp notify\n"+
			"  listener (listenerPath) a container's bind is arbitrated through.\n"+
			"  `crun --version` in the guest is what this reads", p.Crun, minCrun[0], minCrun[1])
	case maj < minCrun[0] || (maj == minCrun[0] && min < minCrun[1]):
		return fmt.Errorf("guest crun %s is older than %d.%d: --oci arbitrates container binds through seccomp\n"+
			"  user-notify (listenerPath), which crun grew in %d.%d.\n"+
			"  Update crun in the VM, or re-run without --oci — inbound mirroring, outbound and\n"+
			"  host-process EADDRINUSE all work without it",
			p.Crun, minCrun[0], minCrun[1], minCrun[0], minCrun[1])
	}
	return nil
}

// parseMajorMinor reads the leading `major.minor` of a version string. It
// stops at the first thing that is not a digit or a dot, which is what makes
// "6.8.0-51-generic" and "5.15.0" and "6.1" and crun's "1.28" all parse.
func parseMajorMinor(rel string) (maj, min int, ok bool) {
	fields := strings.FieldsFunc(rel, func(r rune) bool { return r < '0' || r > '9' })
	if len(fields) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(fields[0])
	min, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}
