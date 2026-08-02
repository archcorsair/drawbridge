package main

// `drawbridge up` — attach a container VM (docs/ergonomics.md §4.1).
//
// Six steps: discover, preflight, push the agent, install the unit,
// optionally provision the OCI wrapper, verify and hand off. The ordering is
// the failure posture (§4.2): every mutating step is preceded by the
// preflight that would have caught it, and the unit install is the last
// mutation before verification, so a failure anywhere leaves the guest in
// the state it was already in.
//
// No sudo on the Mac. vmprovider's limactl half refuses euid 0 outright, and
// everything privileged happens inside the guest.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// controlPort is the agent's transport port — the one thing `up` verifies it
// can reach, and the one port the dev template forwards.
const controlPort = 4777

func runUp(args []string) int {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	oci := fs.Bool("oci", false, "also install the runc wrapper and register it in the guest's Docker daemon.json (default off: it edits a file you own and changes the default container runtime)")
	agentBin := fs.String("agent-bin", "", "guest agent binary to push instead of the bundled one; the dev loop's escape hatch and the way to use a standalone release artifact")
	runcBin := fs.String("runc-bin", "", "runc wrapper binary to push instead of the bundled one (--oci only)")
	instance, err := parsePositional(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge up: %v\n", err)
		return 2
	}

	providers := vmprovider.Detect()
	if len(providers) == 0 {
		fmt.Fprintf(os.Stderr, "drawbridge up: %v\n", noCandidateError(nil))
		return 1
	}
	sel, err := pickInstance(instance, listAll(providers, os.Stderr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge up: %v\n", err)
		return 1
	}

	g := &guest{p: vmprovider.ForRef(sel.Ref), inst: sel.Ref.Instance, out: os.Stdout}
	if err := up(g, sel, upOptions{oci: *oci, agentBin: *agentBin, runcBin: *runcBin}); err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge up: %v\n", err)
		return 1
	}
	handoff(g, sel, os.Stdout)
	return 0
}

// upOptions are the flags, with the binary overrides still as paths: reading
// them is part of the run, and a missing file is a diagnosis like any other.
type upOptions struct {
	oci      bool
	agentBin string
	runcBin  string
}

// up performs steps 2 through 5 against an already-chosen VM. Verification
// (step 6) is separate because it dials the guest over the network, which is
// exactly the part a unit test cannot have.
func up(g *guest, sel selection, o upOptions) error {
	// --- step 2: preflight -------------------------------------------------
	pf, err := g.probe()
	if err != nil {
		return err
	}
	if err := checkPreflight(pf, o.oci); err != nil {
		return err
	}
	arch, err := guestArchOf(pf)
	if err != nil {
		return err
	}
	fmt.Fprintf(g.out, "drawbridge: %s — linux/%s, kernel %s\n", qualify(sel.Instance), arch, pf.Kernel)

	// Resolve every artifact before touching the guest. A dev build with no
	// bundled agent has to fail here, with the remedy, and not halfway
	// through a provisioning run (§4.2).
	agent, err := loadGuestBinary(guestbin.NameAgent, arch, o.agentBin)
	if err != nil {
		return err
	}
	var runc []byte
	if o.oci {
		if runc, err = loadGuestBinary(guestbin.NameRunc, arch, o.runcBin); err != nil {
			return err
		}
	}
	unit, err := guestbin.Unit(guestbin.GuestPath(guestbin.NameAgent))
	if err != nil {
		return err
	}

	// --- step 3: push the agent -------------------------------------------
	agentPath := guestbin.GuestPath(guestbin.NameAgent)
	agentChanged, err := g.pushBinary(agent, agentPath)
	if err != nil {
		return err
	}
	if agentChanged {
		fmt.Fprintf(g.out, "drawbridge: installed %s (%s)\n", agentPath, buildinfo.Version)
	} else {
		fmt.Fprintf(g.out, "drawbridge: %s already current\n", agentPath)
	}

	// --- step 3b: the transport secret ------------------------------------
	// Before the unit install, so the agent's first start already has it.
	// No restart is needed when only the secret changed: both sides re-read
	// the file per connection, which is what makes rotation live (§5).
	if err := ensureSecret(g, sel.Ref); err != nil {
		return err
	}

	// --- step 4: install the unit -----------------------------------------
	unitChanged, err := g.installUnit(unit)
	if err != nil {
		return err
	}
	if err := g.enableAgent(agentChanged || unitChanged); err != nil {
		return err
	}

	// --- step 5: --oci -----------------------------------------------------
	if o.oci {
		if err := provisionOCI(g, runc); err != nil {
			return err
		}
	}
	return nil
}

// ensureSecret provisions the per-VM transport secret (docs/transport-auth.md
// §5). The Mac file is authoritative: reused when present, generated when
// absent, and the guest is converged to it. Deterministic in both directions,
// so a re-run of `up` writes nothing and stays journal-quiet.
//
// Rotation is `rm <mac file> && drawbridge up`: the next run generates a new
// secret and converges the guest, and because both sides re-read per
// connection it heals live, with no daemon or agent restart.
func ensureSecret(g *guest, ref vmprovider.Ref) error {
	path, err := transportauth.PathForRef(ref)
	if err != nil {
		return fmt.Errorf("deriving the transport secret path: %w", err)
	}
	sec, created, err := ensureMacSecret(path)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(g.out, "drawbridge: generated a transport secret at %s\n", path)
	}
	// Compare digests rather than contents: the guest file is 0600 root, so
	// the unprivileged g.sha256 cannot read it. A digest of 32 random bytes
	// is inert, which is what makes exposing one to the comparison fine.
	want := sha256Hex([]byte(sec.Format()))
	have, err := g.sudoSha256(guestbin.SecretPath)
	if err != nil {
		return err
	}
	if have == want {
		return nil
	}
	if err := g.writeFile([]byte(sec.Format()), guestbin.SecretPath, "0600"); err != nil {
		return err
	}
	fmt.Fprintf(g.out, "drawbridge: wrote %s (transport auth enabled)\n", guestbin.SecretPath)
	return nil
}

// ensureMacSecret reads the Mac-side secret, generating it when absent.
// Malformed is fatal rather than regenerated: silently replacing a file the
// user (or another VM's install) may still depend on is not a repair, and the
// remedy is one command (§5).
func ensureMacSecret(path string) (transportauth.Secret, bool, error) {
	sec, err := transportauth.Load(path)
	switch {
	case err == nil:
		return sec, false, nil
	case errors.Is(err, transportauth.ErrAbsent):
	default:
		return transportauth.Secret{}, false, fmt.Errorf("%w\n  Delete it and re-run `drawbridge up` to provision a fresh one", err)
	}
	sec, err = transportauth.Generate()
	if err != nil {
		return transportauth.Secret{}, false, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return transportauth.Secret{}, false, fmt.Errorf("creating %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(sec.Format()), 0o600); err != nil {
		return transportauth.Secret{}, false, fmt.Errorf("writing %s: %w", path, err)
	}
	// Explicit, because WriteFile only applies the mode when it creates the
	// file and umask can trim it either way. A world-readable transport
	// secret is the one outcome this step must never produce.
	if err := os.Chmod(path, 0o600); err != nil {
		return transportauth.Secret{}, false, fmt.Errorf("chmod %s: %w", path, err)
	}
	return sec, true, nil
}

// loadGuestBinary picks the bytes to push: the override when given, the
// bundle otherwise. ErrNotBundled's own text is the remedy, so it passes
// through unwrapped except for which role was missing.
func loadGuestBinary(role, arch, override string) ([]byte, error) {
	if override != "" {
		b, err := os.ReadFile(override)
		if err != nil {
			return nil, fmt.Errorf("reading -%s-bin: %w", role, err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("-%s-bin %s is empty", role, override)
		}
		return b, nil
	}
	b, err := guestbin.Binary(role, arch)
	if errors.Is(err, guestbin.ErrNotBundled) {
		return nil, fmt.Errorf("no bundled %s for linux/%s: %w", role, arch, guestbin.ErrNotBundled)
	}
	return b, err
}

func guestArchOf(p preflight) (string, error) { return guestbin.Arch(p.Arch) }

// sha256Hex matches what `sha256sum` prints in the guest, which is the whole
// point: the comparison happens between a digest computed here and one
// computed there, without the binary ever crossing the wire to be checked.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pushBinary streams a binary into the guest, skipping the copy when the
// digest already matches. The skip is what makes a re-run of `up` cheap
// enough to put in a shell alias (§4.1 step 3).
func (g *guest) pushBinary(data []byte, dst string) (bool, error) {
	staged, err := g.stageIfChanged(data, dst)
	if err != nil || staged == "" {
		return false, err
	}
	defer g.try("rm -f " + shquote(staged))
	if err := g.installFile(staged, dst, "0755"); err != nil {
		return false, err
	}
	return true, nil
}

// stageIfChanged streams a binary to a staging path and returns it, or ""
// when the guest already has this exact content. Split out from pushBinary
// because the `--oci` wrapper is installed by the provisioning script rather
// than here — the script is the single place that knows where Docker execs
// the wrapper from, shared with `just vm-docker`.
func (g *guest) stageIfChanged(data []byte, dst string) (string, error) {
	have, err := g.sha256(dst)
	if err != nil {
		return "", err
	}
	if have != "" && have == sha256Hex(data) {
		return "", nil
	}
	staged := "/tmp/" + sanitizeName(dst) + ".new"
	if err := g.stage(data, staged); err != nil {
		return "", err
	}
	return staged, nil
}

// installUnit renders the persistent unit into /etc/systemd/system and
// reports whether it changed. Comparing first keeps an idempotent `up` from
// touching the file — and from triggering a `daemon-reload` that would
// restart nothing but still shows up in the journal as activity.
func (g *guest) installUnit(unit string) (bool, error) {
	have, _, err := g.readFile(guestbin.UnitPath)
	if err != nil {
		return false, err
	}
	if string(have) == unit {
		return false, nil
	}
	if err := g.writeFile([]byte(unit), guestbin.UnitPath, "0644"); err != nil {
		return false, err
	}
	fmt.Fprintf(g.out, "drawbridge: wrote %s\n", guestbin.UnitPath)
	return true, nil
}

// enableAgent starts the persistent unit, first getting the transient one
// out of the way.
//
// The two would fight. `just agent-up` runs the agent as a transient unit
// under the *same* name (systemd-run --unit=drawbridge-agent), which is
// deliberate — two agents in one guest would race for the same BPF
// attachments and the same transport port, and sharing the name makes that
// impossible rather than merely unlikely. The cost is that `systemctl
// enable --now` on the persistent unit is a no-op while the transient one
// holds the name, so `up` would report success and leave the dev agent
// running. Stopping it (and clearing any failed state it left) is what makes
// `up` converge with the `just agent-up` world instead of silently losing to
// it. The dev flow is unchanged and remains the documented dev override:
// re-running `just agent-up` replaces the persistent unit right back.
func (g *guest) enableAgent(restart bool) error {
	transient, err := g.sh("systemctl show -p Transient --value " + shquote(guestbin.UnitName) + " 2>/dev/null || true")
	if err != nil {
		return fmt.Errorf("querying %s: %w", guestbin.UnitName, err)
	}
	if strings.TrimSpace(transient) == "yes" {
		fmt.Fprintf(g.out, "drawbridge: stopping the transient %s from `just agent-up`\n", guestbin.UnitName)
		g.try("systemctl stop " + shquote(guestbin.UnitName))
		g.try("systemctl reset-failed " + shquote(guestbin.UnitName))
		restart = true
	}
	if _, err := g.sudoSh("systemctl daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	if _, err := g.sudoSh("systemctl enable --now " + shquote(guestbin.UnitName)); err != nil {
		return fmt.Errorf("systemctl enable --now %s: %w\n  `sudo journalctl -u %s -n 50` in the guest has the agent's own account",
			guestbin.UnitName, err, guestbin.UnitName)
	}
	if restart {
		if _, err := g.sudoSh("systemctl restart " + shquote(guestbin.UnitName)); err != nil {
			return fmt.Errorf("systemctl restart %s: %w", guestbin.UnitName, err)
		}
	}
	state, _ := g.sh("systemctl is-active " + shquote(guestbin.UnitName) + " 2>/dev/null || true")
	fmt.Fprintf(g.out, "drawbridge: %s is %s\n", guestbin.UnitName, strings.TrimSpace(state))
	return nil
}

// provisionOCI is §4.1 step 5: the runc wrapper, registered with Docker.
//
// The daemon.json edit is done here, in Go, and not by the provisioning
// script — see internal/guestbin/provision.go for why (`down` has to restore
// exact bytes, and only the writer can promise that).
func provisionOCI(g *guest, runc []byte) error {
	runcPath := guestbin.GuestPath(guestbin.NameRunc)

	// Stage the wrapper now; the script installs it below. Registering a
	// runtime whose binary is not there would leave docker unable to start
	// any container at all, so the install precedes the daemon.json write in
	// the script's own ordering.
	stagedRunc, err := g.stageIfChanged(runc, runcPath)
	if err != nil {
		return err
	}
	if stagedRunc != "" {
		defer g.try("rm -f " + shquote(stagedRunc))
	}

	cur, exists, err := g.readFile(guestbin.DaemonJSONPath)
	if err != nil {
		return err
	}
	if !exists {
		cur = nil // absent and empty revert differently
	}
	merged, st, changed, err := guestbin.Merge(cur, runcPath)
	if err != nil {
		return err
	}
	if changed {
		if err := g.writeFile(merged, guestbin.DaemonJSONPath, "0644"); err != nil {
			return err
		}
		fmt.Fprintf(g.out, "drawbridge: registered the %s runtime in %s and made it the default\n",
			guestbin.RuntimeName, guestbin.DaemonJSONPath)
	}

	// The state file records what *this* run found. Written only when there
	// isn't one already: on a second `up --oci` the merge is a no-op and
	// `DaemonJSONBefore` would be the already-merged file — overwriting a
	// truthful record with that would turn `down`'s exact revert into a
	// revert to the state it is trying to leave.
	if _, have, err := g.readFile(guestbin.ProvisionPath); err != nil {
		return err
	} else if !have {
		blob, err := guestbin.EncodeState(st)
		if err != nil {
			return err
		}
		if err := g.writeFile(blob, guestbin.ProvisionPath, "0644"); err != nil {
			return err
		}
	}

	// The script does the parts that are genuinely the guest's: installing
	// the wrapper where docker will exec it and restarting the engine only
	// when the config actually changed. It is the same file `just vm-docker`
	// runs (internal/guestbin/assets/provision-docker.sh).
	if err := g.stage([]byte(guestbin.ProvisionScript()), guestbin.ProvisionScriptPath); err != nil {
		return err
	}
	defer g.try("rm -f " + shquote(guestbin.ProvisionScriptPath))
	cmd := "bash " + shquote(guestbin.ProvisionScriptPath)
	if stagedRunc != "" {
		cmd += " --runc " + shquote(stagedRunc)
	}
	if changed {
		cmd += " --restart-docker"
	}
	out, err := g.sudoSh(cmd)
	if out != "" {
		fmt.Fprintf(g.out, "drawbridge: %s\n", strings.TrimSpace(out))
	}
	if err != nil {
		return provisionFailure(g, err, changed)
	}
	return nil
}

// provisionFailure turns a failed provisioning run into a statement of where
// the guest actually is.
//
// This is the one place `up` cannot honour "nothing changed" (§4.2): the
// daemon.json write precedes the restart because the restart is what makes
// it take effect, so a restart that fails leaves a guest with a merged
// config and an engine that has not read it. Auto-reverting would not help —
// the revert needs the same restart that just failed — so the honest move is
// to say exactly what state the guest is in and both ways out. `reset-failed`
// in the script makes the systemd rate-limit case rare; rare and named still
// beats rare and raw.
func provisionFailure(g *guest, cause error, wroteDaemonJSON bool) error {
	dockerState, _ := g.sh("systemctl is-active docker 2>/dev/null || true")
	dockerState = strings.TrimSpace(dockerState)
	if dockerState == "" {
		dockerState = "unknown"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "the --oci provisioning step failed in the guest: %v\n", cause)
	sb.WriteString("\n  The guest is in this state:\n")
	sb.WriteString("    - the agent is installed and running; inbound mirroring, outbound and\n" +
		"      host-process EADDRINUSE are unaffected. Only containerized bind arbitration is.\n")
	if wroteDaemonJSON {
		fmt.Fprintf(&sb, "    - %s HAS been updated to register the drawbridge runtime as the default,\n"+
			"      and docker is %s — so the running engine may not have read it.\n",
			guestbin.DaemonJSONPath, dockerState)
	} else {
		fmt.Fprintf(&sb, "    - %s was already correct and was not modified; docker is %s.\n",
			guestbin.DaemonJSONPath, dockerState)
	}
	sb.WriteString("\n  Two ways out:\n" +
		"    - fix docker in the guest, then re-run `drawbridge up --oci` (it is idempotent):\n" +
		"        sudo systemctl reset-failed docker && sudo systemctl restart docker\n" +
		"        sudo journalctl -u docker -n 50 --no-pager\n" +
		"    - or `drawbridge down` to revert the daemon.json change and remove the wrapper.")
	return fmt.Errorf("%s", sb.String())
}

// handoff is step 6: say where the agent is, what version it is, and the one
// next command. It prints rather than returns an error — every mutation has
// already succeeded at this point, and a transport that does not answer is a
// diagnosis about this Mac's network, not a reason to call `up` failed.
// readyScript waits, inside the guest, for the agent's transport to be
// listening.
//
// `systemctl start` on a Type=simple unit returns at exec, not at readiness,
// and the agent loads and attaches its BPF collections — and writes its
// version file — before it binds anything. Resolving the endpoint
// immediately afterwards therefore probes a port nothing is on yet, and the
// resolver classifies that as ECONNREFUSED and prints the loopback fallback
// with a note about an agent that is in fact perfectly healthy. A guest
// without `ss` is not made to wait: no readiness signal is better than a ten
// second pause that proves nothing.
var readyScript = fmt.Sprintf(`
command -v ss >/dev/null 2>&1 || { echo no-probe; exit 0; }
i=0
while [ $i -lt 40 ]; do
  if ss -H -ltn 2>/dev/null | grep -q ':%d '; then echo listening; exit 0; fi
  i=$((i+1)); sleep 0.25
done
echo timeout
`, controlPort)

func handoff(g *guest, sel selection, out io.Writer) {
	ready, _ := g.sh(readyScript)
	if strings.TrimSpace(ready) == "timeout" {
		fmt.Fprintf(out, "drawbridge: warning: nothing is listening on guest :%d after 10s — `sudo journalctl -u %s -n 50` in the guest\n",
			controlPort, guestbin.UnitName)
	}

	version, _ := g.sh("cat /run/drawbridge-agent.version 2>/dev/null || true")
	version = strings.TrimSpace(version)
	if version == "" {
		version = "unknown (the agent writes /run/drawbridge-agent.version at startup)"
	}
	fmt.Fprintf(out, "drawbridge: agent %s in the guest, CLI %s\n", version, buildinfo.Version)
	if version != buildinfo.Version && !strings.HasPrefix(version, "unknown") {
		fmt.Fprintf(out, "drawbridge: warning: the guest agent reports %s but this CLI is %s — re-run `drawbridge up` after upgrading\n", version, buildinfo.Version)
	}

	r := limaaddr.ResolveTarget(limaaddr.Target{
		VM:        sel.Ref.Instance,
		LeaseName: sel.Ref.LeaseName,
		LimaHome:  sel.Ref.LimaHome,
	}, controlPort)
	fmt.Fprintf(out, "drawbridge: transport %s (source %s)\n", r.Endpoint, r.Source)
	if r.Note != "" {
		fmt.Fprintf(out, "drawbridge: %s\n", r.Note)
	}
	if p, err := transportauth.PathForRef(sel.Ref); err == nil {
		fmt.Fprintf(out, "drawbridge: transport auth: enabled (%s)\n", p)
	}

	// The coexistence line (§3.4): one sentence, never an auto-disable. A
	// mirror bind that loses the race to the provider's forwarder still
	// leaves the guest listener reachable — degraded, but working — and
	// silently degrading is the thing worth a warning.
	if f, ok := g.p.(vmprovider.Forwarder); ok {
		if fw, err := f.Forwarding(g.inst); err == nil && fw.Active() {
			fmt.Fprintf(out, "drawbridge: note: this VM's own port forwarder is active (guest loopback %s, wildcard %s).\n"+
				"  Ports it claims first will mirror without drawbridge's synchronous bind arbitration on the Mac side.\n"+
				"  `drawbridge doctor` explains the tradeoff and the opt-out.\n", fw.Loopback, fw.Wildcard)
		}
	}

	fmt.Fprintf(out, "\nNext: sudo drawbridge install -vm %s\n"+
		"      (or, unprivileged and foreground, ports >= 1024 only: drawbridged -vm %s)\n",
		sel.Ref.Spec, sel.Ref.Spec)
}

// parsePositional pulls the optional instance argument out of an argv where
// flags may appear on either side of it.
//
// Go's flag package stops at the first non-flag token, so `drawbridge up
// colima:default --oci` would otherwise silently ignore --oci. Re-parsing
// what follows, until nothing is left, accepts every ordering and still
// rejects a second positional argument — which is a typo, not a second VM.
func parsePositional(fs *flag.FlagSet, args []string) (string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return "", err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	switch len(positional) {
	case 0:
		return "", nil
	case 1:
		return positional[0], nil
	default:
		return "", fmt.Errorf("expected at most one instance argument, got %d: %s", len(positional), strings.Join(positional, " "))
	}
}
