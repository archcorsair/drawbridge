// drawbridge is the user-facing CLI, in two halves.
//
// The guest half — `up` and `down` — attaches an existing Lima or Colima VM:
// it pushes the bundled agent, installs its systemd unit, and optionally
// registers the runc wrapper with the guest's Docker (docs/ergonomics.md
// §4). It never creates a VM, never needs sudo on the Mac, and is idempotent
// in both directions.
//
// The Mac half is the install story for the privileged daemon: `install`
// puts drawbridged under launchd as a root LaunchDaemon (which is what makes
// ports <1024 mirrorable and, per TN3179, exempts the vzNAT transport from
// the Local Network permission gate), `uninstall` takes it back out, and
// `status` reports what launchd and the log say — without talking to the
// daemon, which exposes no control surface at all.
//
// The dev loop is unchanged and stays separate: `just agent-up` runs the
// agent as a transient unit under the same name `up` installs, and each
// replaces the other (docs/privileged-daemon.md §11 q3).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func main() {
	verb := ""
	if len(os.Args) > 1 {
		verb = os.Args[1]
	}
	args := os.Args[2:]
	switch verb {
	case "up":
		os.Exit(runUp(args))
	case "down":
		os.Exit(runDown(args))
	case "install":
		os.Exit(runInstall(args))
	case "uninstall":
		os.Exit(runUninstall(args))
	case "status":
		os.Exit(runStatus(args))
	case "doctor":
		os.Exit(runDoctor(args))
	case "tui":
		os.Exit(runTUI(args))
	case "version", "-v", "--version":
		fmt.Println("drawbridge", buildinfo.Version)
	case "help", "-h", "--help", "":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "drawbridge: unknown command %q\n\n", verb)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `drawbridge — host networking semantics for macOS container VMs

Usage:
  drawbridge up [INSTANCE] [--oci] [-agent-bin PATH] [-runc-bin PATH]
        Install and start the guest agent in a Lima or Colima VM. No sudo on
        the Mac; the privileged half happens inside the guest. Attach-only —
        `+"`up`"+` never creates a VM. INSTANCE takes the same grammar as -vm:
        a bare name is resolved across providers, provider:name selects one
        (lima:myvm, colima:default). With one running vz VM it can be left
        out; with several it is required.
        --oci additionally installs the runc wrapper and registers it as
        Docker's default runtime in the guest's daemon.json — an explicit
        opt-in because it edits a file you own. Without it, mirroring,
        outbound and host-process EADDRINUSE all still work; only
        containerized bind arbitration needs the wrapper.
        -agent-bin/-runc-bin push a binary from disk instead of the one
        bundled into this CLI (dev loop; standalone release artifacts).
  drawbridge down [INSTANCE]
        Remove the agent, its unit and the wrapper from the guest, and revert
        the daemon.json changes `+"`up --oci`"+` recorded. Idempotent: a guest
        that never had drawbridge is a no-op.
  drawbridge install [-vm NAME] [-vm-mac MAC] [-vm-subnet CIDR] [-udp P,P]
                     [-skip P,P] [-bin PATH] [-print]
        Install drawbridged as a root LaunchDaemon (needs sudo).
        Ports <1024 need this; -print previews the files and writes nothing.
        -vm takes a bare Lima instance name (default `+install.DefaultVM+`) or
        provider:name — lima:myvm, colima:default, colima:<profile>.
        -skip lists ports drawbridged leaves alone in both directions
        (default `+install.DefaultSkip+`; -skip "" skips nothing).
        -vm-mac pins which VM the root daemon will trust. Without it the
        daemon matches DHCP lease records by the guest-chosen name alone, so
        any other VM on this Mac can claim the name. Read the address with
          limactl list --format json NAME
        (as your own user — limactl does not run under sudo). For a colima
        instance the command needs LIMA_HOME=<colima's lima dir>; install
        with -print and it prints the exact command, with that directory
        already discovered (colima moved it in v0.9, so it is not a fixed
        path).
  drawbridge uninstall
        Boot out the daemon and remove its binary, plist and rotation entry
        (needs sudo). Logs are kept.
  drawbridge status [-v]
        One compact block per running daemon, read from its introspection
        socket (version, endpoint and source, auth mode, mirror/sync
        counts). -v adds launchd state, artifact paths and the log tail —
        which also print by default whenever no daemon answers, because
        there they are the only evidence. No root needed; exit codes are
        0 running, 1 installed-but-not-running, 3 not installed.
  drawbridge doctor [-vm NAME] [-vm-mac MAC] [-vm-subnet CIDR] [-json] [-v]
                    [-timeout D]
        Diagnose this install: providers, guest prerequisites, the agent,
        endpoint resolution, the vzNAT route, the macOS Local Network gate,
        content filters, the daemon, provider-forwarder coexistence and
        transport authentication. Read-only — it prints remediations and
        never runs them, and never spawns sudo. An ok check prints its
        title only; -v shows its evidence too. -json emits the structured
        report. Exit 0 when nothing failed, 1 when something did, 2 when
        doctor itself could not gather.
  drawbridge tui [-vm NAME] [-vm-subnet CIDR] [-vm-mac MAC] [-timeout D]
        Live read-only view of every running daemon: mirror table, sync
        set, resolution, auth posture, refusals, and the doctor catalog
        on demand. Observes via the introspection socket; cannot command
        the daemon (the socket has no request grammar). No root needed.
  drawbridge version

Developing drawbridge itself? `+"`just agent-up`"+` runs the agent as a transient
unit in the dev VM; it and `+"`drawbridge up`"+` replace each other.
See docs/ergonomics.md §4 and docs/privileged-daemon.md.
`)
}

func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	vm := fs.String("vm", install.DefaultVM, "VM the daemon resolves (-vm in the installed plist): a bare name is a Lima instance, `provider:name` selects one explicitly (lima:myvm, colima:default)")
	mac := fs.String("vm-mac", "", "guest's hardware address to pin (-vm-mac in the installed plist); without it the root daemon trusts DHCP lease records matched by the guest-chosen name alone. `limactl list --format json NAME` reports it")
	subnet := fs.String("vm-subnet", "", "vmnet subnet lease addresses must fall inside (-vm-subnet in the installed plist); only needed when this Mac's vmnet is not on "+limaaddr.DefaultSubnet)
	udp := fs.String("udp", "", "comma-separated Mac UDP ports to offer the guest (-udp in the installed plist)")
	skip := fs.String("skip", install.DefaultSkip, "comma-separated ports the daemon ignores in both directions (-skip in the installed plist); \"\" installs a daemon that skips nothing")
	secretFile := fs.String("secret-file", "", "transport secret the daemon reads (-secret-file in the installed plist); default is the per-VM file `drawbridge up` writes under ~/Library/Application Support/drawbridge")
	bin := fs.String("bin", "", "drawbridged binary to install (default: the drawbridged next to this CLI)")
	print := fs.Bool("print", false, "print the files that would be installed and exit; writes nothing, needs no root")
	_ = fs.Parse(args)

	ports, err := install.ParseUDPPorts(*udp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge install: %v\n", err)
		return 2
	}
	cfg := install.Config{VM: *vm, UDP: ports}
	if err := cfg.SetSkip(*skip); err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge install: -skip: %v\n", err)
		return 2
	}

	// Canonicalise here rather than at the daemon's first resolve: the plist
	// is written once and read by root at every boot, so a value that would
	// not have matched anything is a bad install, not a runtime warning.
	if *mac != "" {
		hw, err := limaaddr.ParseHWAddr(*mac)
		if err != nil {
			fmt.Fprintf(os.Stderr, "drawbridge install: -vm-mac: %v\n", err)
			return 2
		}
		cfg.MAC = hw
	}
	if *subnet != "" {
		p, err := limaaddr.ParseSubnet(*subnet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "drawbridge install: -vm-subnet: %v\n", err)
			return 2
		}
		cfg.Subnet = p.String()
	}
	// The -vm value is parsed here too, both to reject a bad one before any
	// file is written and because the pin warning has to name the DHCP record
	// the daemon will actually match — which, for a colima install, is
	// neither the flag value nor "lima-"+it.
	ref, err := vmprovider.ParseRef(cfg.VM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge install: -vm: %v\n", err)
		return 2
	}
	// Advisory warnings are collected here and printed last — after the
	// status block on success, before the error otherwise — so they end up
	// where the user is still looking instead of scrolled away by the
	// install's own output.
	var warnings []warning
	flushWarnings := func() {
		for _, wn := range warnings {
			renderWarning(os.Stderr, stderrStyles, wn)
		}
	}

	// The transport secret's path is rendered into the plist because root
	// cannot derive it: os.UserHomeDir under launchd is root's, and the
	// secret belongs to the user who ran `up` (docs/transport-auth.md §5).
	// Resolving it here means `sudo drawbridge install` writes the invoking
	// user's path — transportauth.HomeDir is SUDO_USER-aware.
	cfg.SecretFile = *secretFile
	if cfg.SecretFile == "" {
		p, err := transportauth.PathForRef(ref)
		if err != nil {
			warnings = append(warnings, warning{
				title: fmt.Sprintf("cannot derive the transport secret path (%v)", err),
				body:  []string{"the daemon will run UNAUTHENTICATED. Pass -secret-file to point it at one."},
			})
		} else {
			cfg.SecretFile = p
		}
	}
	if cfg.SecretFile != "" {
		if _, err := os.Stat(cfg.SecretFile); err != nil {
			// Not fatal: `install` before `up` is a legitimate order, and the
			// daemon re-reads per connection, so the file appearing later
			// heals without a reinstall.
			warnings = append(warnings, warning{
				title: fmt.Sprintf("no transport secret at %s yet", cfg.SecretFile),
				body: []string{
					fmt.Sprintf("the daemon will run UNAUTHENTICATED until `drawbridge up %s` writes one", cfg.VM),
					"(no reinstall needed).",
				},
			})
		}
	}

	if cfg.MAC == "" {
		// No auto-discovery of the address: reading it for the user and
		// pinning it silently would decide their fail-open-vs-fail-closed
		// posture for them. Print the command instead.
		warnings = append(warnings, warning{
			title: "no -vm-mac given",
			body: []string{
				fmt.Sprintf("the root daemon will accept the DHCP lease record named %s no matter", ref.LeaseName),
				"which VM wrote it. If any other VM runs on this Mac, pin it:",
				"  " + limactlShow(ref) + "   # network[].macAddress",
				fmt.Sprintf("  sudo drawbridge install -vm %s -vm-mac <that address>", cfg.VM),
			},
		})
	}

	if *print {
		plist, err := install.RenderPlist(cfg)
		if err != nil {
			flushWarnings()
			fmt.Fprintf(os.Stderr, "drawbridge install: %v\n", err)
			return 2
		}
		flushWarnings()
		fmt.Printf("# %s\n%s\n# %s\n%s", install.PlistPath, plist, install.NewsyslogPath, install.NewsyslogConf())
		return 0
	}
	st, err := install.Install(cfg, *bin, stepLine(os.Stdout, stdoutStyles))
	if err != nil {
		flushWarnings()
		fmt.Fprintf(os.Stderr, "drawbridge install: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stdout)
	renderStatus(os.Stdout, stdoutStyles, st)
	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr)
		flushWarnings()
	}
	return 0
}

// limactlShow is the command that prints the instance's hardware address,
// spelled so it works for the provider the user actually named. Colima's
// instances are Lima instances in colima's own LIMA_HOME, so a bare limactl
// invocation does not see them at all — and "limactl says no such instance"
// is a far worse first experience than a slightly longer command line.
//
// The directory is whatever vmprovider discovered, never a guess: colima
// moved it in v0.9, so printing a hardcoded path would be printing a command
// that fails on any current install.
func limactlShow(r vmprovider.Ref) string {
	cmd := "limactl list --format json " + r.Instance
	if r.LimaHome != "" {
		cmd = "LIMA_HOME=" + r.LimaHome + " " + cmd
	}
	return cmd
}

func runUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	_ = fs.Parse(args)
	if err := install.Uninstall(stepLine(os.Stdout, stdoutStyles)); err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge uninstall: %v\n", err)
		return 1
	}
	return 0
}

func runStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	verbose := fs.Bool("v", false, "the full form: launchctl state, artifact paths, the log tail, and every daemon field")
	_ = fs.Parse(args)
	st := install.Query()
	snaps, problems := introspect.FetchAll(introspect.DialTimeout)
	// The calm default (same rule as doctor): a live daemon's snapshot IS
	// the status. -v — and every state where no snapshot answers, where
	// launchctl and the log tail are the only evidence — prints the full
	// form. install.Query() stays the spine and the exit-code source either
	// way, so scripts and a daemon predating the socket see exactly what
	// they always saw.
	if *verbose {
		renderStatus(os.Stdout, stdoutStyles, st)
		renderDaemons(os.Stdout, stdoutStyles, snaps, problems)
	} else if !renderCalmStatus(os.Stdout, stdoutStyles, st, snaps, problems) {
		renderStatus(os.Stdout, stdoutStyles, st)
	}
	// Exit status is diagnosable: 0 running, 1 installed-but-not-running,
	// 3 not installed. Scripts (and the acceptance sequence) can branch.
	switch {
	case st.Running():
		return 0
	case st.Installed() || st.Loaded:
		return 1
	default:
		return 3
	}
}

// renderDaemons appends one `daemon:` section per answering introspection
// socket. It never contributes to the exit code and never prints a heading
// for a Mac where nothing answered: the whole section is enrichment, and its
// absence is the ordinary case.
func renderDaemons(w io.Writer, sty styles, snaps []*introspect.Snapshot, problems []error) {
	head := sty.key.Render("daemon:") + "  "
	renderSnapshotIssues(w, sty, snaps, problems)
	for _, s := range snaps {
		if s == nil || !s.Usable {
			continue
		}
		st := s.State
		fmt.Fprintf(w, "%s%s (pid %d, euid %d)\n", head, orUnknown(st.Version), st.PID, st.EUID)
		fmt.Fprintf(w, "%s%s\n", dk(sty, "vm"), orUnknown(st.VM.Ref))
		fmt.Fprintf(w, "%s%s (source=%s)\n", dk(sty, "endpoint"), orUnknown(st.Resolution.Endpoint), orUnknown(st.Resolution.Source))
		if st.Resolution.Note != "" {
			fmt.Fprintf(w, "%s%s\n", dk(sty, "note"), st.Resolution.Note)
		}
		fmt.Fprintf(w, "%s%s (secret %s)\n", dk(sty, "auth"), orUnknown(st.Auth.Mode), orUnknown(st.Auth.SecretState))
		fmt.Fprintf(w, "%ssession %s, %d bound of %d entries\n",
			dk(sty, "mirror"), upDown(st.Mirror.SessionUp), countState(st.Mirror.Entries, introspect.EntryBound), len(st.Mirror.Entries))
		fmt.Fprintf(w, "%ssession %s, %d advertised, %d parked\n",
			dk(sty, "sync"), upDown(st.Sync.SessionUp), len(st.Sync.Advertised), st.Sync.PoolParked)
		fmt.Fprintf(w, "%s%s\n", dk(sty, "socket"), s.Path)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func countState(entries []introspect.MirrorEntry, state string) int {
	n := 0
	for _, e := range entries {
		if e.State == state {
			n++
		}
	}
	return n
}
