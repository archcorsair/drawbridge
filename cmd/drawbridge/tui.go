package main

// `drawbridge tui` — the read-only observability front end (docs/tui.md §4.3).
//
// Flags only: everything else is the TUI's own. -vm pre-selects a daemon by
// canonical ref, and it plus -vm-subnet/-vm-mac/-timeout are carried through
// to the doctor view's Options so a TUI user on a pinned install gets the same
// lease view `drawbridge doctor` gives — same grammar, same defaults.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/tui"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func tuiFlags(args []string) (tui.Options, error) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	vm := fs.String("vm", "", "VM to select first: a bare name is a Lima instance, `provider:name` selects one (lima:myvm, colima:default). Without it every answering daemon is listed and the first is selected")
	subnet := fs.String("vm-subnet", "", "vmnet subnet the guest's lease address must fall inside, passed through to the doctor view; only needed when this Mac's vmnet is not on "+limaaddr.DefaultSubnet)
	mac := fs.String("vm-mac", "", "guest's hardware address, passed through so the doctor view's lease view matches a pinned install")
	timeout := fs.Duration("timeout", 30*time.Second, "overall budget for the doctor view's probes; same default as `drawbridge doctor`")
	_ = fs.Parse(args)
	if err := rejectLeftovers(fs, "tui takes the VM as -vm NAME"); err != nil {
		return tui.Options{}, err
	}

	opts := tui.Options{VM: *vm, HWAddr: *mac, Timeout: *timeout, CLIVersion: buildinfo.Version}
	// A bad -vm is rejected here rather than silently ignored: it would
	// otherwise select nothing and look like "no daemon for that VM".
	if *vm != "" {
		if _, err := vmprovider.ParseRef(*vm); err != nil {
			return opts, fmt.Errorf("-vm: %w", err)
		}
	}
	if *subnet != "" {
		p, err := limaaddr.ParseSubnet(*subnet)
		if err != nil {
			return opts, fmt.Errorf("-vm-subnet: %w", err)
		}
		opts.Subnet = p
	}
	if *mac != "" {
		hw, err := limaaddr.ParseHWAddr(*mac)
		if err != nil {
			return opts, fmt.Errorf("-vm-mac: %w", err)
		}
		opts.HWAddr = hw
	}
	if dir := os.Getenv(envDemoDoctor); dir != "" {
		opts.GatherDoctor = cannedDoctor(dir)
	}
	return opts, nil
}

// envDemoDoctor is demo plumbing, the doctor half of the tui-demo-daemon
// fixture: it names a directory holding canned doctor reports, and the doctor
// view then renders those instead of gathering from this machine. Deliberately
// an env var rather than a flag: the demo fixture prints the export, and the
// verb's advertised surface stays exactly its production flags. Snapshots need
// no counterpart because the fixture serves real introspection sockets.
const envDemoDoctor = "DRAWBRIDGE_TUI_DEMO_DOCTOR"

// Canned report filenames and the honest-spinner delays the demo gather takes
// before returning them. The probe run takes visibly longer, so `p` costs
// something on camera the way the real half-close probe does.
const (
	cannedPlainFile  = "doctor.json"
	cannedProbeFile  = "doctor-probe.json"
	cannedPlainDelay = 2 * time.Second
	cannedProbeDelay = 6 * time.Second
)

// readCannedReport is the pure half of the demo gather: one file per run
// kind, JSON in doctor.Report's own shape (the same encoding `doctor -json`
// consumers already parse).
func readCannedReport(dir string, probe bool) (doctor.Report, error) {
	name := cannedPlainFile
	if probe {
		name = cannedProbeFile
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return doctor.Report{}, err
	}
	var r doctor.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return doctor.Report{}, fmt.Errorf("canned doctor report %s: %w", name, err)
	}
	return r, nil
}

// cannedDoctor is tui.Options.GatherDoctor over readCannedReport: a scripted
// wait (so the running screen and its esc-cancel path are exercised for
// real), then the canned findings. Cancellation wins the wait, exactly as a
// canceled real gather would.
func cannedDoctor(dir string) func(context.Context, doctor.Options) (doctor.Report, error) {
	return func(ctx context.Context, opts doctor.Options) (doctor.Report, error) {
		r, err := readCannedReport(dir, opts.Probe)
		if err != nil {
			return doctor.Report{}, err
		}
		delay := cannedPlainDelay
		if opts.Probe {
			delay = cannedProbeDelay
		}
		select {
		case <-ctx.Done():
			return doctor.Report{}, ctx.Err()
		case <-time.After(delay):
		}
		return r, nil
	}
}

func runTUI(args []string) int {
	opts, err := tuiFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge tui: %v\n", err)
		return 2
	}
	// bubbletea restores the terminal before Run returns, on quit, on ctrl+c
	// and on panic — so printing the error here always lands on a sane screen.
	// Without a terminal at all (a pipe, CI) it fails immediately, which is
	// the right answer for a program whose whole output is a screen.
	if err := tui.Run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge tui: %v\n", err)
		return 1
	}
	return 0
}
