package main

// `drawbridge tui` — the read-only observability front end (docs/tui.md §4.3).
//
// Flags only: everything else is the TUI's own. -vm pre-selects a daemon by
// canonical ref, and it plus -vm-subnet/-vm-mac/-timeout are carried through
// to the doctor view's Options so a TUI user on a pinned install gets the same
// lease view `drawbridge doctor` gives — same grammar, same defaults.

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
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
	return opts, nil
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
