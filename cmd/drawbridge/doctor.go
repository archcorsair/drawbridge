package main

// `drawbridge doctor` — the ordered check catalog (docs/doctor.md).
//
// Three steps and nothing else: gather, classify, render. All the judgment
// lives in internal/doctor's pure classifiers, so this file has no opinions
// to test. Doctor never mutates state and never spawns sudo: the tier-1
// discriminator is an instruction it prints, not a command it runs.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
)

// doctorOutput is the verb's presentation half: how the report is shown,
// which is cmd/drawbridge's business, kept apart from doctor.Options, which
// is what gets diagnosed.
type doctorOutput struct {
	json    bool
	verbose bool
}

// doctorFlags parses the verb's flags into Options. Split out from runDoctor
// so the flag→Options threading is testable without a machine — above all
// -probe, whose whole effect is one bool reaching Gather.
func doctorFlags(args []string) (doctor.Options, doctorOutput, error) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the full structured report as JSON (for bug filing); the text form is the default")
	verbose := fs.Bool("v", false, "show evidence for ok checks too; the text form compacts an ok finding to its title line (warn/fail/skip/info always print evidence and remedies). No effect with -json, which always carries everything")
	vm := fs.String("vm", "", "VM to diagnose: a bare name is a Lima instance, `provider:name` selects one (lima:myvm, colima:default). With one running vz VM it can be left out")
	subnet := fs.String("vm-subnet", "", "vmnet subnet the guest's lease address must fall inside; only needed when this Mac's vmnet is not on "+limaaddr.DefaultSubnet)
	mac := fs.String("vm-mac", "", "guest's hardware address, so doctor's lease view matches a pinned install")
	timeout := fs.Duration("timeout", 30*time.Second, "overall budget for every probe; doctor terminates against a wedged VM rather than hanging")
	probe := fs.Bool("probe", false, "run check 8: open one read-only event session to the agent, half-close it, and see whether the path still delivers server bytes. Costs ~20s (it outlasts the agent's liveness ping) and raises -timeout to that floor")
	_ = fs.Parse(args)

	opts := doctor.Options{
		VM:         *vm,
		HWAddr:     *mac,
		Timeout:    *timeout,
		CLIVersion: buildinfo.Version,
		Probe:      *probe,
	}
	out := doctorOutput{json: *asJSON, verbose: *verbose}
	if *subnet != "" {
		p, err := limaaddr.ParseSubnet(*subnet)
		if err != nil {
			return opts, out, fmt.Errorf("-vm-subnet: %w", err)
		}
		opts.Subnet = p
	}
	if *mac != "" {
		hw, err := limaaddr.ParseHWAddr(*mac)
		if err != nil {
			return opts, out, fmt.Errorf("-vm-mac: %w", err)
		}
		opts.HWAddr = hw
	}
	return opts, out, nil
}

func runDoctor(args []string) int {
	opts, out, err := doctorFlags(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge doctor: %v\n", err)
		return 2
	}

	in, err := doctor.Gather(context.Background(), opts)
	if err != nil {
		// Exit 2 is "doctor could not gather", which is a different thing
		// from "doctor found problems" — scripts and the acceptance matrix
		// branch on the distinction.
		fmt.Fprintf(os.Stderr, "drawbridge doctor: %v\n", err)
		return 2
	}
	report := doctor.Classify(in)

	if out.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "drawbridge doctor: %v\n", err)
			return 2
		}
		return report.ExitCode()
	}
	renderDoctorReport(os.Stdout, stdoutStyles, report, out.verbose)
	return report.ExitCode()
}
