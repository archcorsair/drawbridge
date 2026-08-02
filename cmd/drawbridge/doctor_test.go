package main

import (
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
)

// A malformed flag is a bad invocation, not a diagnosis: doctor exits 2
// before it probes anything.
func TestDoctorRejectsMalformedFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"subnet", []string{"-vm-subnet", "not-a-cidr"}},
		{"public subnet", []string{"-vm-subnet", "8.8.8.0/24"}},
		{"mac", []string{"-vm-mac", "not-a-mac"}},
		{"vm", []string{"-vm", "lima:has/slash"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := runDoctor(tc.args); got != 2 {
				t.Fatalf("runDoctor(%v) = %d, want 2", tc.args, got)
			}
		})
	}
}

// The active probe is opt-in, and its whole effect is one bool reaching
// Gather: a -probe that silently did not thread through would leave check 8
// reporting "pass -probe to run it" to a user who just did.
func TestDoctorProbeFlagThreadsThrough(t *testing.T) {
	off, defaults, err := doctorFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if off.Probe {
		t.Fatal("Probe defaults to true; the active probe must be opt-in")
	}
	if defaults.verbose {
		t.Fatal("verbose defaults to true; the compact form must be the default")
	}

	on, out, err := doctorFlags([]string{"-probe", "-json", "-v", "-vm", "lima:drawbridge", "-timeout", "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if !on.Probe {
		t.Fatal("-probe did not reach Options.Probe")
	}
	if !out.verbose {
		t.Fatal("-v did not reach doctorOutput.verbose")
	}
	if !out.json || on.VM != "lima:drawbridge" || on.Timeout != 5*time.Second {
		t.Fatalf("the other flags stopped threading: %+v out=%+v", on, out)
	}
	// The floor lives in Gather so every caller gets it, not just this verb —
	// asserted here because -timeout 5s is exactly the invocation that would
	// truncate the probe into a false killer-signature report.
	if doctor.ProbeBudget <= doctor.ProbePostFINWindow {
		t.Fatalf("ProbeBudget %s does not cover the post-FIN window %s", doctor.ProbeBudget, doctor.ProbePostFINWindow)
	}
}
