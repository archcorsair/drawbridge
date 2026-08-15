package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
)

// The TUI's flags exist to reach the doctor view (§4.3), so a value that stops
// threading is invisible until T3 — pinned here instead.
func TestTUIFlagsThreadThrough(t *testing.T) {
	def, err := tuiFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if def.VM != "" || def.Timeout != 30*time.Second {
		t.Fatalf("defaults drifted from `drawbridge doctor`: %+v", def)
	}
	if def.CLIVersion == "" {
		t.Fatal("the CLI version does not reach the TUI; the skew chip has nothing to compare")
	}

	got, err := tuiFlags([]string{"-vm", "colima:default", "-vm-subnet", "192.168.105.0/24", "-vm-mac", "52:55:55:12:34:56", "-timeout", "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if got.VM != "colima:default" || got.Timeout != 5*time.Second || got.HWAddr == "" || !got.Subnet.IsValid() {
		t.Fatalf("flags stopped threading: %+v", got)
	}
}

// The canned-doctor demo seam: unset env keeps the production path (nil
// GatherDoctor), a set one substitutes the fixture's reports, and the probe
// flag selects the probe file. Only the pure read half is tested; the delay
// wrapper is a select the doctor view already exercises.
func TestCannedDoctorSeam(t *testing.T) {
	t.Setenv(envDemoDoctor, "")
	opts, err := tuiFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.GatherDoctor != nil {
		t.Fatal("without the env var the production gather must stay in force")
	}

	dir := t.TempDir()
	write := func(name string, r doctor.Report) {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(cannedPlainFile, doctor.Report{VM: "demo:plain",
		Findings: []doctor.Finding{{ID: "half-close", Status: doctor.StatusSkip}}})
	write(cannedProbeFile, doctor.Report{VM: "demo:probe",
		Findings: []doctor.Finding{{ID: "half-close", Status: doctor.StatusOK}}})

	t.Setenv(envDemoDoctor, dir)
	opts, err = tuiFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.GatherDoctor == nil {
		t.Fatal("the env var did not wire the canned gather")
	}
	plain, err := readCannedReport(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := readCannedReport(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if plain.VM != "demo:plain" || plain.Findings[0].Status != doctor.StatusSkip {
		t.Fatalf("plain report = %+v", plain)
	}
	if probe.VM != "demo:probe" || probe.Findings[0].Status != doctor.StatusOK {
		t.Fatalf("probe report = %+v", probe)
	}

	if err := os.WriteFile(filepath.Join(dir, cannedPlainFile), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCannedReport(dir, false); err == nil {
		t.Fatal("a malformed canned report must surface as a gather error, not render as empty findings")
	}
}

// A malformed flag is a bad invocation, not a screen: the verb exits 2 without
// ever taking over the terminal.
func TestTUIRejectsMalformedFlags(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"vm", []string{"-vm", "lima:has/slash"}},
		{"subnet", []string{"-vm-subnet", "not-a-cidr"}},
		{"mac", []string{"-vm-mac", "not-a-mac"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runTUI(tc.args); got != 2 {
				t.Fatalf("runTUI(%v) = %d, want 2", tc.args, got)
			}
		})
	}
}
