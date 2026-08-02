package main

import (
	"testing"
	"time"
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
