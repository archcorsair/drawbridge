package doctor

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     int
	}{
		{"all ok", []Status{StatusOK, StatusOK}, 0},
		{"warns are allowed", []Status{StatusOK, StatusWarn, StatusSkip, StatusInfo}, 0},
		{"one fail", []Status{StatusOK, StatusFail, StatusWarn}, 1},
		{"empty", nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var r Report
			for _, s := range tc.statuses {
				r.add(Finding{ID: "x", Status: s})
			}
			if got := r.ExitCode(); got != tc.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRender(t *testing.T) {
	r := Report{
		CLIVersion: "v0.1.0",
		RanAt:      time.Date(2026, 8, 1, 18, 0, 0, 0, time.UTC),
		VM:         "colima:colima",
		Findings: []Finding{
			{ID: "agent", Title: "guest agent — v0.1.0, active", Status: StatusOK},
			{ID: "vznat-route", Title: "vzNAT route — missing", Status: StatusFail,
				Evidence: []string{"no entry for 192.168.64.0/24"},
				Remedy:   "sudo route -n add -net 192.168.64.0/24 192.168.64.1"},
		},
	}
	var b bytes.Buffer
	r.Render(&b)
	out := b.String()
	for _, want := range []string{
		"drawbridge doctor — CLI v0.1.0, VM colima:colima",
		"[ok] guest agent",
		"[fail] vzNAT route — missing",
		"      no entry for 192.168.64.0/24",
		"    → sudo route -n add -net",
		"2 checks: 1 ok, 0 warn, 1 fail",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// A multi-line remedy indents its continuation lines under the arrow rather
// than repeating it — a numbered list has to read as one remedy.
func TestRenderMultilineRemedy(t *testing.T) {
	var b bytes.Buffer
	Report{Findings: []Finding{{ID: "x", Title: "x", Status: StatusFail, Remedy: "first\nsecond"}}}.Render(&b)
	out := b.String()
	if !strings.Contains(out, "    → first\n      second\n") {
		t.Fatalf("continuation line not indented:\n%s", out)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	in := Inputs{
		CLIVersion: "dev",
		RanAt:      time.Now().UTC().Truncate(time.Second),
		VM:         "lima:drawbridge",
		Guest:      healthyGuest(),
		Providers: ProvidersInput{
			Providers: []string{"lima"},
			Instances: []vmprovider.Instance{vz("lima", "drawbridge", true)},
		},
	}
	in.Bind = BindOf(in.Guest.Listeners, in.Guest.GuestIPs)
	r := Classify(in)

	blob, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.CLIVersion != r.CLIVersion || back.VM != r.VM || len(back.Findings) != len(r.Findings) {
		t.Fatalf("round trip lost data: %+v", back)
	}
	for i, f := range back.Findings {
		if f.ID != r.Findings[i].ID || f.Status != r.Findings[i].Status {
			t.Fatalf("finding %d changed: %+v vs %+v", i, f, r.Findings[i])
		}
	}
}

// Classify runs the catalog in report order, then the auth block.
func TestClassifyOrder(t *testing.T) {
	r := Classify(Inputs{CLIVersion: "dev"})
	want := []string{
		IDProviders, IDGuestPrereqs, IDAgent, IDResolution, IDVZNATRoute,
		IDLocalNetwork, IDNEFilter, IDHalfClose, IDDaemon, IDCoexistence,
		IDSkipVisible, IDAuth,
	}
	got := ids(r.Findings)
	if len(got) != len(want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("finding %d = %q, want %q (order is %v)", i, got[i], want[i], got)
		}
	}
}

// An empty machine — no providers, no VM, no daemon — still produces a whole
// report rather than an error. Diagnosing that state is doctor's job.
func TestClassifyEmptyMachine(t *testing.T) {
	r := Classify(Inputs{CLIVersion: "dev"})
	if r.ExitCode() != 1 {
		t.Fatalf("exit = %d, want 1 (no providers is a fail)", r.ExitCode())
	}
	wantStatus(t, findingByID(t, r.Findings, IDProviders), StatusFail)
	for _, id := range []string{IDGuestPrereqs, IDAgent, IDResolution} {
		wantStatus(t, findingByID(t, r.Findings, id), StatusSkip)
	}
}
