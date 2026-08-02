package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// doctorFixture exercises all five statuses, multi-line evidence with an
// embedded nested indent (the ne-filter shape), and a multi-line remedy.
func doctorFixture() doctor.Report {
	return doctor.Report{
		CLIVersion: "v0.1.0",
		RanAt:      time.Date(2026, 8, 1, 18, 0, 0, 0, time.UTC),
		VM:         "lima:drawbridge",
		Findings: []doctor.Finding{
			{ID: "providers", Title: "VM providers — 1 running vz instance(s)", Status: doctor.StatusOK,
				Evidence: []string{"providers: lima, colima"}},
			{ID: "agent", Title: "guest agent — version skew", Status: doctor.StatusFail,
				Evidence: []string{"ss: listening on 127.0.0.1:4777"},
				Remedy:   "drawbridge up <vm> re-pushes the embedded agent\nand heals the skew"},
			{ID: "ne-filter", Title: "network content filters — 2 activated", Status: doctor.StatusWarn,
				Evidence: []string{"three signatures observed live:\n  1. first-payload DPI stall"}},
			{ID: "probe", Title: "half-close probe — not run", Status: doctor.StatusSkip,
				Evidence: []string{"pass -probe to run it."}},
			{ID: "skiplist", Title: "skip-list — guest :22 is not mirrored", Status: doctor.StatusInfo,
				Evidence: []string{"the default skip-list is \"22\""}},
		},
	}
}

// The calm default: every finding is its title line; warn/fail add only the
// remedy arrow (or their first evidence line when no remedy exists); skip
// adds its one-line reason; ok and info are title-only. Words identical to
// the Report's own; -v is the busy form.
func TestRenderDoctorReport(t *testing.T) {
	var b bytes.Buffer
	renderDoctorReport(&b, asciiStyles(), doctorFixture(), false)
	out := b.String()

	for _, want := range []string{
		"drawbridge doctor — CLI v0.1.0, VM lima:drawbridge, 2026-08-01T18:00:00Z\n",
		// The tag column: [ok] padded to the [warn] width, titles aligned.
		"[ok]   VM providers — 1 running vz instance(s)\n",
		"[fail] guest agent — version skew\n",
		// The remedy arrow sits at the title column; continuations align under
		// the remedy text, exactly like Report.Render's relationship.
		"\n       → drawbridge up <vm> re-pushes the embedded agent\n         and heals the skew\n",
		// A warn with no remedy shows its first evidence line, never a bare tag.
		"\n         three signatures observed live:\n           1. first-payload DPI stall\n",
		// skip keeps one line of evidence: how to un-skip is the message.
		"\n         pass -probe to run it.\n",
		"\n5 checks: 1 ok, 1 warn, 1 fail, 1 skip, 1 info (-v shows full evidence)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for name, absent := range map[string]string{
		"ok evidence":                    "providers: lima, colima",
		"fail evidence (remedy present)": "ss: listening on 127.0.0.1:4777",
		"info evidence":                  "the default skip-list is \"22\"",
	} {
		if strings.Contains(out, absent) {
			t.Errorf("%s rendered without -v:\n%s", name, out)
		}
	}
}

// -v restores every finding's full evidence, and the hint disappears with
// nothing left to show.
func TestRenderDoctorReportVerbose(t *testing.T) {
	var b bytes.Buffer
	renderDoctorReport(&b, asciiStyles(), doctorFixture(), true)
	out := b.String()
	for _, want := range []string{
		"\n         providers: lima, colima\n",
		"\n         ss: listening on 127.0.0.1:4777\n",
		"\n         the default skip-list is \"22\"\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("-v did not restore evidence %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "(-v shows full evidence") {
		t.Errorf("hint printed when -v already showed everything:\n%s", out)
	}
}

// A report with nothing elided must not advertise a -v that would show
// nothing new: title-only findings and a warn whose single evidence line
// already prints (no remedy) leave no hidden content.
func TestRenderDoctorNoHintWithoutElision(t *testing.T) {
	r := doctor.Report{Findings: []doctor.Finding{
		{ID: "a", Title: "a", Status: doctor.StatusOK},
		{ID: "b", Title: "b", Status: doctor.StatusWarn, Evidence: []string{"e"}},
	}}
	var b bytes.Buffer
	renderDoctorReport(&b, asciiStyles(), r, false)
	if strings.Contains(b.String(), "(-v shows full evidence") {
		t.Errorf("hint printed with no elided evidence:\n%s", b.String())
	}
}

// The summary's words are Report.Summary's exact bytes under an ascii profile:
// color decorates the counts and never rewrites them.
func TestRenderDoctorSummaryWords(t *testing.T) {
	for _, r := range []doctor.Report{
		{},
		doctorFixture(),
		{Findings: []doctor.Finding{{Status: doctor.StatusFail}, {Status: doctor.StatusFail}}},
	} {
		if got, want := renderDoctorSummary(asciiStyles(), r), r.Summary(); got != want {
			t.Errorf("summary = %q, want %q", got, want)
		}
	}
}

// Colored output keeps every status word intact — color is emphasis, never
// the carrier (§3.6's rule, and the reason NO_COLOR loses nothing).
func TestRenderDoctorColoredKeepsWords(t *testing.T) {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.ANSI)
	sty := newStyles(r)
	var b bytes.Buffer
	renderDoctorReport(&b, sty, doctorFixture(), false)
	out := b.String()
	if !strings.Contains(out, "\x1b[") {
		t.Fatal("ANSI profile produced no styling; the colored path is untested")
	}
	for _, want := range []string{"[ok]", "[warn]", "[fail]", "[skip]", "[info]", "1 fail", "1 warn"} {
		if !strings.Contains(out, want) {
			t.Errorf("colored output lost the word %q:\n%s", want, out)
		}
	}
}
