package main

// Presentation for the doctor verb. internal/doctor stays presentation-free —
// Report.Render is the plain fixture form and `-json` marshals the Report
// unstyled — while this file owns what a terminal shows, the same way
// render.go does for install/uninstall/status.
//
// The words are doctor's own: finding titles, evidence and remedy strings are
// printed verbatim (evidence indented, remedy behind its `→`), status tags
// keep their bracketed words, and the summary keeps Report.Summary's exact
// wording. Styling is emphasis only — NO_COLOR, TERM=dumb and piped output
// print the same words uncolored — with one documented layout rule on top
// (docs/doctor.md §6): the default is calm. Every finding is its title line;
// warn and fail add their remedy (the actionable line — or, lacking one,
// their first evidence line, so a verdict is never bare); skip adds its
// first evidence line (the reason lives there, e.g. "pass -probe"); ok and
// info add nothing — their titles are the whole message. -v restores full
// evidence for everything. The evidence is the justification; doctor -json
// carries all of it regardless.

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/charmbracelet/lipgloss"
)

// doctorTagWidth is the bracketed status column, sized for the longest tag —
// the TUI's doctorStatusW (internal/tui/doctorview.go), so both surfaces
// start every title at the same column instead of ragged behind `[ok]`.
const doctorTagWidth = len("[warn]")

const (
	// doctorRemedyIndent puts the remedy arrow at the title column and
	// doctorEvidenceIndent nests evidence two columns further in — the same
	// relationship the TUI's expanded finding renders.
	doctorRemedyIndent   = doctorTagWidth + 1
	doctorEvidenceIndent = doctorRemedyIndent + 2
)

// doctorStatusStyle mirrors internal/tui's doctor.Status → style mapping:
// `skip` is dim and `info` is the label color rather than a verdict color —
// check 11's job is discoverability, and it must be readable without ever
// coloring a run red or green.
func doctorStatusStyle(sty styles, s doctor.Status) lipgloss.Style {
	switch s {
	case doctor.StatusOK:
		return sty.ok
	case doctor.StatusWarn:
		return sty.warn
	case doctor.StatusFail:
		return sty.err
	case doctor.StatusSkip:
		return sty.dim
	default:
		return sty.key
	}
}

func renderDoctorReport(w io.Writer, sty styles, r doctor.Report, verbose bool) {
	meta := "CLI " + r.CLIVersion
	if r.VM != "" {
		meta += ", VM " + r.VM
	}
	meta += ", " + r.RanAt.Format(time.RFC3339)
	fmt.Fprintf(w, "drawbridge doctor — %s\n\n", sty.dim.Render(meta))

	elided := false
	for _, f := range r.Findings {
		tag := "[" + string(f.Status) + "]"
		pad := strings.Repeat(" ", max(doctorTagWidth-len(tag), 0)+1)
		fmt.Fprintf(w, "%s%s%s\n", doctorStatusStyle(sty, f.Status).Render(tag), pad, f.Title)

		evidence, remedy := f.Evidence, f.Remedy
		if !verbose {
			switch f.Status {
			case doctor.StatusWarn, doctor.StatusFail:
				// The remedy is the actionable line; a verdict without one
				// shows its first evidence line instead of standing bare.
				if remedy == "" && len(evidence) > 0 {
					evidence = evidence[:1]
					elided = elided || len(f.Evidence) > 1
				} else {
					elided = elided || len(evidence) > 0
					evidence = nil
				}
			case doctor.StatusSkip:
				// The reason a check did not run lives in its evidence
				// ("pass -probe"); one line of it is the message.
				if len(evidence) > 0 {
					elided = elided || len(evidence) > 1
					evidence = evidence[:1]
				}
			default: // ok, info: the title is the whole message.
				elided = elided || len(evidence) > 0
				evidence = nil
			}
		}
		for _, e := range evidence {
			for _, line := range strings.Split(strings.TrimRight(e, "\n"), "\n") {
				fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", doctorEvidenceIndent), sty.dim.Render(line))
			}
		}
		if remedy != "" {
			for i, line := range strings.Split(strings.TrimRight(remedy, "\n"), "\n") {
				prefix := strings.Repeat(" ", doctorRemedyIndent) + "→ "
				if i > 0 {
					prefix = strings.Repeat(" ", doctorRemedyIndent+2)
				}
				fmt.Fprintf(w, "%s%s\n", prefix, line)
			}
		}
	}

	fmt.Fprintf(w, "\n%s", renderDoctorSummary(sty, r))
	if elided {
		fmt.Fprintf(w, " %s", sty.dim.Render("(-v shows full evidence)"))
	}
	fmt.Fprintln(w)
}

// renderDoctorSummary is Report.Summary with the counts colored: a count wears
// its status color when it is nonzero and dims to background noise at zero.
// Under an ascii profile it must render Summary's exact bytes — pinned by
// TestRenderDoctorSummaryWords, because scripts and eyes both read this line.
func renderDoctorSummary(sty styles, r doctor.Report) string {
	n := map[doctor.Status]int{}
	for _, f := range r.Findings {
		n[f.Status]++
	}
	seg := func(st lipgloss.Style, count int, word string) string {
		s := fmt.Sprintf("%d %s", count, word)
		if count == 0 {
			return sty.dim.Render(s)
		}
		return st.Render(s)
	}
	return fmt.Sprintf("%d checks: %s, %s, %s, %s, %s",
		len(r.Findings),
		seg(sty.ok, n[doctor.StatusOK], "ok"),
		seg(sty.warn, n[doctor.StatusWarn], "warn"),
		seg(sty.err, n[doctor.StatusFail], "fail"),
		seg(sty.dim, n[doctor.StatusSkip], "skip"),
		seg(sty.key, n[doctor.StatusInfo], "info"))
}
