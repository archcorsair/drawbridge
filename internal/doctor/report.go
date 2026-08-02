// Package doctor is `drawbridge doctor`: the ordered check catalog of
// docs/doctor.md §4/§5, plus the thin impure layer that gathers what the
// checks classify.
//
// Two rules shape the package, and both are load-bearing:
//
//   - Every classification is a pure function over injected probe results.
//     The catalog is therefore reachable from fixtures — including the states
//     that took a week of field debugging to produce once — instead of only
//     from a broken machine.
//   - Doctor never mutates state. Probes are reads, remediations are printed,
//     and the sudo discriminator (§4 check 6) is an instruction to the user,
//     never a doctor-spawned `sudo`.
package doctor

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// Status is a finding's verdict. `info` exists for the checks whose job is
// discoverability rather than health (check 11): they must be readable
// without ever colouring a run red or green.
type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
	StatusSkip Status = "skip"
	StatusInfo Status = "info"
)

// Finding is one catalog entry's result. ID is stable — it is the catalog
// name or a transport-auth §7 check ID — because `-json` consumers and the
// acceptance matrix key on it, not on the prose.
type Finding struct {
	ID       string
	Title    string
	Status   Status
	Evidence []string       `json:",omitempty"` // verbatim probe lines, resolver Notes, log lines
	Remedy   string         `json:",omitempty"` // one line; empty when Status == ok
	Data     map[string]any `json:",omitempty"`
}

// Report is a whole run. Daemon is docs/doctor.md §D5: the matched VM's
// introspection snapshot, embedded verbatim when a socket answered and this
// build understood its schema. Two documents, shared types, one dependency
// direction — nothing is copied between shapes, and a nil here is the normal
// no-daemon case, never an error.
type Report struct {
	CLIVersion string
	RanAt      time.Time
	VM         string            `json:",omitempty"` // canonical ref, when one was selected
	Daemon     *introspect.State `json:",omitempty"`
	Findings   []Finding
}

func (r *Report) add(f ...Finding) { r.Findings = append(r.Findings, f...) }

// ExitCode is the contract scripts branch on: 0 when nothing failed (warns
// are allowed), 1 when anything did. 2 is the gather failure, which never
// produces a Report at all — see Gather.
func (r Report) ExitCode() int {
	for _, f := range r.Findings {
		if f.Status == StatusFail {
			return 1
		}
	}
	return 0
}

// Render writes the human form: one line per finding, evidence indented,
// remediation prefixed `→`.
func (r Report) Render(w io.Writer) {
	fmt.Fprintf(w, "drawbridge doctor — CLI %s", r.CLIVersion)
	if r.VM != "" {
		fmt.Fprintf(w, ", VM %s", r.VM)
	}
	fmt.Fprintf(w, ", %s\n\n", r.RanAt.Format(time.RFC3339))
	for _, f := range r.Findings {
		fmt.Fprintf(w, "[%s] %s\n", f.Status, f.Title)
		for _, e := range f.Evidence {
			for _, line := range strings.Split(strings.TrimRight(e, "\n"), "\n") {
				fmt.Fprintf(w, "      %s\n", line)
			}
		}
		if f.Remedy != "" {
			for i, line := range strings.Split(strings.TrimRight(f.Remedy, "\n"), "\n") {
				prefix := "    → "
				if i > 0 {
					prefix = "      "
				}
				fmt.Fprintf(w, "%s%s\n", prefix, line)
			}
		}
	}
	fmt.Fprintf(w, "\n%s\n", r.Summary())
}

// Summary counts the run, so a long report ends with the sentence a reader
// came for.
func (r Report) Summary() string {
	n := map[Status]int{}
	for _, f := range r.Findings {
		n[f.Status]++
	}
	return fmt.Sprintf("%d checks: %d ok, %d warn, %d fail, %d skip, %d info",
		len(r.Findings), n[StatusOK], n[StatusWarn], n[StatusFail], n[StatusSkip], n[StatusInfo])
}
