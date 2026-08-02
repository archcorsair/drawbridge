package doctor

// The transport-auth check block (docs/doctor.md §5, docs/transport-auth.md
// §7). Two evidence classes feed it: a state comparison doctor computes
// itself (authoritative), and runtime evidence from the daemon log tail (the
// ID-tagged refusal ring lands with the introspection substrate).
//
// The disclosure rule is absolute and enforced here rather than at the call
// sites: digests are compared in memory, and what reaches a report is a
// verdict plus at most an 8-hex-character prefix per side. Never bytes,
// never proofs, never a full digest — transport-auth §5 sanctions the prefix
// precisely because comparison is doctor's whole job.

import (
	"fmt"
	"strings"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// Auth finding IDs — the transport-auth §7 contract.
const (
	IDAuth             = "auth"
	IDAuthMacMissing   = "auth-mac-missing-secret"
	IDAuthGuestMissing = "auth-guest-missing-secret"
	IDAuthMismatch     = "auth-mismatch"
	IDAuthWrongPeer    = "auth-wrong-peer"
	IDAuthFilePerms    = "auth-file-perms"
)

// digestPrefixLen is the whole disclosure budget: enough to make two files
// distinguishable at a glance, useless as a preimage handle.
const digestPrefixLen = 8

// SecretFile is one side's transport secret as doctor could observe it.
// Digest is the full sha256 and exists only for the in-memory comparison —
// nothing renders it.
type SecretFile struct {
	Path    string
	Present bool
	Mode    string // octal, as stat prints it
	Owner   string // "user" on the Mac side, "user:group" in the guest
	Size    int64

	Digest string // sha256 hex of the canonical secret bytes; "" when unknown

	Malformed bool
	Why       string // why malformed, or why the digest is unknown
}

// prefix is the only rendering of a digest this package performs.
func (s SecretFile) prefix() string {
	if len(s.Digest) < digestPrefixLen {
		return "unknown"
	}
	return s.Digest[:digestPrefixLen]
}

// AuthEvidence is one runtime observation, tagged with the check ID its
// emit site belongs to. Source names the vantage it came from — "ring" for
// the daemon's ID-tagged refusal ring (authoritative about its own emit
// site, and the only vantage a foreground daemon has, since it writes no log
// file), "log" for a line matched out of the daemon log tail. Empty means
// log, so a fixture built before the ring existed still reads correctly.
type AuthEvidence struct {
	ID     string
	Line   string
	Source string
}

// label is how one observation renders. The prefix is load-bearing: a
// digest-comparison verdict and a string matched out of a log are not the
// same grade of evidence, and the report has to let a reader tell.
func (e AuthEvidence) label() string {
	return firstNonEmpty(e.Source, "log") + ": " + e.Line
}

// AuthInput is everything the auth block classifies.
type AuthInput struct {
	VM               string
	Mac              SecretFile
	Guest            SecretFile
	MacSkip          string // non-empty: no VM was selected, so no per-VM path exists
	GuestSkip        string // non-empty: the guest side could not be compared
	Evidence         []AuthEvidence
	ResolutionSource string
}

// MatchAuthLog tags a daemon log tail with the transport-auth §7 rows doctor
// can recognise. String matching is this phase's only runtime vantage; the
// ID-tagged ring replaces it without changing this function's output shape.
func MatchAuthLog(lines []string) []AuthEvidence {
	var out []AuthEvidence
	for _, l := range lines {
		line := strings.TrimSpace(l)
		switch {
		// Row 4. It also carries row 5's wrong-peer job: the refused side
		// closes first, so the Mac rarely reaches the row-5 verdict.
		case strings.Contains(line, "closed during transport authentication"):
			out = append(out, AuthEvidence{ID: IDAuthMismatch, Line: line})
		// Row 5, when it does happen.
		case strings.Contains(line, "presented an invalid transport secret"):
			out = append(out, AuthEvidence{ID: IDAuthWrongPeer, Line: line})
		// Row 6.
		case strings.Contains(line, "closed the connection immediately"):
			out = append(out, AuthEvidence{ID: IDAuthMacMissing, Line: line})
		// Row 8, either side's half.
		case strings.Contains(line, "transport secret is unusable"):
			out = append(out, AuthEvidence{ID: IDAuthFilePerms, Line: line})
		}
	}
	return out
}

// MatchAuthRing lifts the daemon's refusal ring into evidence. No string
// matching: every entry is already tagged with the check ID of the site that
// emitted it (docs/transport-auth.md §7), which is the whole reason the ring
// exists — the log tail is prose that has to be recognised, and a foreground
// daemon writes no log at all. Non-auth IDs (mirror skips, row 7, row 9)
// belong to checks 9 and 11 and are left to them.
func MatchAuthRing(refusals []introspect.Refusal) []AuthEvidence {
	var out []AuthEvidence
	for _, r := range refusals {
		switch r.ID {
		case IDAuth, IDAuthMacMissing, IDAuthGuestMissing, IDAuthMismatch, IDAuthWrongPeer, IDAuthFilePerms:
			out = append(out, AuthEvidence{ID: r.ID, Line: strings.TrimSpace(r.Line), Source: "ring"})
		}
	}
	return out
}

func (in AuthInput) evidenceFor(id string) []string {
	var out []string
	for _, e := range in.Evidence {
		if e.ID == id {
			out = append(out, e.label())
		}
	}
	return out
}

func (in AuthInput) hasEvidence(id string) bool { return len(in.evidenceFor(id)) > 0 }

// CheckAuth is the whole §5 block. It emits at most one primary finding
// (the umbrella or one of the three state IDs), plus auth-file-perms when a
// file is unusable and auth-wrong-peer when the wire says one thing while
// the files say another.
func CheckAuth(in AuthInput) []Finding {
	var out []Finding

	if f, ok := checkAuthFilePerms(in); ok {
		out = append(out, f)
	}
	out = append(out, primaryAuthFinding(in))
	if f, ok := checkWrongPeer(in); ok {
		out = append(out, f)
	}
	return out
}

// checkAuthFilePerms is the row-8 condition on either side: present but not
// 0600, not owned by the expected principal, or not 64 lowercase hex + \n.
func checkAuthFilePerms(in AuthInput) (Finding, bool) {
	var bad []string
	if in.Mac.Present {
		if in.Mac.Malformed {
			bad = append(bad, fmt.Sprintf("Mac %s: %s", in.Mac.Path, in.Mac.Why))
		}
		if in.Mac.Mode != "" && in.Mac.Mode != "600" {
			bad = append(bad, fmt.Sprintf("Mac %s: mode %s, want 600", in.Mac.Path, in.Mac.Mode))
		}
	}
	if in.Guest.Present {
		if in.Guest.Malformed {
			bad = append(bad, fmt.Sprintf("guest %s: %s", in.Guest.Path, in.Guest.Why))
		}
		if in.Guest.Mode != "" && in.Guest.Mode != "600" {
			bad = append(bad, fmt.Sprintf("guest %s: mode %s, want 600", in.Guest.Path, in.Guest.Mode))
		}
		if in.Guest.Owner != "" && in.Guest.Owner != "root:root" {
			bad = append(bad, fmt.Sprintf("guest %s: owner %s, want root:root", in.Guest.Path, in.Guest.Owner))
		}
	}
	logged := in.evidenceFor(IDAuthFilePerms)
	if len(bad) == 0 && len(logged) == 0 {
		return Finding{}, false
	}
	f := Finding{
		ID:       IDAuthFilePerms,
		Title:    "transport secret — unusable file",
		Status:   StatusFail,
		Evidence: append(bad, logged...),
		Remedy: "a transport secret is 64 lowercase hex characters plus a newline, mode 0600 (root:root in the guest);\n" +
			"a malformed one fails closed. Delete the Mac file and re-run `drawbridge up " + in.VM + "` to reprovision both sides",
	}
	return f, true
}

// primaryAuthFinding is the state comparison — the authoritative vantage.
func primaryAuthFinding(in AuthInput) Finding {
	f := Finding{ID: IDAuth, Title: "transport authentication"}

	// The secret is per-VM, so with no VM chosen there is nothing to compare
	// — and a path assembled from an empty ref would be a worse answer than
	// none.
	if in.MacSkip != "" {
		f.Status = StatusSkip
		f.Title = "transport authentication — not compared"
		f.Evidence = append(f.Evidence, in.MacSkip)
		return f
	}

	// The guest side could not be read at all (VM stopped, sudo -n refused).
	// Mac-side file checks still ran, so say what is known rather than
	// nothing.
	if in.GuestSkip != "" || (in.Guest.Present && in.Guest.Digest == "") {
		reason := firstNonEmpty(in.GuestSkip, in.Guest.Why, "the guest digest could not be read")
		if !in.Mac.Present {
			f.Status = StatusWarn
			f.Title = "transport authentication — no Mac-side secret"
			f.Evidence = append(f.Evidence,
				"expected at "+in.Mac.Path+" (absent)",
				"a daemon started now would run UNAUTHENTICATED: any process that reaches the transport is trusted.",
				"guest side not compared: "+reason)
			f.Remedy = "drawbridge up " + in.VM + "    # provisions a secret on both sides"
			return f
		}
		f.Status = StatusSkip
		f.Title = "transport authentication — guest side not compared"
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("Mac secret %s present (sha256 %s…)", in.Mac.Path, in.Mac.prefix()),
			"guest side not compared: "+reason)
		return f
	}

	switch {
	case !in.Mac.Present && !in.Guest.Present:
		// The §6 fail-open state. Warn, not fail: the bare dev flow
		// (`just agent-up`, no `up`) is legitimate and loudly logged, and a
		// red here would train dev users to ignore red.
		f.Status = StatusWarn
		f.Title = "transport authentication — UNAUTHENTICATED (no secret on either side)"
		f.Evidence = append(f.Evidence,
			"Mac:   "+in.Mac.Path+" (absent)",
			"guest: "+in.Guest.Path+" (absent)",
			"the transport is unauthenticated: any process that reaches it is trusted.")
		f.Remedy = "drawbridge up " + in.VM + "    # provisions a secret on both sides"

	case !in.Mac.Present && in.Guest.Present:
		f = Finding{ID: IDAuthMacMissing, Title: "transport authentication — the Mac side has no secret"}
		f.Status = StatusFail
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("guest %s present (sha256 %s…)", in.Guest.Path, in.Guest.prefix()),
			"Mac "+in.Mac.Path+" absent — the agent will refuse every conn this Mac opens.")
		f.Evidence = append(f.Evidence, in.evidenceFor(IDAuthMacMissing)...)
		f.Remedy = "`drawbridge up " + in.VM + "` writes it; `sudo drawbridge install` points the daemon at it"

	case in.Mac.Present && !in.Guest.Present:
		f = Finding{ID: IDAuthGuestMissing, Title: "transport authentication — the guest has no secret"}
		f.Status = StatusFail
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("Mac %s present (sha256 %s…)", in.Mac.Path, in.Mac.prefix()),
			"guest "+in.Guest.Path+" absent — this Mac requires authentication and the agent cannot answer.")
		f.Evidence = append(f.Evidence, in.evidenceFor(IDAuthGuestMissing)...)
		f.Remedy = "drawbridge up " + in.VM + "    # provisions one in the guest"

	case in.Mac.Digest != in.Guest.Digest:
		f = Finding{ID: IDAuthMismatch, Title: "transport authentication — the two sides hold different secrets"}
		f.Status = StatusFail
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("Mac   %s sha256 %s…", in.Mac.Path, in.Mac.prefix()),
			fmt.Sprintf("guest %s sha256 %s…", in.Guest.Path, in.Guest.prefix()))
		f.Evidence = append(f.Evidence, in.evidenceFor(IDAuthMismatch)...)
		f.Remedy = "re-run `drawbridge up " + in.VM + "` to converge (the Mac file is authoritative; the guest follows it)"

	default:
		f.Status = StatusOK
		f.Title = "transport authentication — mutual auth on every conn"
		f.Evidence = append(f.Evidence, fmt.Sprintf("both sides hold the same secret (sha256 %s…)", in.Mac.prefix()))
	}
	return f
}

// checkWrongPeer is evidence-only, and deliberately suppressed when the
// digests differ: then the same log line corroborates auth-mismatch instead
// (one condition, two vantage points — transport-auth §7's own note).
func checkWrongPeer(in AuthInput) (Finding, bool) {
	digestsMatch := in.Mac.Present && in.Guest.Present && in.Mac.Digest != "" && in.Mac.Digest == in.Guest.Digest
	if !digestsMatch {
		return Finding{}, false
	}
	lines := append(in.evidenceFor(IDAuthMismatch), in.evidenceFor(IDAuthWrongPeer)...)
	if len(lines) == 0 {
		return Finding{}, false
	}
	src := firstNonEmpty(in.ResolutionSource, "unknown")
	f := Finding{
		ID:     IDAuthWrongPeer,
		Title:  "transport authentication — the daemon authenticated against something that is not this VM's agent",
		Status: StatusFail,
		Evidence: append([]string{
			fmt.Sprintf("this VM's provisioned pair matches (sha256 %s…), yet the wire refused authentication — the daemon is not talking to it.", in.Mac.prefix()),
			"resolution source: " + src,
		}, lines...),
		Remedy: "check `-vm`, and whether the transport fell back to the loopback forwarder — the forwarded 127.0.0.1:" +
			fmt.Sprint(ControlPort) + " port is not attributable to a VM",
	}
	return f, true
}
