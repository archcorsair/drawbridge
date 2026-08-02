package doctor

import (
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// Two secrets' digests. A flipped hex digit in the secret — the phase's
// live mismatch recipe — moves every byte of the digest, so the two prefixes
// differ too, which is what makes the printed evidence worth printing.
const (
	digestA = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	digestB = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"
)

func macSecret(digest string) SecretFile {
	return SecretFile{Path: "/Users/x/Library/Application Support/drawbridge/transport-secret-lima-dev",
		Present: true, Mode: "600", Owner: "x", Size: 65, Digest: digest}
}

func guestSecret(digest string) SecretFile {
	return SecretFile{Path: "/etc/drawbridge/transport-secret",
		Present: true, Mode: "600", Owner: "root:root", Size: 65, Digest: digest}
}

func findingByID(t *testing.T, fs []Finding, id string) Finding {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no %q finding in %v", id, ids(fs))
	return Finding{}
}

func noFindingByID(t *testing.T, fs []Finding, id string) {
	t.Helper()
	for _, f := range fs {
		if f.ID == id {
			t.Fatalf("%q was emitted and must not have been: %s", id, f.Title)
		}
	}
}

func ids(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// The state-comparison matrix of §5, first column.
func TestCheckAuthStateMatrix(t *testing.T) {
	tests := []struct {
		name   string
		mac    SecretFile
		guest  SecretFile
		wantID string
		want   Status
		says   string
	}{
		{"both present and equal", macSecret(digestA), guestSecret(digestA), IDAuth, StatusOK, "mutual auth on every conn"},
		{"both absent", SecretFile{Path: "/mac"}, SecretFile{Path: "/guest"}, IDAuth, StatusWarn, "UNAUTHENTICATED"},
		{"mac missing", SecretFile{Path: "/mac"}, guestSecret(digestA), IDAuthMacMissing, StatusFail, "sudo drawbridge install"},
		{"guest missing", macSecret(digestA), SecretFile{Path: "/guest"}, IDAuthGuestMissing, StatusFail, "drawbridge up lima:dev"},
		{"digests differ", macSecret(digestA), guestSecret(digestB), IDAuthMismatch, StatusFail, "converge"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckAuth(AuthInput{VM: "lima:dev", Mac: tc.mac, Guest: tc.guest})
			f := findingByID(t, got, tc.wantID)
			wantStatus(t, f, tc.want)
			wantContains(t, f, tc.says)
		})
	}
}

// The both-absent state is a warn, not a fail: the bare dev flow is
// legitimate, and a red here would train dev users to ignore red (§5).
func TestBothAbsentIsWarnNotFail(t *testing.T) {
	r := Report{Findings: CheckAuth(AuthInput{VM: "lima:dev", Mac: SecretFile{Path: "/mac"}, Guest: SecretFile{Path: "/guest"}})}
	if r.ExitCode() != 0 {
		t.Fatal("an unauthenticated-but-legitimate dev transport made doctor exit 1")
	}
}

// The disclosure rule: verdicts and at most an 8-hex-character prefix per
// side. Never a full digest, anywhere in the report.
func TestAuthNeverPrintsAFullDigest(t *testing.T) {
	in := AuthInput{VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestB)}
	for _, f := range CheckAuth(in) {
		hay := f.Title + strings.Join(f.Evidence, "") + f.Remedy
		for _, d := range []string{digestA, digestB} {
			if strings.Contains(hay, d) {
				t.Fatalf("%s leaked a full digest", f.ID)
			}
			if !strings.Contains(hay, d[:digestPrefixLen]) {
				t.Fatalf("%s should carry the %d-character prefix", f.ID, digestPrefixLen)
			}
			if strings.Contains(hay, d[:digestPrefixLen+1]) {
				t.Fatalf("%s disclosed more than %d characters of a digest", f.ID, digestPrefixLen)
			}
		}
	}
}

func TestCheckAuthFilePerms(t *testing.T) {
	tests := []struct {
		name  string
		mac   SecretFile
		guest SecretFile
		says  string
	}{
		{"mac mode", func() SecretFile { s := macSecret(digestA); s.Mode = "644"; return s }(), guestSecret(digestA), "mode 644, want 600"},
		{"guest mode", macSecret(digestA), func() SecretFile { s := guestSecret(digestA); s.Mode = "644"; return s }(), "mode 644, want 600"},
		{"guest owner", macSecret(digestA), func() SecretFile { s := guestSecret(digestA); s.Owner = "ubuntu:ubuntu"; return s }(), "want root:root"},
		{"mac malformed", func() SecretFile {
			s := macSecret("")
			s.Malformed, s.Why = true, "malformed transport secret: want 64 hex characters, got 7"
			return s
		}(), guestSecret(digestA), "got 7"},
		{"guest wrong size", macSecret(digestA), func() SecretFile {
			s := guestSecret(digestA)
			s.Malformed, s.Why = true, "12 bytes, want 65 (64 hex characters plus a newline)"
			return s
		}(), "want 65"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckAuth(AuthInput{VM: "lima:dev", Mac: tc.mac, Guest: tc.guest})
			f := findingByID(t, got, IDAuthFilePerms)
			wantStatus(t, f, StatusFail)
			wantContains(t, f, tc.says)
			wantContains(t, f, "64 lowercase hex characters")
		})
	}
}

func TestCheckAuthFilePermsSilentWhenHealthy(t *testing.T) {
	noFindingByID(t, CheckAuth(AuthInput{VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestA)}), IDAuthFilePerms)
}

// --- runtime evidence ------------------------------------------------------

const (
	row4Line = "drawbridged: mirror: agent at tcp://127.0.0.1:4777 closed during transport authentication (source=ssh-forwarder) — the guest's secret differs, the agent predates auth, or this is a DIFFERENT VM's agent reached via a fallback path"
	row5Line = "drawbridged: peer at tcp://192.168.64.9:4777 presented an invalid transport secret: this is NOT the agent 'lima:dev' was provisioned for"
	row6Line = "drawbridged: mirror: agent at tcp://192.168.64.2:4777 closed the connection immediately — if that guest was provisioned with a transport secret"
	row7Line = "drawbridged: macsync: refused reverse dial to 127.0.0.1:5432 (proto 6): not a port this Mac advertised"
)

func TestMatchAuthLog(t *testing.T) {
	got := MatchAuthLog([]string{row4Line, row5Line, row6Line, row7Line, "drawbridged: mirror: mirroring guest tcp :8080"})
	want := []string{IDAuthMismatch, IDAuthWrongPeer, IDAuthMacMissing}
	if len(got) != len(want) {
		t.Fatalf("evidence = %v, want %d entries", got, len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("evidence[%d].ID = %q, want %q", i, got[i].ID, id)
		}
	}
}

// Row 4 while the provisioned pair matches is THE wrong-peer signature: the
// daemon authenticated against something that is not this VM's agent.
func TestAuthWrongPeerFromRow4(t *testing.T) {
	got := CheckAuth(AuthInput{
		VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestA),
		Evidence:         MatchAuthLog([]string{row4Line}),
		ResolutionSource: "ssh-forwarder",
	})
	f := findingByID(t, got, IDAuthWrongPeer)
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "resolution source: ssh-forwarder")
	wantContains(t, f, "loopback forwarder")
	// The umbrella still reports the files as healthy — they are.
	wantStatus(t, findingByID(t, got, IDAuth), StatusOK)
}

// Suppressed when the digests differ: then the same line corroborates
// auth-mismatch, and emitting both would report one condition twice.
func TestAuthWrongPeerSuppressedOnMismatch(t *testing.T) {
	got := CheckAuth(AuthInput{
		VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestB),
		Evidence: MatchAuthLog([]string{row4Line}),
	})
	noFindingByID(t, got, IDAuthWrongPeer)
	f := findingByID(t, got, IDAuthMismatch)
	wantContains(t, f, "closed during transport authentication")
}

func TestAuthWrongPeerNeedsEvidence(t *testing.T) {
	noFindingByID(t, CheckAuth(AuthInput{VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestA)}), IDAuthWrongPeer)
}

// --- the guest half unavailable --------------------------------------------

// VM not running: guest-side comparison skips, Mac-side file checks still run.
func TestCheckAuthGuestSkipped(t *testing.T) {
	got := CheckAuth(AuthInput{VM: "lima:dev", Mac: macSecret(digestA), GuestSkip: "colima:colima is not running"})
	f := findingByID(t, got, IDAuth)
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "is not running")
	wantContains(t, f, digestA[:digestPrefixLen])
}

// The Mac side being absent is worth flagging on sight even when the guest
// could not be compared: a daemon started now runs unauthenticated.
func TestCheckAuthGuestSkippedAndMacAbsent(t *testing.T) {
	got := CheckAuth(AuthInput{VM: "lima:dev", Mac: SecretFile{Path: "/mac"}, GuestSkip: "several VMs are running — pass -vm"})
	f := findingByID(t, got, IDAuth)
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "UNAUTHENTICATED")
	wantContains(t, f, "drawbridge up lima:dev")
}

// `sudo -n` refused in the guest: the file is there, the digest is not, and
// doctor says which rather than guessing at a verdict.
func TestCheckAuthGuestDigestUnreadable(t *testing.T) {
	guest := guestSecret("")
	guest.Why = "`sudo -n sha256sum` was refused in the guest, so the digests could not be compared"
	got := CheckAuth(AuthInput{VM: "lima:dev", Mac: macSecret(digestA), Guest: guest})
	f := findingByID(t, got, IDAuth)
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "sudo -n")
	noFindingByID(t, got, IDAuthMismatch)
}

// With no VM selected there is no per-VM secret path: doctor says so rather
// than naming a file assembled from an empty ref.
func TestCheckAuthNoVMSelected(t *testing.T) {
	got := CheckAuth(AuthInput{VM: "<vm>", MacSkip: "several VMs are running — pass -vm provider:name"})
	f := findingByID(t, got, IDAuth)
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "pass -vm")
	wantNotContains(t, f, "transport-secret--")
	noFindingByID(t, got, IDAuthFilePerms)
}

// The ring is ID-tagged at the emit site, so nothing is string-matched — and
// it is the only runtime vantage a foreground daemon has, which writes no log
// file at all. The rendered line says which vantage it came from.
func TestMatchAuthRing(t *testing.T) {
	got := MatchAuthRing([]introspect.Refusal{
		{ID: IDAuthMismatch, Line: row4Line},
		{ID: introspect.IDMirrorSkip, Line: "drawbridged: mirror: skipping guest tcp :22 (skip-list)"},
		{ID: introspect.IDReverseDialRefused, Line: row7Line},
	})
	if len(got) != 1 || got[0].ID != IDAuthMismatch || got[0].Source != "ring" {
		t.Fatalf("ring evidence = %+v, want one ring-sourced auth-mismatch", got)
	}

	f := findingByID(t, CheckAuth(AuthInput{
		VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestB),
		Evidence: append(MatchAuthLog([]string{row6Line}), got...),
	}), IDAuthMismatch)
	wantContains(t, f, "ring: "+row4Line)
}

// A log-tail line keeps its old rendering, so a fixture written before the
// ring existed still reads the way the report always read.
func TestAuthLogEvidenceKeepsItsLabel(t *testing.T) {
	f := findingByID(t, CheckAuth(AuthInput{
		VM: "lima:dev", Mac: macSecret(digestA), Guest: guestSecret(digestB),
		Evidence: MatchAuthLog([]string{row4Line}),
	}), IDAuthMismatch)
	wantContains(t, f, "log: "+row4Line)
}
