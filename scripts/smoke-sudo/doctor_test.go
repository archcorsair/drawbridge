package main

import "testing"

// The doctor check parses what a user sees, not -json: the text form is what
// they paste back, and a check that reads something else can disagree with
// the thing in front of them.
func TestParseDoctorText(t *testing.T) {
	const out = `drawbridge doctor — CLI v0.1.2, VM podman:spike, 2026-09-11T14:55:23-07:00

[ok]   VM providers — 1 attachable instance(s) running
[ok]   guest prerequisites — kernel 7.1.3, BTF, cgroup v2, systemd
[fail] guest agent — drawbridge-agent.service is inactive
       → no agent is running in the guest
[ok]   endpoint resolution — tcp://127.0.0.1:4778 (gvproxy-publish)
[skip] vzNAT route — not applicable to a podman machine
[warn] network content filters — 2 activated network extension(s)
[fail] Mac daemon — installed v0.1.1, this CLI is v0.1.2
[info] skip-list — guest 22,323 is not mirrored by default

12 checks: 6 ok, 1 warn, 2 fail, 2 skip, 1 info
`
	summary, failures := parseDoctorText(out)
	if summary != "12 checks: 6 ok, 1 warn, 2 fail, 2 skip, 1 info" {
		t.Fatalf("summary = %q", summary)
	}
	if len(failures) != 2 {
		t.Fatalf("failures = %v, want 2", failures)
	}
	for i, want := range []string{"guest agent", "Mac daemon"} {
		if len(failures[i]) < len(want) || failures[i][:len(want)] != want {
			t.Fatalf("failure %d = %q, want one starting %q", i, failures[i], want)
		}
	}
}

// A clean run reports its summary and nothing else. Warnings are not
// failures: a Mac with a content filter installed warns on check 7 forever,
// and a smoke run that called that broken would be unusable here.
func TestParseDoctorTextClean(t *testing.T) {
	const out = `[ok]   VM providers — 1 attachable instance(s) running
[warn] network content filters — 2 activated network extension(s)
[info] skip-list — guest 22,323 is not mirrored by default

12 checks: 9 ok, 1 warn, 0 fail, 1 skip, 1 info
`
	summary, failures := parseDoctorText(out)
	if len(failures) != 0 {
		t.Fatalf("a warn was counted as a failure: %v", failures)
	}
	if summary == "" {
		t.Fatal("no summary")
	}
}

// A run that printed nothing recognisable has no summary, which the caller
// turns into a failure of its own rather than a silent pass.
func TestParseDoctorTextGarbage(t *testing.T) {
	summary, failures := parseDoctorText("sudo: a password is required\n")
	if summary != "" || len(failures) != 0 {
		t.Fatalf("summary=%q failures=%v", summary, failures)
	}
}
