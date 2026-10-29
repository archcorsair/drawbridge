package kernelfeat

import (
	"strings"
	"testing"
)

// liveOK and liveNo are the probe's own output: liveOK captured from the dev
// VM (Ubuntu 24.04, 6.8.0, arm64) on 2026-10-29, liveNo the shape a kernel
// without the option produces (ENOPROTOOPT from sock_getsockopt).
const (
	liveOK = `{"probe":"drawbridge-features/v1","so_netns_cookie":true}`
	liveNo = `{"probe":"drawbridge-features/v1","so_netns_cookie":false,"so_netns_cookie_error":"getsockopt(SO_NETNS_COOKIE): protocol not available"}`
)

func TestParse(t *testing.T) {
	tests := []struct {
		in     string
		ran    bool
		cookie bool
		why    string
	}{
		{liveOK, true, true, ""},
		{liveNo, true, false, ""},
		{"absent", false, false, Absent},
		{"unreadable", false, false, Unreadable},
		{"predates", false, false, Predates},
		{"failed", false, false, Failed},
		{"", false, false, Failed},
		// A different probe version is not this build's report.
		{`{"probe":"drawbridge-features/v9","so_netns_cookie":true}`, false, false, "failed: "},
		{`{"probe":`, false, false, "failed: "},
	}
	for _, tc := range tests {
		p := Parse(tc.in)
		if p.Ran != tc.ran || p.Report.NetnsCookie != tc.cookie || !strings.HasPrefix(p.Why, tc.why) {
			t.Errorf("Parse(%q) = %+v, want ran=%v cookie=%v why^=%q", tc.in, p, tc.ran, tc.cookie, tc.why)
		}
	}
}

func TestClassify(t *testing.T) {
	ok, no := Parse(liveOK), Parse(liveNo)
	predates := Parse(Predates)
	absent := Parse(Absent)
	tests := []struct {
		name   string
		p      Probe
		kernel string
		want   Status
		probed bool
		says   string
	}{
		// The probe wins in both directions, whatever the version says.
		{"probe ok on 6.8", ok, "6.8.0-51-generic", OK, true, "supported"},
		{"probe ok on a backported 5.13", ok, "5.13.19", OK, true, "supported"},
		{"probe ok on an old distro kernel", ok, "4.18.0-553.el8", OK, true, "supported"},
		{"probe no on 5.15", no, "5.15.0", Fail, true, "protocol not available"},
		{"probe no on a 5.13 without the backport", no, "5.13.0", Fail, true, "does not support"},

		// Fallback: the probe could not run.
		{"old agent, 6.8", predates, "6.8.0-51-generic", OK, false, "6.8 >= 5.14"},
		{"old agent, exactly 5.14", predates, "5.14.0", OK, false, "5.14 >= 5.14"},
		{"old agent, 5.13", predates, "5.13.12", Warn, false, "cannot confirm"},
		{"old agent, 5.12", predates, "5.12.0", Warn, false, "only some 5.12.y/5.13.y"},
		{"old agent, 5.11", predates, "5.11.0", Fail, false, "older than 5.12"},
		{"no agent, 5.8", absent, "5.8.0", Fail, false, "older than 5.12"},
		{"no agent, unparsable", absent, "linux", Warn, false, "cannot read the guest kernel version"},
		// Numeric, never lexical: "5.9" sorts after "5.14" as a string.
		{"no agent, 5.9", absent, "5.9.0", Fail, false, "older than 5.12"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.p, tc.kernel)
			if v.Status != tc.want || v.Probed != tc.probed {
				t.Fatalf("Classify = %+v, want status %d probed %v", v, tc.want, tc.probed)
			}
			if text := v.Evidence + "\n" + v.Problem; !strings.Contains(text, tc.says) {
				t.Fatalf("verdict does not say %q:\n%s", tc.says, text)
			}
			if tc.want != OK && v.Problem == "" {
				t.Fatal("a warn or fail verdict has no problem sentence")
			}
		})
	}
}

// The fallback names why the probe could not run, so a reader knows whether
// re-running `up` would turn it into a real answer.
func TestClassifyNamesWhyNotProbed(t *testing.T) {
	for why, says := range map[string]string{
		Absent:     "no agent is installed",
		Predates:   "predates the `features` probe",
		Unreadable: "not readable",
		Failed:     "printed no answer",
	} {
		v := Classify(Parse(why), "5.13.0")
		if !strings.Contains(v.Evidence, says) || !strings.Contains(v.Problem, says) {
			t.Errorf("%s: verdict does not say %q: %+v", why, says, v)
		}
	}
}

// The script is what stands between an old agent and an accidental daemon
// start: it must look for the marker before running anything, run the
// subcommand only in the branch that found it, and emit one key.
func TestScriptGatesOnTheMarker(t *testing.T) {
	s := Script("/usr/local/bin/drawbridge-agent")
	grep := strings.Index(s, "grep -qF '"+Marker+"'")
	run := strings.Index(s, `"$db_feat_bin" `+Subcommand)
	if grep < 0 || run < 0 || grep > run {
		t.Fatalf("the subcommand is not gated on the marker grep:\n%s", s)
	}
	if strings.Contains(s, "sudo") {
		t.Fatalf("the probe needs no privilege and must not ask for any:\n%s", s)
	}
	for _, want := range []string{Absent, Unreadable, Predates, Failed} {
		if !strings.Contains(s, Key+"="+want) && !strings.Contains(s, ":-"+want) {
			t.Errorf("script never emits %q:\n%s", want, s)
		}
	}
}

func TestParseMajorMinor(t *testing.T) {
	tests := []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"6.8.0-51-generic", 6, 8, true},
		{"5.14.0-427.el9.x86_64", 5, 14, true},
		{"7.1.3-200.fc44.aarch64", 7, 1, true},
		{"5.13", 5, 13, true},
		{"6", 0, 0, false},
		{"linux", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range tests {
		maj, min, ok := ParseMajorMinor(tc.in)
		if maj != tc.maj || min != tc.min || ok != tc.ok {
			t.Errorf("ParseMajorMinor(%q) = %d,%d,%v want %d,%d,%v", tc.in, maj, min, ok, tc.maj, tc.min, tc.ok)
		}
	}
}
