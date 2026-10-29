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

// liveK515 is Script's whole output on the throwaway Ubuntu 22.04 VM
// (5.15.0-185-generic aarch64, GA kernel) on 2026-10-29, the kernel on which
// the agent itself died with "load tracker objects: … program
// tcp_listen_stop: load program: operation not supported".
const liveK515 = "features-arch=aarch64\nfeatures-ftrace-direct-calls=n\nfeatures=" + liveOK + "\n"

func probeOf(out string) Probe {
	p := Parse("")
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			p.Set(k, v)
		}
	}
	return p
}

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

// Set takes every key Script emits, in any order, without one clobbering
// another, and leaves everything else to the caller.
func TestSet(t *testing.T) {
	p := probeOf(liveK515)
	if !p.Ran || !p.Report.NetnsCookie || p.Arch != "aarch64" || p.DirectCalls != ConfigNo {
		t.Fatalf("probe = %+v", p)
	}
	p = probeOf("features=" + liveOK + "\nfeatures-ftrace-direct-calls=garbage\nfeatures-arch=x86_64\n")
	if !p.Ran || p.Arch != "x86_64" || p.DirectCalls != ConfigUnknown {
		t.Fatalf("probe = %+v", p)
	}
	if p.Set("kernel", "6.8.0") {
		t.Fatal("Set claimed a key Script never emits")
	}
}

func TestClassify(t *testing.T) {
	arm := func(p Probe, cfg string) Probe { p.Arch, p.DirectCalls = "aarch64", cfg; return p }
	x86 := func(p Probe, cfg string) Probe { p.Arch, p.DirectCalls = "x86_64", cfg; return p }
	ok, no := Parse(liveOK), Parse(liveNo)
	predates, absent := Parse(Predates), Parse(Absent)
	tests := []struct {
		name   string
		p      Probe
		kernel string
		want   Status
		probed bool
		says   string
	}{
		// The cookie: the probe wins in both directions, whatever the version says.
		{"probe ok on 6.8", arm(ok, ConfigYes), "6.8.0-51-generic", OK, true, "supported"},
		{"probe ok on a backported x86 5.13", x86(ok, ConfigYes), "5.13.19", OK, true, "supported"},
		{"probe ok on an old distro kernel", x86(ok, ConfigYes), "4.18.0-553.el8", OK, true, "supported"},
		{"probe no on 5.15", x86(no, ConfigYes), "5.15.0", Fail, true, "protocol not available"},
		{"probe no on a 5.13 without the backport", x86(no, ConfigYes), "5.13.0", Fail, true, "does not support"},

		// The cookie's fallback: the probe could not run.
		{"old agent, 6.8", arm(predates, ConfigYes), "6.8.0-51-generic", OK, false, "6.8 >= 5.14"},
		{"old agent, exactly 5.14", x86(predates, ConfigYes), "5.14.0", OK, false, "5.14 >= 5.14"},
		{"old agent, 5.13", x86(predates, ConfigYes), "5.13.12", Warn, false, "cannot confirm"},
		{"old agent, 5.12", x86(predates, ConfigYes), "5.12.0", Warn, false, "only some 5.12.y/5.13.y"},
		{"old agent, 5.11", x86(predates, ConfigYes), "5.11.0", Fail, false, "older than 5.12"},
		{"no agent, 5.8", x86(absent, ConfigYes), "5.8.0", Fail, false, "older than 5.12"},
		{"no agent, unparsable", x86(absent, ConfigYes), "linux", Warn, false, "cannot read the guest kernel version"},
		// Numeric, never lexical: "5.9" sorts after "5.14" as a string.
		{"no agent, 5.9", x86(absent, ConfigYes), "5.9.0", Fail, false, "older than 5.12"},

		// The tracker: the kernel config wins whenever it was readable.
		{"live 5.15 arm64 GA", probeOf(liveK515), "5.15.0-185-generic", Fail, true, "has no ftrace direct calls"},
		{"config n names the option", arm(ok, ConfigNo), "6.8.0", Fail, true, "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS is not set"},
		{"config y on an arm64 backport below 6.4", arm(ok, ConfigYes), "5.15.0", OK, true, "=y in the kernel config"},
		{"config n on x86 too", x86(ok, ConfigNo), "6.1.0", Fail, true, "cannot attach its fentry/fexit hooks"},

		// The tracker's fallback: no readable config.
		{"arm64 6.4, no config", arm(ok, ConfigUnknown), "6.4.0", OK, true, "6.4 >= 6.4"},
		{"arm64 6.3, no config", arm(ok, ConfigUnknown), "6.3.0", Fail, true, "older than 6.4"},
		{"arm64 5.15, no config", arm(ok, ConfigUnknown), "5.15.0", Fail, true, "where arm64 gained ftrace direct calls"},
		{"arm64 unparsable, no config", arm(ok, ConfigUnknown), "linux", Warn, true, "ftrace direct calls"},
		{"x86 5.14, no config", x86(ok, ConfigUnknown), "5.14.0", OK, true, "since 5.5"},
		{"not asked: no arch, no config", ok, "5.15.0", OK, true, "kernel config not read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Classify(tc.p, tc.kernel)
			if v.Status != tc.want || v.Probed != tc.probed {
				t.Fatalf("Classify = %+v, want status %d probed %v", v, tc.want, tc.probed)
			}
			if text := strings.Join(v.Evidence, "\n") + "\n" + v.Problem; !strings.Contains(text, tc.says) {
				t.Fatalf("verdict does not say %q:\n%s", tc.says, text)
			}
			if len(v.Evidence) != 2 {
				t.Fatalf("want one evidence line per dependency, got %q", v.Evidence)
			}
			if tc.want != OK && (v.Problem == "" || v.Remedy == "" || v.Short == "") {
				t.Fatalf("a warn or fail verdict is missing its words: %+v", v)
			}
			if tc.want == OK && (v.Problem != "" || v.Remedy != "") {
				t.Fatalf("an ok verdict carries a problem: %+v", v)
			}
		})
	}
}

// The remedies never point an arm64 reader at a kernel the tracker cannot
// run on, and the tracker failure carries the one shared remedy.
func TestClassifyRemedies(t *testing.T) {
	v := Classify(probeOf(liveK515), "5.15.0-185-generic")
	if v.Remedy != TracerRemedy {
		t.Fatalf("tracker failure remedy = %q, want TracerRemedy", v.Remedy)
	}
	for _, want := range []string{"6.4", "linux-generic-hwe-22.04", "GA 5.15 kernel is not enough"} {
		if !strings.Contains(v.Remedy, want) {
			t.Errorf("TracerRemedy does not say %q", want)
		}
	}

	armNo := Parse(liveNo)
	armNo.Arch, armNo.DirectCalls = "aarch64", ConfigYes
	if r := Classify(armNo, "6.8.0").Remedy; !strings.Contains(r, ">= 6.4") || strings.Contains(r, ">= 5.14") {
		t.Errorf("arm64 cookie remedy points below 6.4:\n%s", r)
	}
	x86No := Parse(liveNo)
	x86No.Arch, x86No.DirectCalls = "x86_64", ConfigYes
	if r := Classify(x86No, "5.15.0").Remedy; !strings.Contains(r, ">= 5.14") {
		t.Errorf("x86 cookie remedy does not give the 5.14 floor:\n%s", r)
	}

	// Both broken: both problems named, the tracker's floor (which covers
	// the cookie's on arm64) as the remedy.
	both := Parse(Absent)
	both.Arch, both.DirectCalls = "aarch64", ConfigNo
	v = Classify(both, "5.10.0")
	if !strings.Contains(v.Problem, "SO_NETNS_COOKIE") || !strings.Contains(v.Problem, "ftrace direct calls") || v.Remedy != TracerRemedy {
		t.Fatalf("double failure = %+v", v)
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
		if !strings.Contains(v.Evidence[0], says) || !strings.Contains(v.Problem, says) {
			t.Errorf("%s: verdict does not say %q: %+v", why, says, v)
		}
	}
}

// The script is what stands between an old agent and an accidental daemon
// start: it must look for the marker before running anything, run the
// subcommand only in the branch that found it, read the config without
// privilege, and emit each key.
func TestScript(t *testing.T) {
	s := Script("/usr/local/bin/drawbridge-agent")
	grep := strings.Index(s, "grep -qF '"+Marker+"'")
	run := strings.Index(s, `"$db_feat_bin" `+Subcommand)
	if grep < 0 || run < 0 || grep > run {
		t.Fatalf("the subcommand is not gated on the marker grep:\n%s", s)
	}
	if strings.Contains(s, "sudo") {
		t.Fatalf("the probe needs no privilege and must not ask for any:\n%s", s)
	}
	for _, want := range []string{
		Key + "=" + Absent, Key + "=" + Unreadable, Key + "=" + Predates, ":-" + Failed,
		KeyArch + "=$(uname -m", KeyDirectCalls + "=$db_feat_cfg",
		`"/boot/config-$db_feat_rel"`, `"/lib/modules/$db_feat_rel/config"`, "/proc/config.gz",
		"'^CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y'", "printf '%s\\n'",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script does not contain %q:\n%s", want, s)
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
