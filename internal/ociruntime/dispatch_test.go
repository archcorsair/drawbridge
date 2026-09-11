package ociruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// argv[0] is the whole registration: `up --oci` installs one binary under the
// name of the runtime it stands in for, and the binary reads that name back.
// An unknown name is runc, not an error: the wrapper's failure posture is
// stock behaviour, so a renamed binary must still start containers, and runc
// is what this wrapper has always been.
func TestRuntimeFor(t *testing.T) {
	for _, tc := range []struct{ argv0, want string }{
		{"/usr/local/bin/drawbridge-crun", RuntimeCrun},
		{"drawbridge-crun", RuntimeCrun},
		{"./drawbridge-crun", RuntimeCrun},
		{"/usr/local/bin/drawbridge-runc", RuntimeRunc},
		{"drawbridge-runc", RuntimeRunc},
		{"/tmp/build/drawbridge-runc-linux-arm64", RuntimeRunc},
		{"drawbridge-crun-backup", RuntimeRunc}, // not the exact suffix
		{"crun", RuntimeRunc},                   // no wrapper prefix: not a claim to be crun
		{"", RuntimeRunc},
		{"/usr/bin/something-else", RuntimeRunc},
	} {
		if got := RuntimeFor(tc.argv0).Name; got != tc.want {
			t.Errorf("RuntimeFor(%q) = %q, want %q", tc.argv0, got, tc.want)
		}
	}
}

// The subcommand parse is what decides whether a bundle is inspected at all.
// Getting a value flag wrong reads the flag's value as the subcommand, so
// `create` is never seen and arbitration silently stops happening.
func TestSubcommand(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rt       Runtime
		args     []string
		wantSub  string
		wantRest []string
	}{{
		// Docker's containerd-shim, verbatim.
		name:     "runc create through the shim",
		rt:       RuntimeFor("drawbridge-runc"),
		args:     []string{"--root", "/run/containerd/runc/moby", "--log", "/run/.../log.json", "--log-format", "json", "--systemd-cgroup", "create", "--bundle", "/run/.../bundle", "--pid-file", "/run/.../init.pid", "abc123"},
		wantSub:  "create",
		wantRest: []string{"--bundle", "/run/.../bundle", "--pid-file", "/run/.../init.pid", "abc123"},
	}, {
		// Podman through conmon, verbatim (docs/podman.md §6.1). The
		// booleans are the trap: --systemd-cgroup swallowing the next word
		// would make `create` a flag value.
		name:     "crun create through conmon",
		rt:       RuntimeFor("drawbridge-crun"),
		args:     []string{"--root", "/run/crun", "--systemd-cgroup", "--log", "/var/.../ctr.log", "--log-format", "json", "create", "--bundle", "/var/.../userdata", "--pid-file", "/run/.../pidfile", "deadbeef"},
		wantSub:  "create",
		wantRest: []string{"--bundle", "/var/.../userdata", "--pid-file", "/run/.../pidfile", "deadbeef"},
	}, {
		name:     "crun's own value flags",
		rt:       RuntimeFor("drawbridge-crun"),
		args:     []string{"--log-level", "warning", "--cgroup-manager", "systemd", "--root", "/run/crun", "run", "id"},
		wantSub:  "run",
		wantRest: []string{"id"},
	}, {
		// One argv word carries its own value, so nothing is skipped after
		// it. A table entry for these forms would skip the subcommand.
		name:     "--flag=value needs no entry",
		rt:       RuntimeFor("drawbridge-crun"),
		args:     []string{"--root=/run/crun", "--log-format=json", "--systemd-cgroup", "create", "--bundle=/b", "id"},
		wantSub:  "create",
		wantRest: []string{"--bundle=/b", "id"},
	}, {
		name:     "runc --flag=value",
		rt:       RuntimeFor("drawbridge-runc"),
		args:     []string{"--root=/run/x", "--log=/l", "create", "--bundle", "/b"},
		wantSub:  "create",
		wantRest: []string{"--bundle", "/b"},
	}, {
		name:     "booleans do not swallow",
		rt:       RuntimeFor("drawbridge-crun"),
		args:     []string{"--debug", "--no-pivot", "--systemd-cgroup", "state", "id"},
		wantSub:  "state",
		wantRest: []string{"id"},
	}, {
		name:    "no subcommand at all",
		rt:      RuntimeFor("drawbridge-runc"),
		args:    []string{"--root", "/run/x"},
		wantSub: "",
	}, {
		name:    "nothing",
		rt:      RuntimeFor("drawbridge-runc"),
		args:    nil,
		wantSub: "",
	}, {
		name:    "a dangling value flag does not run off the end",
		rt:      RuntimeFor("drawbridge-crun"),
		args:    []string{"--root"},
		wantSub: "",
	}, {
		// runc's --rootless takes a value; crun has no such flag, so for crun
		// the word after it is the subcommand. The tables are not
		// interchangeable, which is the reason each runtime carries its own.
		name:     "runc --rootless takes a value",
		rt:       RuntimeFor("drawbridge-runc"),
		args:     []string{"--rootless", "true", "create", "--bundle", "/b"},
		wantSub:  "create",
		wantRest: []string{"--bundle", "/b"},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			sub, rest := Subcommand(tc.rt, tc.args)
			if sub != tc.wantSub {
				t.Fatalf("subcommand = %q, want %q", sub, tc.wantSub)
			}
			if strings.Join(rest, " ") != strings.Join(tc.wantRest, " ") {
				t.Fatalf("rest = %v, want %v", rest, tc.wantRest)
			}
		})
	}
}

// The env override is the dev loop's escape hatch. DRAWBRIDGE_RUNC stays in
// runc's list forever: `just vm-docker` exports it and every VM provisioned
// by it has it, so dropping the spelling would break running guests to save
// one string.
func TestOverride(t *testing.T) {
	runc, crun := RuntimeFor("drawbridge-runc"), RuntimeFor("drawbridge-crun")
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	for _, tc := range []struct {
		name string
		rt   Runtime
		vars map[string]string
		want string
	}{
		{"legacy runc spelling", runc, map[string]string{"DRAWBRIDGE_RUNC": "/dev/runc"}, "/dev/runc"},
		{"new spelling", runc, map[string]string{"DRAWBRIDGE_RUNTIME": "/dev/rt"}, "/dev/rt"},
		{"new spelling wins", runc, map[string]string{"DRAWBRIDGE_RUNTIME": "/dev/rt", "DRAWBRIDGE_RUNC": "/dev/runc"}, "/dev/rt"},
		{"crun ignores the runc spelling", crun, map[string]string{"DRAWBRIDGE_RUNC": "/dev/runc"}, ""},
		{"crun takes the new one", crun, map[string]string{"DRAWBRIDGE_RUNTIME": "/dev/crun"}, "/dev/crun"},
		{"blank is unset", runc, map[string]string{"DRAWBRIDGE_RUNC": "   "}, ""},
		{"nothing set", runc, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rt.Override(env(tc.vars)); got != tc.want {
				t.Fatalf("Override = %q, want %q", got, tc.want)
			}
		})
	}
}

// A wrapper that execs itself is an unkillable fork bomb holding a container
// start open, and it is reachable: `up --oci` installs the wrapper in
// /usr/local/bin, and a package or an administrator may well have pointed a
// probe path at it. So the exclusion compares CANONICAL paths, which is what
// catches the symlink; comparing the literals does not.
func TestPickExcludesTheWrapperItself(t *testing.T) {
	crun := RuntimeFor("drawbridge-crun")
	const self = "/usr/local/bin/drawbridge-crun"

	// The live shape: /usr/bin/crun is a symlink to the wrapper, and the real
	// crun is further down the probe list.
	canon := func(p string) string {
		switch p {
		case "/usr/bin/crun", self:
			return self // the symlink resolves to us
		case "/usr/local/sbin/crun":
			return "/usr/local/sbin/crun"
		}
		return ""
	}
	if got := crun.Pick("", self, canon); got != "/usr/local/sbin/crun" {
		t.Fatalf("Pick = %q, want the first candidate that is not the wrapper", got)
	}

	// Every candidate is the wrapper: nothing to exec, and saying so beats
	// exec'ing ourselves.
	all := func(p string) string { return self }
	if got := crun.Pick("", self, all); got != "" {
		t.Fatalf("Pick = %q, want none when every candidate is the wrapper", got)
	}

	// The literal comparison the old code did would have passed the symlink
	// through, so pin that this test would actually catch the regression.
	literal := func(p string) string {
		if p == "/usr/bin/crun" || p == self {
			return p // no symlink resolution
		}
		return ""
	}
	if got := crun.Pick("", self, literal); got != "/usr/bin/crun" {
		t.Fatalf("the fixture no longer models the hazard: %q", got)
	}
}

func TestPickOrderAndOverride(t *testing.T) {
	runc := RuntimeFor("drawbridge-runc")
	exists := func(paths ...string) func(string) string {
		set := map[string]bool{}
		for _, p := range paths {
			set[p] = true
		}
		return func(p string) string {
			if set[p] {
				return p
			}
			return ""
		}
	}

	// Probe order is the table's order, not the filesystem's.
	if got := runc.Pick("", "/usr/local/bin/drawbridge-runc", exists("/usr/bin/runc", "/usr/sbin/runc")); got != "/usr/sbin/runc" {
		t.Fatalf("Pick = %q, want the first entry of the probe list that exists", got)
	}
	if got := runc.Pick("", "", exists()); got != "" {
		t.Fatalf("Pick = %q, want none when nothing exists", got)
	}
	// An override is returned verbatim and unchecked: it is set by someone
	// who knows where their runtime is, and falling through to the system one
	// would make the dev loop measure the wrong binary.
	if got := runc.Pick("/build/runc", "", exists()); got != "/build/runc" {
		t.Fatalf("Pick = %q, want the override verbatim", got)
	}
	// Including when the override IS a probe path that also resolves to us:
	// deliberate, and the caller asked for it.
	if got := runc.Pick("/usr/sbin/runc", "/usr/sbin/runc", exists("/usr/sbin/runc")); got != "/usr/sbin/runc" {
		t.Fatalf("Pick = %q, want the override honoured", got)
	}
}

// Probe lists are absolute paths to a real runtime, never a wrapper name: a
// relative entry would resolve against the engine's working directory, and an
// entry ending in the wrapper's own basename would be self-exec by default
// rather than by accident.
func TestProbeListsAreSane(t *testing.T) {
	for _, rt := range []Runtime{RuntimeFor("drawbridge-runc"), RuntimeFor("drawbridge-crun")} {
		if len(rt.Probe) == 0 {
			t.Fatalf("%s has no probe candidates", rt.Name)
		}
		seen := map[string]bool{}
		for _, p := range rt.Probe {
			if !filepath.IsAbs(p) {
				t.Errorf("%s: probe %q is not absolute", rt.Name, p)
			}
			if base := filepath.Base(p); base != rt.Name {
				t.Errorf("%s: probe %q is not a %s", rt.Name, p, rt.Name)
			}
			if seen[p] {
				t.Errorf("%s: probe %q listed twice", rt.Name, p)
			}
			seen[p] = true
		}
		for _, k := range rt.EnvOverride {
			if !strings.HasPrefix(k, "DRAWBRIDGE_") {
				t.Errorf("%s: override %q is not ours to read", rt.Name, k)
			}
		}
	}
}

// runc's table is the one this wrapper shipped with. It is load-bearing for
// every guest already provisioned, so a change to it is a change to running
// systems and has to be deliberate.
func TestRuncTableIsUnchanged(t *testing.T) {
	runc := RuntimeFor("drawbridge-runc")
	want := map[string]bool{
		"--log": true, "--log-format": true, "--root": true,
		"--criu": true, "--rootless": true,
	}
	if len(runc.ValueFlags) != len(want) {
		t.Fatalf("runc value flags = %v, want %v", runc.ValueFlags, want)
	}
	for k := range want {
		if !runc.ValueFlags[k] {
			t.Fatalf("runc value flags lost %s: %v", k, runc.ValueFlags)
		}
	}
	if strings.Join(runc.Probe, " ") != "/usr/sbin/runc /usr/bin/runc /usr/local/sbin/runc" {
		t.Fatalf("runc probe list changed: %v", runc.Probe)
	}
}

// crun's booleans must NOT be value flags. Each one of these appears in
// conmon's real command line before `create`.
func TestCrunBooleansAreNotValueFlags(t *testing.T) {
	crun := RuntimeFor("drawbridge-crun")
	for _, b := range []string{"--debug", "--systemd-cgroup", "--no-pivot", "--version", "--help"} {
		if crun.ValueFlags[b] {
			t.Errorf("crun: %s is a boolean but is listed as taking a value", b)
		}
	}
	for _, v := range []string{"--root", "--log", "--log-format", "--log-level", "--cgroup-manager"} {
		if !crun.ValueFlags[v] {
			t.Errorf("crun: %s takes a separate value but is not listed", v)
		}
	}
}

// CanonicalPath is Pick's default canon: symlinks resolved, and "" for
// anything that is not a regular file (a directory named like a runtime must
// not be exec'd).
func TestCanonicalPath(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "crun")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "crun-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	wantReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if got := CanonicalPath(link); got != wantReal {
		t.Fatalf("CanonicalPath(symlink) = %q, want %q", got, wantReal)
	}
	if got := CanonicalPath(real); got != wantReal {
		t.Fatalf("CanonicalPath(file) = %q, want %q", got, wantReal)
	}
	for _, p := range []string{"", filepath.Join(dir, "absent"), dir} {
		if got := CanonicalPath(p); got != "" {
			t.Fatalf("CanonicalPath(%q) = %q, want empty", p, got)
		}
	}
}
