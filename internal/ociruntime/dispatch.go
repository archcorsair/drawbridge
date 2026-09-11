package ociruntime

// Which real runtime the wrapper is standing in for, and how to read that
// runtime's command line (docs/podman.md §6.1).
//
// One binary is built and embedded, and it dispatches on argv[0]: installed as
// `drawbridge-runc` it wraps runc for Docker, installed as `drawbridge-crun`
// it wraps crun for Podman. The alternative, two binaries, doubles the
// embedded payload and the build matrix to express a difference that is two
// tables and a probe list.
//
// Everything here is pure except Real, which is the one seam that touches the
// filesystem, so the tables and the self-exclusion are testable on the Mac.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The runtimes this wrapper can stand in for.
const (
	RuntimeRunc = "runc"
	RuntimeCrun = "crun"
)

// WrapperPrefix is the basename prefix `drawbridge up --oci` installs the
// wrapper under: `drawbridge-` plus the runtime it wraps. RuntimeFor reads
// the suffix back out.
const WrapperPrefix = "drawbridge-"

// Runtime is everything that differs between the runtimes the wrapper wraps.
type Runtime struct {
	// Name is the real runtime's own name, and the word every message uses.
	Name string

	// EnvOverride are the environment variables that pin the real runtime's
	// path, most specific first. The dev flow sets one of these, which is why
	// the legacy spelling stays in the list forever: `just vm-docker` and
	// every VM provisioned by it export DRAWBRIDGE_RUNC, and dropping it
	// would break running guests to save one string.
	EnvOverride []string

	// Probe are the candidate paths for the real runtime, in order. First
	// existing regular file wins, except one that resolves to this wrapper.
	Probe []string

	// ValueFlags are the global flags (those before the subcommand) that take
	// a SEPARATE value, so the argument after them is not the subcommand.
	// `--flag=value` is one argv word and needs no entry.
	ValueFlags map[string]bool
}

// runcRuntime is the table this wrapper shipped with, unchanged. Docker's
// containerd-shim invokes runc as
// `runc --root … --log … --log-format json --systemd-cgroup create --bundle …`.
var runcRuntime = Runtime{
	Name:        RuntimeRunc,
	EnvOverride: []string{"DRAWBRIDGE_RUNTIME", "DRAWBRIDGE_RUNC"},
	Probe:       []string{"/usr/sbin/runc", "/usr/bin/runc", "/usr/local/sbin/runc"},
	ValueFlags: map[string]bool{
		"--log": true, "--log-format": true, "--root": true,
		"--criu": true, "--rootless": true,
	},
}

// crunRuntime is crun's. Podman invokes the runtime through conmon as
// `crun --root … --systemd-cgroup --log … [--log-format json] create
// --bundle <dir> --pid-file … <id>`, so only the value-taking flags of that
// line matter: --debug, --systemd-cgroup and --no-pivot are booleans and must
// NOT swallow the word after them, or `create` would be read as a flag value
// and the bundle would never be inspected.
//
// The probe order puts /usr/bin/crun first because that is where every distro
// that ships crun puts it (Fedora CoreOS included, verified in the 7.0 spike);
// the /usr/local pair covers a hand-built one.
var crunRuntime = Runtime{
	Name:        RuntimeCrun,
	EnvOverride: []string{"DRAWBRIDGE_RUNTIME"},
	Probe:       []string{"/usr/bin/crun", "/usr/local/sbin/crun", "/usr/sbin/crun", "/usr/local/bin/crun"},
	ValueFlags: map[string]bool{
		"--root": true, "--log": true, "--log-format": true,
		"--log-level": true, "--cgroup-manager": true,
	},
}

// RuntimeFor picks the runtime from the wrapper's own argv[0].
//
// `drawbridge-crun` is crun; anything else is runc. Defaulting rather than
// failing on an unknown name is deliberate: the wrapper's whole failure
// posture is stock behaviour, and a binary someone renamed must still start
// containers. runc is the safe default because it is what the wrapper has
// always been, so an existing install cannot change meaning.
func RuntimeFor(argv0 string) Runtime {
	base := filepath.Base(argv0)
	// The prefix is required, not stripped-if-present: only the exact name
	// `up --oci` installs claims to be the crun wrapper. A binary called
	// plain `crun` is somebody's real crun, and answering "I am the crun
	// wrapper" to that name is how a probe list ends up pointing at us.
	if name, ok := strings.CutPrefix(base, WrapperPrefix); ok && name == RuntimeCrun {
		return crunRuntime
	}
	return runcRuntime
}

// Subcommand splits a runtime command line into the subcommand and the
// arguments after it.
//
// The global flags precede the subcommand, and the only thing that needs
// knowing about them is which take a separate value: `--root /run/crun create`
// must not read `/run/crun` as the subcommand. A `--flag=value` word carries
// its own value and is skipped like any other flag; a bare `-` (stdin, which
// no runtime uses here) reads as a flag and is skipped with the rest.
func Subcommand(rt Runtime, args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "" || a[0] != '-' {
			return a, args[i+1:]
		}
		if rt.ValueFlags[a] {
			i++ // skip the flag's value
		}
	}
	return "", nil
}

// Override is the pinned runtime path from the environment, "" when none is
// set. The variables are consulted in order, so DRAWBRIDGE_RUNTIME wins over
// the legacy DRAWBRIDGE_RUNC on a guest that has both.
func (rt Runtime) Override(getenv func(string) string) string {
	for _, k := range rt.EnvOverride {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// Pick chooses the real runtime path: the override when set, else the first
// probe candidate that canon accepts and that is not this wrapper.
//
// self is the wrapper's own path and canon canonicalises a path (resolving
// symlinks), returning "" for anything that does not exist or is not a
// regular file. Comparing canonical paths rather than the literals is the
// whole point: `up --oci` installs the wrapper at /usr/local/bin and a
// distro, a package or an administrator may well have pointed /usr/bin/crun
// at it, and a wrapper that execs itself is an unkillable fork bomb holding a
// container start open.
//
// An override is returned verbatim and unchecked. It is the dev loop's
// escape hatch, it is set by someone who knows where their runtime is, and
// second-guessing it would make `DRAWBRIDGE_RUNC=/some/build/runc` silently
// fall through to the system one.
func (rt Runtime) Pick(override, self string, canon func(string) string) string {
	if override != "" {
		return override
	}
	me := canon(self)
	for _, p := range rt.Probe {
		real := canon(p)
		if real == "" {
			continue
		}
		if me != "" && real == me {
			continue // a symlink (or a copy's path) pointing back at us
		}
		return p
	}
	return ""
}

// Real is Pick wired to the running process: the environment, this
// executable, and the filesystem. It is the only impure function in this
// file, which is what keeps the tables above testable on the Mac.
func (rt Runtime) Real() string {
	self, _ := os.Executable()
	return rt.Pick(rt.Override(os.Getenv), self, CanonicalPath)
}

// CanonicalPath resolves symlinks and reports "" unless the result is a
// regular file. Pick's default canon.
func CanonicalPath(p string) string {
	if p == "" {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ""
	}
	st, err := os.Stat(resolved)
	if err != nil || !isRegular(st) {
		return ""
	}
	return resolved
}

func isRegular(st fs.FileInfo) bool { return st.Mode().IsRegular() }
