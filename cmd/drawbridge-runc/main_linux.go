//go:build linux

// drawbridge-runc is a wrapper OCI runtime (docs/oci-hook.md, Phase B):
// registered as an engine's runtime, it rewrites a host-network bundle's
// config.json (bind to SCMP_ACT_NOTIFY plus listenerPath) and execs the real
// runtime, which installs the filter and delivers the notify fd to the agent
// itself. Every path that cannot provably inject execs the runtime with the
// spec untouched: the failure posture is stock engine behavior, never a
// container that fails to start.
//
// One binary, two names. Installed as `drawbridge-runc` it stands in for
// runc (Docker); installed as `drawbridge-crun` it stands in for crun
// (Podman). Everything that differs is a table in internal/ociruntime
// (docs/podman.md §6.1), and everything below is engine-neutral: the bundle
// detection, the injection decision and the exec are the same code either
// way, which is what makes "runc behaviour is unchanged" a property of the
// build rather than of a second code path.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/ociruntime"
)

const defaultOCISock = "/run/drawbridge-oci.sock"

// rt is the runtime this invocation stands in for, decided by argv[0] before
// anything else reads the command line: which global flags take a value is
// the difference between finding the subcommand and mistaking a flag's value
// for it.
var rt = ociruntime.RuntimeFor(os.Args[0])

func main() {
	args := os.Args[1:]
	if sub, bundle := createBundle(args); sub {
		tryInject(bundle)
	}
	execRuntime(args)
}

// createBundle reports whether args are a `create`/`run` invocation and
// resolves the bundle directory (default: cwd, as both runtimes do).
func createBundle(args []string) (bool, string) {
	sub, rest := ociruntime.Subcommand(rt, args)
	if sub != "create" && sub != "run" {
		return false, ""
	}
	bundle := "."
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--bundle" || a == "-b":
			if i+1 < len(rest) {
				bundle = rest[i+1]
			}
		case len(a) > len("--bundle=") && a[:len("--bundle=")] == "--bundle=":
			bundle = a[len("--bundle="):]
		case len(a) > len("-b=") && a[:len("-b=")] == "-b=":
			bundle = a[len("-b="):]
		}
	}
	return true, bundle
}

// tryInject mutates the bundle's config.json when every precondition
// holds. All failures are silent skips (stderr note only): the wrapper
// must never break a container start.
func tryInject(bundle string) {
	sock := os.Getenv("DRAWBRIDGE_OCI_SOCK")
	if sock == "" {
		sock = defaultOCISock
	}
	cfg := filepath.Join(bundle, "config.json")
	raw, err := os.ReadFile(cfg)
	if err != nil {
		note("read %s: %v", cfg, err)
		return
	}
	meta := `{"v":1,"source":"` + wrapperName() + `","hostNetwork":true}`
	out, injected, _, err := ociruntime.MutateConfig(raw, sock, meta)
	if err != nil {
		note("%s: %v", cfg, err)
		return
	}
	if !injected {
		return // bridged / opt-out / unprovable profile — by design
	}
	// Probe after deciding, before writing: agent down ⇒ stock behavior
	// (a listenerPath send failure would be a container-start failure),
	// and bridged containers never even dial.
	c, err := net.DialTimeout("unix", sock, 100*time.Millisecond)
	if err != nil {
		return
	}
	c.Close()
	st, err := os.Stat(cfg)
	if err != nil {
		note("stat %s: %v", cfg, err)
		return
	}
	tmp := cfg + ".drawbridge"
	if err := os.WriteFile(tmp, out, st.Mode().Perm()); err != nil {
		note("write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, cfg); err != nil {
		os.Remove(tmp)
		note("rename %s: %v", tmp, err)
		return
	}
}

// execRuntime replaces this process with the real runtime; stdio, exit code,
// and argv all stay the shim's.
func execRuntime(args []string) {
	real := rt.Real()
	if real == "" {
		fmt.Fprintf(os.Stderr, "%s: no real %s found (tried %s; set %s)\n",
			wrapperName(), rt.Name, strings.Join(rt.Probe, ", "), strings.Join(rt.EnvOverride, " or "))
		os.Exit(1)
	}
	argv := append([]string{real}, args...)
	if err := syscall.Exec(real, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "%s: exec %s: %v\n", wrapperName(), real, err)
		os.Exit(1)
	}
}

// wrapperName is how this binary refers to itself in its own messages: the
// name it was installed under, so a podman user reading a container-start
// failure sees the command their engine actually ran.
func wrapperName() string { return filepath.Base(os.Args[0]) }

func note(format string, args ...any) {
	fmt.Fprintf(os.Stderr, wrapperName()+": "+format+"\n", args...)
}
