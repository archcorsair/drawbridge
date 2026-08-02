//go:build linux

// drawbridge-runc is a wrapper OCI runtime (docs/oci-hook.md, Phase B):
// registered in Docker's daemon.json, it rewrites a host-network bundle's
// config.json — bind → SCMP_ACT_NOTIFY plus listenerPath — and execs the
// real runc, which installs the filter and delivers the notify fd to the
// agent itself. Every path that cannot provably inject execs runc with the
// spec untouched: the failure posture is stock Docker behavior, never a
// container that fails to start.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/ociruntime"
)

const defaultOCISock = "/run/drawbridge-oci.sock"

// Value-taking runc global flags (they precede the subcommand); everything
// else before the subcommand is a boolean flag. Stable since runc 1.0.
var globalValueFlags = map[string]bool{
	"--log": true, "--log-format": true, "--root": true,
	"--criu": true, "--rootless": true,
}

func main() {
	args := os.Args[1:]
	if sub, bundle := createBundle(args); sub {
		tryInject(bundle)
	}
	execRunc(args)
}

// createBundle reports whether args are a `create`/`run` invocation and
// resolves the bundle directory (default: cwd, as runc does).
func createBundle(args []string) (bool, string) {
	sub, rest := subcommand(args)
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

func subcommand(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) == 0 || a[0] != '-' {
			return a, args[i+1:]
		}
		if globalValueFlags[a] {
			i++ // skip the flag's value
		}
	}
	return "", nil
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
	meta := `{"v":1,"source":"drawbridge-runc","hostNetwork":true}`
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

// execRunc replaces this process with the real runc; stdio, exit code, and
// argv all stay the shim's.
func execRunc(args []string) {
	runc := realRunc()
	if runc == "" {
		fmt.Fprintln(os.Stderr, "drawbridge-runc: no real runc found (set DRAWBRIDGE_RUNC)")
		os.Exit(1)
	}
	argv := append([]string{runc}, args...)
	if err := syscall.Exec(runc, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge-runc: exec %s: %v\n", runc, err)
		os.Exit(1)
	}
}

func realRunc() string {
	if p := os.Getenv("DRAWBRIDGE_RUNC"); p != "" {
		return p
	}
	self, _ := os.Executable()
	for _, p := range []string{"/usr/sbin/runc", "/usr/bin/runc", "/usr/local/sbin/runc"} {
		if p == self {
			continue
		}
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func note(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "drawbridge-runc: "+format+"\n", args...)
}
