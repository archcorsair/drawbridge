package guestbin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/ociruntime"
)

// The dev-build path is the one every contributor hits on a fresh checkout,
// and the one a broken release would hit in front of a user. It has to be a
// message, not a panic and not a compile error — which is also the reason
// the embed pattern is `all:bin` over a directory with a committed .keep.
func TestBinaryNotBundled(t *testing.T) {
	// This assertion only means anything when the tree has not been built.
	// After `just build` the binaries are really there, and "bundled" is the
	// correct answer — so assert the *shape* of the failure rather than
	// forcing one.
	for _, arch := range []string{"arm64", "amd64"} {
		b, err := Binary(NameAgent, arch)
		switch {
		case err == nil:
			if len(b) == 0 {
				t.Fatalf("Binary(agent, %s) returned no error and no bytes", arch)
			}
		case errors.Is(err, ErrNotBundled):
			if !strings.Contains(err.Error(), "just build") || !strings.Contains(err.Error(), "-agent-bin") {
				t.Fatalf("ErrNotBundled must name both remedies, got %q", err)
			}
		default:
			t.Fatalf("Binary(agent, %s): unexpected error %v", arch, err)
		}
	}
}

// A role we do not ship is a programming error, not a missing artifact, and
// must not read as "run `just build`".
func TestBinaryUnknownRole(t *testing.T) {
	_, err := Binary("kernel", "arm64")
	if err == nil || errors.Is(err, ErrNotBundled) {
		t.Fatalf("Binary with an unknown role: got %v, want a distinct error", err)
	}
}

// An architecture we do not ship must fail here, on the Mac, and not in the
// guest as an exec format error — which diagnoses nothing.
func TestArch(t *testing.T) {
	for _, tc := range []struct {
		uname, want string
		wantErr     bool
	}{
		{uname: "aarch64", want: "arm64"},
		{uname: "arm64", want: "arm64"},
		{uname: "x86_64", want: "amd64"},
		{uname: "amd64", want: "amd64"},
		{uname: "  aarch64\n", want: "arm64"},
		{uname: "riscv64", wantErr: true},
		{uname: "", wantErr: true},
	} {
		got, err := Arch(tc.uname)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("Arch(%q) = %q, want an error", tc.uname, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("Arch(%q) = %q, %v; want %q", tc.uname, got, err, tc.want)
		}
	}
}

// The unit is written into a user's guest and read by systemd at every boot,
// so its bytes are the contract — the same reasoning as the install plist's
// golden test. A silent change to Restart= or WantedBy= surfaces as "the
// agent didn't come back after the VM restarted".
func TestUnitGolden(t *testing.T) {
	u, err := Unit(GuestPath(NameAgent))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "unit-agent.golden", u)
	if strings.Contains(u, "{{") {
		t.Fatalf("unit still contains an unexpanded action:\n%s", u)
	}
}

// Unit takes a whole ExecStart line so a podman guest's agent can carry the
// flags a Lima one does not (docs/podman.md §5.4). The property that matters
// is the one in the other direction: a bare binary path must still render the
// exact bytes it always did, or every existing guest's `up` rewrites a unit
// that did not change and restarts an agent that did not need it.
func TestUnitWithFlagsLeavesTheBarePathByteIdentical(t *testing.T) {
	bare, err := Unit(GuestPath(NameAgent))
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "unit-agent.golden", bare)

	withFlags, err := Unit(GuestPath(NameAgent) + " -gvproxy-publish 127.0.0.1:4778")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(withFlags, "ExecStart="+GuestPath(NameAgent)+" -gvproxy-publish 127.0.0.1:4778\n") {
		t.Fatalf("the flags did not reach ExecStart:\n%s", withFlags)
	}
	// Everything but that one line is the same file.
	if a, b := withoutExecStart(bare), withoutExecStart(withFlags); a != b {
		t.Fatalf("the ExecStart argument changed more than ExecStart:\n--- bare ---\n%s\n--- with flags ---\n%s", a, b)
	}

	// The unit is line-oriented: a newline in the argument would forge
	// directives systemd would then honour.
	if _, err := Unit(GuestPath(NameAgent) + "\nExecStartPost=/bin/sh"); err == nil {
		t.Fatal("Unit accepted a newline in its ExecStart argument")
	}
}

func withoutExecStart(unit string) string {
	var keep []string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// The provisioning script is embedded, streamed into an arbitrary user's
// guest and run as root there. Two properties are worth pinning: it is the
// same file the dev flow runs (so the dev wrapper must reference it), and it
// does not touch daemon.json (that merge is provision.go's, because `down`
// has to restore exact bytes).
func TestProvisionScriptShape(t *testing.T) {
	s := ProvisionScript()
	if !strings.HasPrefix(s, "#!/usr/bin/env bash") {
		t.Fatalf("provisioning script must be executable bash; starts with %q", firstLine(s))
	}
	// It may *mention* daemon.json in a diagnostic; it may not go near
	// /etc/docker, which is the only place it could write one.
	if code := stripComments(s); strings.Contains(code, "/etc/docker") {
		t.Fatal("the provisioning script must not touch /etc/docker: `down` restores exact bytes, so the daemon.json writer is internal/guestbin/provision.go")
	}
	for _, flag := range []string{"--runc", "--restart-docker", "--test-image", "--ensure-docker"} {
		if !strings.Contains(s, flag) {
			t.Fatalf("provisioning script does not accept %s, which a caller passes", flag)
		}
	}

	// Every docker restart must clear systemd's start-limit counter first.
	// Reproduced live on colima: two restarts inside the burst window put
	// docker.service into `failed` with start-limit-hit, after which
	// `restart` does nothing at all — and `up --oci` fails *after* writing
	// daemon.json, which is the one place the "nothing changed" posture
	// cannot be recovered.
	code := stripComments(s)
	reset := strings.Index(code, "reset-failed docker")
	restart := strings.Index(code, "systemctl restart docker")
	switch {
	case reset < 0:
		t.Fatal("the provisioning script restarts docker without `systemctl reset-failed docker`; systemd's start rate limit then makes the restart a silent no-op")
	case restart >= 0 && reset > restart:
		t.Fatal("`reset-failed docker` must precede the restart, or it clears the counter after the restart it was meant to enable")
	}

	// One source: the dev wrapper must delegate here rather than carry its
	// own copy of the install/restart logic.
	dev, err := os.ReadFile(filepath.Join("..", "..", "scripts", "provision-docker.sh"))
	if err != nil {
		t.Fatalf("reading the dev wrapper: %v", err)
	}
	if !strings.Contains(string(dev), "internal/guestbin/assets/provision-docker.sh") {
		t.Fatal("scripts/provision-docker.sh must delegate to the embedded asset — otherwise `just vm-docker` and `drawbridge up --oci` drift")
	}
}

// stripComments drops whole-line shell comments, so an assertion about what
// the script *does* is not defeated by a comment explaining what it does not.
func stripComments(s string) string {
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

// The wrapper's installed NAME is its whole dispatch: one binary, and
// internal/ociruntime reads argv[0] to decide which runtime it stands in for.
// So the name this package installs and the name that package recognises are
// one contract, and a rename on either side is a wrapper that execs the wrong
// runtime (or itself).
func TestWrapperPathMatchesRuntimeDispatch(t *testing.T) {
	for _, tc := range []struct{ engine, want string }{
		{EngineDocker, ociruntime.RuntimeRunc},
		{EnginePodman, ociruntime.RuntimeCrun},
		{EngineNone, ociruntime.RuntimeRunc}, // unknown engines get the historical wrapper
		{"containerd", ociruntime.RuntimeRunc},
	} {
		path := WrapperPath(tc.engine)
		if got := ociruntime.RuntimeFor(path).Name; got != tc.want {
			t.Fatalf("WrapperPath(%q) = %q, which dispatches to %q, want %q", tc.engine, path, got, tc.want)
		}
		if !strings.HasPrefix(path, "/usr/local/bin/") {
			t.Fatalf("WrapperPath(%q) = %q, want it under /usr/local/bin", tc.engine, path)
		}
	}

	// Docker's wrapper path is the one already installed in every guest that
	// ran `up --oci`, and `down` removes exactly it. It must not move.
	if got := WrapperPath(EngineDocker); got != GuestPath(NameRunc) {
		t.Fatalf("the docker wrapper path moved to %q; every provisioned guest points at %q", got, GuestPath(NameRunc))
	}
}
