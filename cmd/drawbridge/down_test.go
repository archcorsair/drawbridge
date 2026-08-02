package main

import (
	"os"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/guestbin"
)

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func runDownOn(t *testing.T, f *fakeGuest) error {
	t.Helper()
	_, err := runDownCapturing(t, f)
	return err
}

// runDownCapturing is runDownOn with `down`'s own output, for the paths
// whose whole point is what the user is told.
func runDownCapturing(t *testing.T, f *fakeGuest) (string, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // `down` names the Mac-side secret it keeps
	sel := testSelection(t, "lima:drawbridge")
	var out strings.Builder
	err := down(&guest{p: f, inst: sel.Ref.Instance, out: &out}, sel)
	return out.String(), err
}

// A guest that never had drawbridge is a no-op success, not an error: `down`
// is idempotent in the same way `up` is, and a teardown that fails when
// there is nothing to tear down is unusable in a script.
func TestDownOnCleanGuest(t *testing.T) {
	f := newFakeGuest(t)
	if err := runDownOn(t, f); err != nil {
		t.Fatal(err)
	}
	if len(f.files) != 0 {
		t.Fatalf("down created files on a clean guest: %v", f.files)
	}
}

// The round trip §8's Phase 4 verify asserts live: `up` then `down` leaves
// no drawbridge files behind.
func TestDownRemovesEverything(t *testing.T) {
	f := newFakeGuest(t)
	if err := runUpOn(t, f, upOptions{agentBin: writeTempBinary(t, "agent")}); err != nil {
		t.Fatal(err)
	}
	if err := runDownOn(t, f); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{agentPath, runcGuest, guestbin.UnitPath, guestbin.ProvisionPath} {
		if _, ok := f.files[p]; ok {
			t.Fatalf("%s survived down", p)
		}
	}
	if f.enabled || f.active {
		t.Fatalf("the unit is still enabled=%v active=%v after down", f.enabled, f.active)
	}
}

// The literal §8 assertion: after `up --oci` and `down`, docker's config is
// byte-identical to what it was — indentation, key order and all.
func TestDownRestoresDaemonJSONByteIdentical(t *testing.T) {
	const before = "{\n    \"log-driver\": \"json-file\",\n    \"log-opts\": {\n        \"max-size\": \"10m\"\n    }\n}\n"
	f := newFakeGuest(t).withDocker()
	f.files[guestbin.DaemonJSONPath] = before

	if err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	}); err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.DaemonJSONPath] == before {
		t.Fatal("up --oci did not change daemon.json, so the revert proves nothing")
	}
	if err := runDownOn(t, f); err != nil {
		t.Fatal(err)
	}
	if got := f.files[guestbin.DaemonJSONPath]; got != before {
		t.Fatalf("daemon.json is not byte-identical after down:\n--- got ---\n%s\n--- want ---\n%s", got, before)
	}
	if !f.ran("systemctl restart docker") {
		t.Fatal("daemon.json was reverted but docker was not restarted, so the engine keeps the old config")
	}
}

// A daemon.json `up --oci` created is removed, not left behind as an empty
// object — the guest ends up as it started.
func TestDownRemovesCreatedDaemonJSON(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	if err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := runDownOn(t, f); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.files[guestbin.DaemonJSONPath]; ok {
		t.Fatalf("daemon.json survived a down that should have removed it:\n%s", f.files[guestbin.DaemonJSONPath])
	}
}

// The wrapper must outlive the daemon.json revert: removing it first leaves
// docker with a default-runtime pointing at a path that does not exist,
// which is a guest where no container starts at all.
func TestDownRevertsBeforeRemovingWrapper(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	if err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	}); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := runDownOn(t, f); err != nil {
		t.Fatal(err)
	}
	restart, remove := -1, -1
	for i, c := range f.calls {
		if restart < 0 && strings.Contains(c, "systemctl restart docker") {
			restart = i
		}
		if remove < 0 && strings.Contains(c, "rm -f '"+runcGuest+"'") {
			remove = i
		}
	}
	if restart < 0 || remove < 0 {
		t.Fatalf("expected both a docker restart and a wrapper removal:\n%s", strings.Join(f.calls, "\n"))
	}
	if restart > remove {
		t.Fatal("the wrapper was removed before docker reloaded a config that no longer references it")
	}
}

// Finding 1 on the teardown side: the rate limit is just as reachable here
// (`up --oci` restarted docker, `down` restarts it again minutes later), and
// a refused restart is worse during `down` than during `up` — the wrapper is
// deleted immediately afterwards.
func TestDownRecoversWedgedDocker(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	if err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	}); err != nil {
		t.Fatal(err)
	}
	f.dockerWedged, f.dockerActive = true, false

	out, err := runDownCapturing(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if !f.ran("systemctl reset-failed docker") {
		t.Fatalf("down restarted docker without clearing systemd's start-limit counter:\n%s", strings.Join(f.calls, "\n---\n"))
	}
	if !f.dockerActive {
		t.Fatal("docker was not brought back up")
	}
	if !strings.Contains(out, "restarted docker") {
		t.Fatalf("down did not report the restart:\n%s", out)
	}
}

// Finding 2: a restart that genuinely fails must be loud. The wrapper is
// about to be deleted while a running dockerd still has default-runtime
// pointing at it — silence there is a guest that starts no containers and
// gives no clue why.
func TestDownWarnsLoudlyWhenDockerWillNotRestart(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	if err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	}); err != nil {
		t.Fatal(err)
	}
	f.dockerBroken, f.dockerActive = true, false

	out, err := runDownCapturing(t, f)
	if err != nil {
		// down still completes: the files go, and the warning is the
		// deliverable. Failing here would leave the guest half-torn-down.
		t.Fatalf("down failed instead of warning: %v", err)
	}
	for _, want := range []string{"WARNING", "did not restart", "reset-failed docker && sudo systemctl restart docker"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the warning does not mention %q:\n%s", want, out)
		}
	}
	if _, ok := f.files[runcGuest]; ok {
		t.Fatal("the wrapper survived down; the warning describes a state that did not happen")
	}
}

// A guest with no docker at all gets neither a restart nor a warning: there
// is no engine holding the old config.
func TestDownSilentWhenDockerAbsent(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	if err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	}); err != nil {
		t.Fatal(err)
	}
	f.hasDocker = false // engine removed between up and down

	out, err := runDownCapturing(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "WARNING") || strings.Contains(out, "restarted docker") {
		t.Fatalf("down reported an engine that is not there:\n%s", out)
	}
}

// Without a state file, `down` leaves daemon.json alone. That is what makes
// it safe after the dev flow (`just vm-docker` provisions the same wrapper
// and writes no state), and it is the "never a guess" rule in action.
func TestDownWithoutStateLeavesDaemonJSON(t *testing.T) {
	const devProvisioned = `{"default-runtime":"drawbridge","runtimes":{"drawbridge":{"path":"/usr/local/bin/drawbridge-runc"}}}`
	f := newFakeGuest(t).withDocker()
	f.files[guestbin.DaemonJSONPath] = devProvisioned
	if err := runDownOn(t, f); err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.DaemonJSONPath] != devProvisioned {
		t.Fatalf("down changed a daemon.json it has no record of writing:\n%s", f.files[guestbin.DaemonJSONPath])
	}
}
