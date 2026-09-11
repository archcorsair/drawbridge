package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
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

// `down` on a podman guest removes what `up` put there, the unit, the
// binary, the state directory, plus the one thing that lives on the Mac and
// would otherwise name a port nothing publishes any more.
//
// And it never goes near docker: the revert path ends in a docker restart,
// which on a guest whose only engine is podman is a command aimed at nothing.
func TestDownPodmanRemovesTheRecordAndNeverTouchesDocker(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeGuest(t).withFCOS()

	sel, err := upPodman(t, f, upOptions{agentBin: writeTempBinary(t, "agent")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vmrecord.Read(sel.Ref); err != nil {
		t.Fatal(err)
	}

	f.calls = nil
	var out strings.Builder
	if err := down(&guest{p: f, inst: sel.Ref.Instance, out: &out}, sel); err != nil {
		t.Fatal(err)
	}

	if _, err := vmrecord.Read(sel.Ref); !errors.Is(err, vmrecord.ErrAbsent) {
		t.Fatalf("the Mac-side record survived `down`: %v", err)
	}
	for _, p := range []string{guestbin.UnitPath, agentPath, guestbin.SecretPath} {
		if _, ok := f.files[p]; ok {
			t.Fatalf("%s survived `down`", p)
		}
	}
	if f.ran("docker") {
		t.Fatalf("`down` on a podman guest went near docker:\n%s", strings.Join(f.calls, "\n"))
	}

	// Idempotent in both halves: a second run removes nothing and fails at
	// nothing, including the record that is already gone.
	if err := down(&guest{p: f, inst: sel.Ref.Instance, out: io.Discard}, sel); err != nil {
		t.Fatalf("a second `down` failed: %v", err)
	}
}

// --- `down` on a podman guest provisioned with --oci (§6.2) ----------------

// upThenDownPodmanOCI runs the whole round trip against one fake guest and
// hands back its output, since what `down` says is half of what it does.
func upThenDownPodmanOCI(t *testing.T, f *fakeGuest, before func()) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	sel, err := upPodman(t, f, upOptions{
		oci: true, agentBin: writeTempBinary(t, "agent"), runcBin: writeTempBinary(t, "wrapper"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.DropinPath] == "" {
		t.Fatal("up --oci wrote no drop-in")
	}
	if before != nil {
		before()
	}
	f.calls, f.podmanRestarted = nil, false
	var out strings.Builder
	if err := down(&guest{p: f, inst: sel.Ref.Instance, out: &out}, sel); err != nil {
		t.Fatalf("down: %v\n%s", err, out.String())
	}
	return out.String()
}

// The round trip: everything `up --oci` wrote is gone, and the drop-in goes
// before the wrapper it names.
func TestDownPodmanOCIRemovesTheDropin(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	f.podmanAPIActive = true
	out := upThenDownPodmanOCI(t, f, nil)

	for _, p := range []string{
		guestbin.DropinPath,
		guestbin.WrapperPath(guestbin.EnginePodman),
		guestbin.UnitPath,
		guestbin.ProvisionPath,
		agentPath,
	} {
		if _, ok := f.files[p]; ok {
			t.Fatalf("%s survived `down`", p)
		}
	}
	if !strings.Contains(out, "removed "+guestbin.DropinPath) {
		t.Fatalf("down did not say it removed the drop-in:\n%s", out)
	}
	// Ordering: the registration goes while the binary it names still
	// exists, the same rule the docker path follows.
	dropinAt, wrapperAt := -1, -1
	for i, r := range f.removed {
		if r == guestbin.DropinPath && dropinAt < 0 {
			dropinAt = i
		}
		if r == guestbin.WrapperPath(guestbin.EnginePodman) && wrapperAt < 0 {
			wrapperAt = i
		}
	}
	if dropinAt < 0 || wrapperAt < 0 || dropinAt > wrapperAt {
		t.Fatalf("drop-in removed at %d, wrapper at %d: %v", dropinAt, wrapperAt, f.removed)
	}
	if !f.podmanRestarted {
		t.Fatal("the running API service was not reloaded after the registration was removed")
	}
	// And nothing anywhere near docker: the revert path's docker restart is
	// a command aimed at nothing on a guest whose only engine is podman.
	if f.ran("docker") {
		t.Fatalf("`down` on a podman guest went near docker:\n%s", strings.Join(f.calls, "\n"))
	}
}

// A drop-in edited since `up` is left exactly where it is, and `down` says
// so by name. Guessing is the one thing the recorded digest exists to
// prevent.
func TestDownPodmanOCIKeepsAnEditedDropin(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	out := upThenDownPodmanOCI(t, f, func() {
		f.files[guestbin.DropinPath] += "# an administrator was here\n"
	})
	if _, ok := f.files[guestbin.DropinPath]; !ok {
		t.Fatal("an edited drop-in was deleted")
	}
	if !strings.Contains(out, "edited since `up`; not removed") || !strings.Contains(out, guestbin.DropinPath) {
		t.Fatalf("down did not name the file it kept:\n%s", out)
	}
	// The wrapper still goes: the drop-in's second element is the real
	// crun, so podman keeps starting containers on stock crun either way.
	if _, ok := f.files[guestbin.WrapperPath(guestbin.EnginePodman)]; ok {
		t.Fatal("the wrapper survived down")
	}
}

// A drop-in already gone is a no-op, not an error, and `down` stays silent
// about it: there is nothing for the user to do.
func TestDownPodmanOCIWithTheDropinAlreadyGone(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	out := upThenDownPodmanOCI(t, f, func() { delete(f.files, guestbin.DropinPath) })
	if strings.Contains(out, "not removed") {
		t.Fatalf("down complained about a file that was already gone:\n%s", out)
	}
}

// A state file from a build this one does not understand is refused, not
// guessed at — the rule that has applied to daemon.json since Phase 4,
// carried forward to the version that replaced it.
func TestDownRefusesANewerStateFile(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	f.files[guestbin.ProvisionPath] = `{"version":99,"engine":"podman"}` + "\n"
	err := runDownOn(t, f)
	if err == nil || !strings.Contains(err.Error(), "newer drawbridge") {
		t.Fatalf("down against a version-99 state file = %v, want a refusal", err)
	}
}
