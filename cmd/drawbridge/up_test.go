package main

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
)

const (
	agentPath = "/usr/local/bin/drawbridge-agent"
	runcGuest = "/usr/local/bin/drawbridge-runc"
)

func testSelection(t *testing.T, spec string) selection {
	t.Helper()
	ref, err := vmprovider.ParseRef(spec)
	if err != nil {
		t.Fatal(err)
	}
	return selection{Ref: ref, Instance: vmprovider.Instance{
		Provider: ref.Provider, Name: ref.Instance, VMType: "vz", Running: true,
	}}
}

func runUpOn(t *testing.T, f *fakeGuest, o upOptions) error {
	t.Helper()
	// `up` now writes the Mac-side transport secret under the user's home
	// (docs/transport-auth.md §5). No test may touch the real one.
	t.Setenv("HOME", t.TempDir())
	sel := testSelection(t, "lima:drawbridge")
	return up(&guest{p: f, inst: sel.Ref.Instance, out: io.Discard}, sel, o)
}

// The whole of steps 2–4 against a guest that has never seen drawbridge.
func TestUpFirstRun(t *testing.T) {
	f := newFakeGuest(t)
	agent := writeTempBinary(t, "agent-bytes")
	if err := runUpOn(t, f, upOptions{agentBin: agent}); err != nil {
		t.Fatal(err)
	}
	if f.files[agentPath] != "agent-bytes" {
		t.Fatalf("agent not installed: %q", f.files[agentPath])
	}
	// Named explicitly so the "did not happen" assertions in
	// TestUpIdempotent cannot go vacuous if a command spelling changes.
	if !f.ran("dd of=/tmp/usr-local-bin-drawbridge-agent.new") {
		t.Fatal("the agent was not streamed over the provider shell")
	}
	if !f.ran("install -m 0644") {
		t.Fatal("the unit was not installed with mode 0644")
	}
	unit, ok := f.files[guestbin.UnitPath]
	if !ok || !strings.Contains(unit, "ExecStart="+agentPath) {
		t.Fatalf("unit not installed correctly: %q", unit)
	}
	if !f.enabled || !f.active {
		t.Fatalf("agent unit enabled=%v active=%v, want both", f.enabled, f.active)
	}
	// No --oci: nothing about docker, and no state file to revert.
	if _, ok := f.files[guestbin.DaemonJSONPath]; ok {
		t.Fatal("up without --oci touched daemon.json")
	}
	if _, ok := f.files[guestbin.ProvisionPath]; ok {
		t.Fatal("up without --oci wrote a provisioning state file")
	}
}

// The idempotent re-run is the one users repeat, so its cost matters: an
// unchanged agent must not be streamed and the unit must not be rewritten.
func TestUpIdempotent(t *testing.T) {
	f := newFakeGuest(t)
	agent := writeTempBinary(t, "agent-bytes")
	if err := runUpOn(t, f, upOptions{agentBin: agent}); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := runUpOn(t, f, upOptions{agentBin: agent}); err != nil {
		t.Fatal(err)
	}
	if f.ran("dd of=/tmp/usr-local-bin-drawbridge-agent.new") {
		t.Fatal("re-run streamed an agent the guest already had — the sha256 comparison is not short-circuiting")
	}
	if f.ran("install -m 0644") {
		t.Fatal("re-run rewrote the unit file although it was unchanged")
	}
}

// A changed binary must actually reach the running agent. `enable --now` on
// an already-enabled unit does nothing, so without the explicit restart the
// guest would keep running the old code and `up` would report success.
func TestUpRestartsOnBinaryChange(t *testing.T) {
	f := newFakeGuest(t)
	if err := runUpOn(t, f, upOptions{agentBin: writeTempBinary(t, "v1")}); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := runUpOn(t, f, upOptions{agentBin: writeTempBinary(t, "v2")}); err != nil {
		t.Fatal(err)
	}
	if f.files[agentPath] != "v2" {
		t.Fatalf("agent not refreshed: %q", f.files[agentPath])
	}
	if !f.ran("systemctl restart") {
		t.Fatal("a new agent binary did not trigger a restart")
	}
}

// The transient-vs-persistent unit fight. `just agent-up` holds the unit
// name with a transient unit; `systemctl enable --now` against it is a
// silent no-op, so `up` would claim success and leave the dev agent running.
func TestUpStopsTransientUnit(t *testing.T) {
	f := newFakeGuest(t)
	f.transient, f.active = true, true
	if err := runUpOn(t, f, upOptions{agentBin: writeTempBinary(t, "agent")}); err != nil {
		t.Fatal(err)
	}
	if !f.ran("systemctl stop") || !f.ran("systemctl reset-failed") {
		t.Fatalf("the transient unit was not cleared before enabling the persistent one:\n%s", strings.Join(f.calls, "\n"))
	}
	if !f.ran("systemctl restart") {
		t.Fatal("after replacing a transient unit, the persistent one must be restarted rather than assumed started")
	}
}

// A dev build has no bundled agent. It must say so — with the remedy — and
// before touching the guest at all (§4.2: the failure posture is "nothing
// changed").
func TestUpUnbundledFailsBeforeMutating(t *testing.T) {
	if guestbin.Bundled() {
		t.Skip("this tree has been built; ErrNotBundled is not reachable")
	}
	f := newFakeGuest(t)
	err := runUpOn(t, f, upOptions{})
	if err == nil || !strings.Contains(err.Error(), "just build") {
		t.Fatalf("up on a dev build: got %v, want the ErrNotBundled remedy", err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "cat > ") || strings.Contains(c, "install -m") {
			t.Fatalf("up mutated the guest before failing: %q", c)
		}
	}
}

// --oci on a guest with no daemon.json: the file is created, the state file
// records that it was created, and docker is restarted exactly once because
// the config changed.
func TestUpOCICreatesDaemonJSON(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.files[runcGuest] != "runc" {
		t.Fatalf("wrapper not installed by the provisioning script: %q", f.files[runcGuest])
	}
	if !strings.Contains(f.files[guestbin.DaemonJSONPath], `"default-runtime": "drawbridge"`) {
		t.Fatalf("daemon.json not merged:\n%s", f.files[guestbin.DaemonJSONPath])
	}
	st, err := guestbin.DecodeState([]byte(f.files[guestbin.ProvisionPath]))
	if err != nil {
		t.Fatal(err)
	}
	if st.DaemonJSONExisted || !st.AddedRuntime || !st.SetDefaultRuntime {
		t.Fatalf("state does not record a created file: %+v", st)
	}
	if !f.ran("--restart-docker") {
		t.Fatal("daemon.json changed but docker was not restarted")
	}
}

// The second `up --oci` must not overwrite the state file. Its
// DaemonJSONBefore would then hold the *merged* content, and `down` would
// "restore" the guest to the state it is trying to leave.
func TestUpOCIKeepsFirstState(t *testing.T) {
	f := newFakeGuest(t).withDocker()
	f.files[guestbin.DaemonJSONPath] = "{\n  \"log-driver\": \"journald\"\n}\n"
	o := upOptions{oci: true, agentBin: writeTempBinary(t, "agent"), runcBin: writeTempBinary(t, "runc")}
	if err := runUpOn(t, f, o); err != nil {
		t.Fatal(err)
	}
	first := f.files[guestbin.ProvisionPath]

	f.calls = nil
	if err := runUpOn(t, f, o); err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.ProvisionPath] != first {
		t.Fatalf("the second up --oci rewrote the state file:\n--- was ---\n%s\n--- now ---\n%s", first, f.files[guestbin.ProvisionPath])
	}
	if f.ran("--restart-docker") {
		t.Fatal("an unchanged daemon.json must not restart docker — that kills running containers")
	}
}

// --oci against a guest with no docker is refused in the preflight, before
// anything is pushed.
func TestUpOCIWithoutDocker(t *testing.T) {
	f := newFakeGuest(t) // docker=no
	err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	})
	if err == nil || !strings.Contains(err.Error(), "no docker in the guest") {
		t.Fatalf("up --oci without docker: got %v, want a preflight refusal", err)
	}
	if len(f.files) != 0 {
		t.Fatalf("the guest was mutated despite a failed preflight: %v", f.files)
	}
}

// Finding 1, live: two docker restarts inside systemd's burst window leave
// docker.service `failed` with start-limit-hit, and every subsequent
// `restart` is refused outright. `up --oci` has to clear the counter, or a
// perfectly healthy guest fails provisioning for a reason that has nothing
// to do with drawbridge.
func TestUpOCIRecoversWedgedDocker(t *testing.T) {
	f := newFakeGuest(t).withWedgedDocker()
	err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	})
	if err != nil {
		t.Fatalf("up --oci against a rate-limited docker: %v", err)
	}
	if !f.dockerActive {
		t.Fatal("docker was not brought back up")
	}
}

// Finding 3: when the restart fails anyway, the daemon.json write has
// already happened — this is the one step that cannot honour "nothing
// changed", so it has to say precisely what did change and how to get out.
func TestUpOCIProvisionFailureIsDiagnosed(t *testing.T) {
	f := newFakeGuest(t).withBrokenDocker()
	err := runUpOn(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	})
	if err == nil {
		t.Fatal("up --oci succeeded against an engine that will not start")
	}
	for _, want := range []string{
		"the agent is installed and running", // what still works
		guestbin.DaemonJSONPath,              // what changed
		"HAS been updated",
		"reset-failed docker",         // way out 1
		"`drawbridge up --oci`",       // …re-run
		"`drawbridge down` to revert", // way out 2
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the failure message does not mention %q:\n%s", want, err)
		}
	}
	// And it must not be the raw shell error on its own.
	if strings.HasPrefix(err.Error(), "provisioning the OCI wrapper") {
		t.Fatalf("the failure is still a raw exec error:\n%s", err)
	}
}

func writeTempBinary(t *testing.T, content string) string {
	t.Helper()
	path := t.TempDir() + "/bin"
	if err := writeFileForTest(path, content); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- the podman branch (docs/podman.md §3.2, §3.4, §5.2, §5.4) -------------

func runUpOnPodman(t *testing.T, f *fakeGuest, o upOptions) (selection, error) {
	t.Helper()
	// The Mac-side record lands under the user's home (docs/podman.md §3.4).
	// No test may touch the real one.
	t.Setenv("HOME", t.TempDir())
	return upPodman(t, f, o)
}

// upPodman is runUpOnPodman without the home fixture, for a test that runs
// `up` twice against the same Mac-side state.
func upPodman(t *testing.T, f *fakeGuest, o upOptions) (selection, error) {
	t.Helper()
	sel := testSelection(t, "podman:spike")
	sel.Instance.VMType = "libkrun"
	return sel, up(&guest{p: f, inst: sel.Ref.Instance, out: io.Discard}, sel, o)
}

// A podman guest gets the same agent, the same unit path and the same secret
// as a Lima one; what differs is the ExecStart line (the Mac cannot reach the
// transport without the gvproxy publish) and the Mac-side record that
// remembers which port that was.
func TestUpPodmanPublishesAndRecords(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	sel, err := runUpOnPodman(t, f, upOptions{agentBin: writeTempBinary(t, "agent-bytes")})
	if err != nil {
		t.Fatal(err)
	}

	rec, err := vmrecord.Read(sel.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Transport != vmrecord.TransportGvproxyPublish {
		t.Fatalf("transport = %q, want %q", rec.Transport, vmrecord.TransportGvproxyPublish)
	}
	port := recordedPort(rec)
	if port < publishPortLo || port > publishPortHi {
		t.Fatalf("recorded endpoint %q is outside %d-%d", rec.Endpoint, publishPortLo, publishPortHi)
	}
	// 4777 is deliberately excluded: a Lima dev VM's SSH forward holds it.
	if port == controlPort {
		t.Fatalf("chose %d, the port a Lima dev VM's SSH forward holds", controlPort)
	}
	// The ssh coordinates come from `machine inspect`, so doctor can compare
	// them against a live one and catch a machine recreated under the name.
	if rec.SSH.Port != 57446 || rec.SSH.User != "core" || rec.SSH.Identity == "" {
		t.Fatalf("ssh coordinates not recorded: %+v", rec.SSH)
	}
	if rec.VMType != "libkrun" {
		t.Fatalf("vmtype = %q, want libkrun", rec.VMType)
	}

	unit := f.files[guestbin.UnitPath]
	want := "ExecStart=" + agentPath + " -gvproxy-publish 127.0.0.1:" + strconv.Itoa(port) + "\n"
	if !strings.Contains(unit, want) {
		t.Fatalf("unit does not publish through gvproxy:\n%s", unit)
	}
}

// The recorded port is reused as-is on a re-run, without a bind probe: by
// then gvproxy is holding it, so probing would find it busy, move the
// endpoint, rewrite the unit and restart a perfectly healthy agent.
func TestUpPodmanIsIdempotent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeGuest(t).withFCOS()
	agent := writeTempBinary(t, "agent-bytes")
	sel, err := upPodman(t, f, upOptions{agentBin: agent})
	if err != nil {
		t.Fatal(err)
	}
	first, err := vmrecord.Read(sel.Ref)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the recorded port, exactly as gvproxy does once the agent has
	// published it.
	ln, err := net.Listen("tcp", strings.TrimPrefix(first.Endpoint, "tcp://"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	f.calls = nil
	if _, err := upPodman(t, f, upOptions{agentBin: agent}); err != nil {
		t.Fatal(err)
	}
	second, err := vmrecord.Read(sel.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if second.Endpoint != first.Endpoint {
		t.Fatalf("the re-run moved the endpoint from %s to %s while gvproxy held it", first.Endpoint, second.Endpoint)
	}
	if f.ran("install -m 0644") {
		t.Fatal("the re-run rewrote the unit although nothing about it changed")
	}
	if f.ran("dd of=/tmp/usr-local-bin-drawbridge-agent.new") {
		t.Fatal("the re-run streamed an agent the guest already had")
	}
}

// Fedora CoreOS runs SELinux Enforcing. Every file installed into the guest
// gets its label restored, and on a guest without restorecon nothing is
// attempted at all — not even the round trip to find out.
func TestUpRelabelsOnSELinuxGuestsOnly(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	if _, err := runUpOnPodman(t, f, upOptions{agentBin: writeTempBinary(t, "agent")}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{agentPath, guestbin.UnitPath, guestbin.SecretPath} {
		var found bool
		for _, p := range f.relabelled {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s was installed without a restorecon: %v", want, f.relabelled)
		}
	}

	lima := newFakeGuest(t)
	if err := runUpOn(t, lima, upOptions{agentBin: writeTempBinary(t, "agent")}); err != nil {
		t.Fatal(err)
	}
	if len(lima.relabelled) != 0 || lima.ran("restorecon -F") {
		t.Fatalf("a guest with no restorecon was asked to relabel anyway: %v", lima.relabelled)
	}
}

// --oci on podman would register a runc wrapper in a daemon.json no engine
// reads. It is refused before the guest is touched at all.
func TestUpPodmanRefusesOCI(t *testing.T) {
	f := newFakeGuest(t).withFCOS()
	_, err := runUpOnPodman(t, f, upOptions{
		oci:      true,
		agentBin: writeTempBinary(t, "agent"),
		runcBin:  writeTempBinary(t, "runc"),
	})
	if err == nil || !strings.Contains(err.Error(), "7.4") {
		t.Fatalf("up --oci on podman = %v, want a refusal naming the phase it lands in", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("the guest was shelled into despite the refusal: %v", f.calls)
	}
}

// A Lima guest's unit must stay byte-identical: no -gvproxy-publish, and
// therefore no rewrite and no restart on a guest that was already correct.
func TestUpLimaUnitIsUnchanged(t *testing.T) {
	f := newFakeGuest(t)
	if err := runUpOn(t, f, upOptions{agentBin: writeTempBinary(t, "agent")}); err != nil {
		t.Fatal(err)
	}
	want, err := guestbin.Unit(agentPath)
	if err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.UnitPath] != want {
		t.Fatalf("the Lima unit changed:\n--- got ---\n%s\n--- want ---\n%s", f.files[guestbin.UnitPath], want)
	}
	if strings.Contains(f.files[guestbin.UnitPath], "gvproxy") {
		t.Fatal("a Lima guest's unit carries a podman flag")
	}
}
