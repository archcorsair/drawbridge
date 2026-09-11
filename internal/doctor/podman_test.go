package doctor

import (
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
)

// podmanTarget is the fixture shape: a running rootless libkrun machine,
// exactly `podman:spike`.
func podmanTarget() PodmanInput {
	return PodmanInput{
		Target:   true,
		Instance: "spike",
		Config: vmprovider.MachineConfig{
			Name: "spike", VMType: "libkrun", Rootful: false,
			SSH:  vmprovider.PodmanSSH{Port: 57446, RemoteUsername: "core"},
			Path: "/Users/u/.config/containers/podman/machine/libkrun/spike.json",
		},
		Record: vmrecord.Record{
			Endpoint: "tcp://127.0.0.1:4778", Transport: vmrecord.TransportGvproxyPublish,
			VMType: "libkrun", SSH: vmrecord.SSH{Port: 57446, User: "core"},
		},
		RecordPresent: true,
		RecordPath:    "/Users/u/Library/Application Support/drawbridge/vm-podman-spike.json",
		Publish: PublishEvidence{
			Known: true, Local: "127.0.0.1:4778", Remote: "192.168.127.2:4777",
			Journal: []string{"gvproxy: published 127.0.0.1:4778 -> 192.168.127.2:4777 (the Mac dials tcp://127.0.0.1:4778)"},
		},
	}
}

// --- check 1 ---------------------------------------------------------------

// libkrun is podman 6's default macOS provider and both it and applehv are
// attachable. The "no host-reachable guest IP" wording a qemu Lima instance
// earns must never appear for one.
func TestCheckProvidersPodmanRunningIsOK(t *testing.T) {
	f := CheckProviders(ProvidersInput{
		Providers: []string{"podman"},
		Instances: []vmprovider.Instance{podmanInstance("spike", true)},
		Podman:    podmanTarget(),
	})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "running on libkrun")
	wantContains(t, f, "rootless")
	wantContains(t, f, "ssh port 57446")
	for _, forbidden := range []string{"no host-reachable guest IP", "vm-type vz", "limactl edit"} {
		if strings.Contains(strings.Join(append(f.Evidence, f.Title, f.Remedy), "\n"), forbidden) {
			t.Fatalf("a running podman machine was described in Lima's vocabulary (%q):\n%+v", forbidden, f)
		}
	}
}

// A rootful machine says so, because that is the fact that decides whether
// a container can bind :80 at all.
func TestCheckProvidersPodmanRootful(t *testing.T) {
	pm := podmanTarget()
	pm.Config.Rootful = true
	f := CheckProviders(ProvidersInput{
		Providers: []string{"podman"},
		Instances: []vmprovider.Instance{podmanInstance("spike", true)},
		Podman:    pm,
	})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "rootful")
}

// Only one podman machine runs at a time, so stopped siblings are the normal
// state and must not read as trouble.
func TestCheckProvidersPodmanStoppedSiblingIsNormal(t *testing.T) {
	f := CheckProviders(ProvidersInput{
		Providers: []string{"podman"},
		Instances: []vmprovider.Instance{
			podmanInstance("spike", true),
			podmanInstance("spike-rootful", false),
			podmanInstance("spike-hv", false),
		},
		Podman: podmanTarget(),
	})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "only one podman machine runs at a time")
}

// With nothing running at all the check still warns, and the podman start
// hint is the one it prints.
func TestCheckProvidersPodmanNothingRunning(t *testing.T) {
	f := CheckProviders(ProvidersInput{
		Providers: []string{"podman"},
		Instances: []vmprovider.Instance{podmanInstance("spike", false)},
	})
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "podman machine start spike")
}

// A Lima run is untouched: same status, same words.
func TestCheckProvidersLimaUnchanged(t *testing.T) {
	f := CheckProviders(ProvidersInput{
		Providers: []string{"lima"},
		Instances: []vmprovider.Instance{vz("lima", "drawbridge", true)},
	})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "MAC 52:55:55:a5:de:d2")
	if strings.Contains(strings.Join(f.Evidence, "\n"), "only one podman machine") {
		t.Fatal("a Lima run printed podman's note")
	}
}

// --- check 2 ---------------------------------------------------------------

func podmanGuest() GuestProbe {
	return GuestProbe{
		Ran: true, Kernel: "7.1.3-200.fc44.aarch64", BTF: true, CGroup2: true, Systemd: true, Sudo: true,
		OCI: true, Crun: "crun version 1.28", SELinux: "Enforcing", UnprivPort: "1024",
		ContainersFS: "virtiofs", Dropin: true,
		OCIRuntime: "/usr/local/bin/drawbridge-crun",
	}
}

// The finding 7.4 landed on, reported: the drop-in is one file on the Mac,
// shared by every machine.
func TestCheckGuestPrereqsPodmanSharedDropin(t *testing.T) {
	pm := podmanTarget()
	pm.Dropin = DropinEvidence{
		Present: true, Path: guestbin.DropinPath, Shared: true, FS: "virtiofs",
		MacPath:     "/Users/u/.config/containers/containers.conf.d/50-drawbridge.conf",
		RuntimePath: "/usr/local/bin/drawbridge-crun",
		WrapperPath: guestbin.WrapperPath(guestbin.EnginePodman),
		Machines:    []string{"podman:spike-rootful", "podman:spike-hv"},
	}
	f := CheckGuestPrereqs(podmanGuest(), "", pm)
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "ONE file on the Mac")
	wantContains(t, f, "/Users/u/.config/containers/containers.conf.d/50-drawbridge.conf")
	wantContains(t, f, "podman:spike-rootful")
	wantContains(t, f, "SELinux is Enforcing")
	wantContains(t, f, "ip_unprivileged_port_start is 1024")
}

// A drop-in that is present while podman reads some other runtime is the
// one state worth saying out loud, because the registration looks done.
func TestCheckGuestPrereqsPodmanDropinNotInEffect(t *testing.T) {
	pm := podmanTarget()
	pm.Dropin = DropinEvidence{
		Present: true, Path: guestbin.DropinPath,
		RuntimePath: "/usr/bin/crun",
		WrapperPath: guestbin.WrapperPath(guestbin.EnginePodman),
	}
	f := CheckGuestPrereqs(podmanGuest(), "", pm)
	wantContains(t, f, "NOT the wrapper")
}

// crun below the listenerPath floor warns, with the version in the title.
func TestCheckGuestPrereqsPodmanOldCrun(t *testing.T) {
	g := podmanGuest()
	g.Crun = "crun version 0.18"
	f := CheckGuestPrereqs(g, "", podmanTarget())
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "crun 0.18.0")
	wantContains(t, f, "listenerPath")
}

// A rootful machine's unprivileged-port floor is not a limitation worth
// mentioning: its containers are root in the init user namespace.
func TestCheckGuestPrereqsRootfulSkipsThePortNote(t *testing.T) {
	pm := podmanTarget()
	pm.Config.Rootful = true
	f := CheckGuestPrereqs(podmanGuest(), "", pm)
	if strings.Contains(strings.Join(f.Evidence, "\n"), "ip_unprivileged_port_start") {
		t.Fatalf("a rootful machine was told about the unprivileged port floor:\n%v", f.Evidence)
	}
}

// A Lima guest sees none of it.
func TestCheckGuestPrereqsLimaUnchanged(t *testing.T) {
	g := GuestProbe{Ran: true, Kernel: "6.8.0-51-generic", BTF: true, CGroup2: true, Systemd: true, Sudo: true}
	f := CheckGuestPrereqs(g, "", PodmanInput{})
	wantStatus(t, f, StatusOK)
	if strings.Contains(strings.Join(f.Evidence, "\n"), "SELinux") {
		t.Fatalf("a Lima guest got podman's notes:\n%v", f.Evidence)
	}
}

// --- check 3 ---------------------------------------------------------------

func podmanAgentGuest() GuestProbe {
	g := podmanGuest()
	g.AgentActive = "active"
	g.AgentVersion = "dev"
	g.GuestIPs = []string{"192.168.127.2"}
	g.Listeners = []Listener{{Addr: "127.0.0.1", Port: ControlPort}, {Addr: "192.168.127.2", Port: ControlPort}}
	return g
}

// The agent being up and the Mac being able to reach it are two claims on a
// podman machine, and the publish is what makes the second one true.
func TestCheckAgentPodmanPublished(t *testing.T) {
	g := podmanAgentGuest()
	f := CheckAgent(g, BindOf(g.Listeners, g.GuestIPs), "dev", "", podmanTarget())
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "published on 127.0.0.1:4778")
	wantContains(t, f, "gvproxy: 127.0.0.1:4778 -> 192.168.127.2:4777")
	wantContains(t, f, "gvproxy: published 127.0.0.1:4778")
}

// An agent that is running without its publish is running and unreachable.
func TestCheckAgentPodmanNotPublished(t *testing.T) {
	pm := podmanTarget()
	pm.Publish = PublishEvidence{Known: true}
	g := podmanAgentGuest()
	f := CheckAgent(g, BindOf(g.Listeners, g.GuestIPs), "dev", "", pm)
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "up but not published")
	wantContains(t, f, "journalctl")
}

// "I could not ask gvproxy" is not "it is not published".
func TestCheckAgentPodmanPublishUnknown(t *testing.T) {
	pm := podmanTarget()
	pm.Publish = PublishEvidence{Err: "no curl in the guest"}
	g := podmanAgentGuest()
	f := CheckAgent(g, BindOf(g.Listeners, g.GuestIPs), "dev", "", pm)
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "publish state unknown")
}

// A stopped agent is still check 3's fail, before any publish question.
func TestCheckAgentPodmanStopped(t *testing.T) {
	g := podmanAgentGuest()
	g.AgentActive = "inactive"
	f := CheckAgent(g, BindOf(g.Listeners, g.GuestIPs), "dev", "", podmanTarget())
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "is inactive")
}

// --- check 4 ---------------------------------------------------------------

func podmanResolution() limaaddr.Resolution {
	return limaaddr.Resolution{Endpoint: "tcp://127.0.0.1:4778", Source: "gvproxy-publish"}
}

// A gvproxy-published loopback endpoint is the design, not a fallback, so it
// must not warn the way a Lima run landing on the forwarder does.
func TestCheckResolutionPodmanIsNotAFallback(t *testing.T) {
	f := CheckResolution(ResolutionInput{Res: podmanResolution(), Ran: true, Podman: podmanTarget()})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "tcp://127.0.0.1:4778")
	if strings.Contains(f.Title, "fell back") {
		t.Fatalf("the podman path was reported as a fallback: %s", f.Title)
	}
}

// The 7.2 comparison, surfaced: a machine recreated under the same name has
// a new ssh port, and the record's endpoint stopped meaning anything.
func TestCheckResolutionPodmanRecordDisagrees(t *testing.T) {
	pm := podmanTarget()
	pm.Config.SSH.Port = 61000
	pm.Disagreements = pm.Record.Disagreements(pm.Config)
	if len(pm.Disagreements) == 0 {
		t.Fatal("the fixture does not disagree; the comparison under test is vacuous")
	}
	f := CheckResolution(ResolutionInput{Res: podmanResolution(), Ran: true, Podman: pm})
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "ssh port: recorded 57446, now 61000")
	wantContains(t, f, "drawbridge up")
	wantContains(t, f, "sudo drawbridge install")
}

// No record means the daemon has nothing to dial.
func TestCheckResolutionPodmanNoRecord(t *testing.T) {
	pm := podmanTarget()
	pm.RecordPresent = false
	f := CheckResolution(ResolutionInput{Res: podmanResolution(), Ran: true, Podman: pm})
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "no per-VM record")
}

// The root run must not read the user's record, and says what it reports
// instead: the endpoint `install` pinned into the plist.
func TestCheckResolutionPodmanRootReportsThePin(t *testing.T) {
	pm := podmanTarget()
	pm.EUID0 = true
	pm.RecordPresent = false
	pm.PinnedAgent = "tcp://127.0.0.1:4778"
	f := CheckResolution(ResolutionInput{Res: podmanResolution(), Ran: true, Podman: pm})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "the per-VM record is a user-owned file and is not read here")
	wantContains(t, f, "pinned -agent is tcp://127.0.0.1:4778")
	if strings.Contains(strings.Join(f.Evidence, "\n"), "vm-podman-spike.json") {
		t.Fatal("the root run named the user's record file")
	}
}

// --- checks 5 and 6 --------------------------------------------------------

// There is no vmnet route and no Local Network gate on a podman machine, so
// both checks skip and neither prints its Lima remedy.
func TestPodmanSkipsTheVZNATChecks(t *testing.T) {
	route := CheckVZNATRoute(RouteInput{Podman: true})
	wantStatus(t, route, StatusSkip)
	wantContains(t, route, "gvproxy is user-mode")

	ln := CheckLocalNetwork(LocalNetworkInput{Podman: true, UserProbe: ProbeFail})
	wantStatus(t, ln, StatusSkip)
	wantContains(t, ln, "loopback is not subject to the Local Network gate")
	if strings.Contains(ln.Remedy, "sudo drawbridge doctor") {
		t.Fatal("the sudo discriminator was printed for a run that cannot learn anything from it")
	}
}

// --- check 10 --------------------------------------------------------------

func TestCheckCoexistencePodman(t *testing.T) {
	fwd := vmprovider.Forwarding{
		Instance: "spike", Provider: vmprovider.ProviderPodman, HostAgent: true,
		Wildcard: vmprovider.PortSet{{Lo: 8081, Hi: 8081}},
	}
	f := CheckCoexistence(CoexistenceInput{Known: true, Fwd: fwd})
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "published ports")
	wantContains(t, f, "A published container is bridged")
	wantContains(t, f, "drop the `-p`")
	// Lima's remedy would be wrong here: there is no portForwards stanza.
	if strings.Contains(f.Remedy, "portForwards") {
		t.Fatalf("a podman machine got Lima's remedy:\n%s", f.Remedy)
	}
}

// The baseline (agent published, nothing else) is not coexistence: the ssh
// forward and drawbridge's own publish are filtered out before this.
func TestCheckCoexistencePodmanBaseline(t *testing.T) {
	fwd := vmprovider.Forwarding{Instance: "spike", Provider: vmprovider.ProviderPodman, HostAgent: true}
	f := CheckCoexistence(CoexistenceInput{Known: true, Fwd: fwd})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "nothing published")
}

// --- check 8 ---------------------------------------------------------------

// On a podman machine the loopback endpoint IS the transport's path, so the
// caveat that calls a loopback result "evidence about the agent, not the
// path" would be false.
func TestCheckHalfClosePodmanLoopbackIsEvidence(t *testing.T) {
	p := HalfCloseProbe{
		Ran: true, Endpoint: "tcp://127.0.0.1:4778", Source: "gvproxy-publish",
		Loopback: true, DirectPath: true, Window: ProbePostFINWindow,
		PreBytes: 120, PreEvents: 1, PostBytes: 30, PostEvents: 1,
	}
	f := CheckHalfClose(p)
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "that IS the transport's path")
	if strings.Contains(strings.Join(f.Evidence, "\n"), "NOT about the vznat-direct path") {
		t.Fatal("the loopback caveat was printed for a path that has no vznat alternative")
	}
}

// And a starve on that path is a real failure with a real suspect, not the
// "loopback should never show this" warn a Lima fallback earns.
func TestCheckHalfClosePodmanStarveFails(t *testing.T) {
	p := HalfCloseProbe{
		Ran: true, Endpoint: "tcp://127.0.0.1:4778", Source: "gvproxy-publish",
		Loopback: true, DirectPath: true, Window: ProbePostFINWindow,
		PreBytes: 120, PreEvents: 1,
	}
	f := CheckHalfClose(p)
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "gvproxy")
	wantContains(t, f, "2025-01-21")
}

// A Lima loopback fallback keeps its old warn and its old caveat.
func TestCheckHalfCloseLimaLoopbackUnchanged(t *testing.T) {
	p := HalfCloseProbe{
		Ran: true, Endpoint: "tcp://127.0.0.1:4777", Source: limaaddr.SourceSSHForwarder,
		Loopback: true, Window: ProbePostFINWindow, PreBytes: 120, PreEvents: 1,
	}
	f := CheckHalfClose(p)
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "NOT about the vznat-direct path")
}

// --- the publish parser ----------------------------------------------------

func TestPublishEvidenceFromTheGuestTable(t *testing.T) {
	g := GuestProbe{Gvproxy: `[{"local":"127.0.0.1:4778","remote":"192.168.127.2:4777","protocol":"tcp"},
 {"local":"127.0.0.1:57446","remote":"192.168.127.2:22","protocol":"tcp"}]`}
	p := publishEvidence(g)
	if !p.Known {
		t.Fatal("the table parsed but was not marked known")
	}
	if p.Local != "127.0.0.1:4778" || p.Remote != "192.168.127.2:4777" {
		t.Fatalf("publish = %+v", p)
	}
}

func TestPublishEvidenceMissingPublish(t *testing.T) {
	g := GuestProbe{Gvproxy: `[{"local":"127.0.0.1:57446","remote":"192.168.127.2:22","protocol":"tcp"}]`}
	p := publishEvidence(g)
	if !p.Known {
		t.Fatal("a table without our forward is still a table that was read")
	}
	if p.Local != "" {
		t.Fatalf("found a publish that is not there: %+v", p)
	}
}

func TestPublishEvidenceUnreadable(t *testing.T) {
	p := publishEvidence(GuestProbe{GvproxyErr: "no curl in the guest"})
	if p.Known {
		t.Fatal("an unreadable table was reported as known")
	}
	if p.Err == "" {
		t.Fatal("no reason recorded")
	}
}

// The guest script's fenced blocks round-trip: the table and the journal
// lines are not mistaken for key=value lines.
func TestParseGuestProbeFences(t *testing.T) {
	out := strings.Join([]string{
		"kernel=7.1.3",
		"dropin=yes",
		"oci_runtime=/usr/local/bin/drawbridge-crun",
		"containers_fs=virtiofs",
		"selinux=Enforcing",
		"ss-begin",
		"LISTEN 0 4096 127.0.0.1:4777 0.0.0.0:*",
		"ss-end",
		"gvproxy-begin",
		`[{"local":"127.0.0.1:4778","remote":"192.168.127.2:4777","protocol":"tcp"}]`,
		"gvproxy-end",
		"journal-begin",
		"Sep 11 12:18:40 host drawbridge-agent[1]: gvproxy: published 127.0.0.1:4778 -> 192.168.127.2:4777",
		"journal-end",
	}, "\n")
	g := ParseGuestProbe(out)
	if !g.Dropin || g.OCIRuntime != "/usr/local/bin/drawbridge-crun" || g.ContainersFS != "virtiofs" || g.SELinux != "Enforcing" {
		t.Fatalf("keys not parsed: %+v", g)
	}
	if len(g.Listeners) != 1 || g.Listeners[0].Port != ControlPort {
		t.Fatalf("listeners = %+v", g.Listeners)
	}
	if !strings.HasPrefix(g.Gvproxy, "[{") {
		t.Fatalf("gvproxy = %q", g.Gvproxy)
	}
	if len(g.Journal) != 1 || !strings.Contains(g.Journal[0], "gvproxy: published") {
		t.Fatalf("journal = %v", g.Journal)
	}
}
