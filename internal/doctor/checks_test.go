package doctor

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func vz(provider, name string, running bool) vmprovider.Instance {
	return vmprovider.Instance{Provider: provider, Name: name, VMType: "vz", Running: running, MACAddress: "52:55:55:a5:de:d2"}
}

func qemu(provider, name string) vmprovider.Instance {
	return vmprovider.Instance{Provider: provider, Name: name, VMType: "qemu", Running: true}
}

func wantStatus(t *testing.T, f Finding, want Status) {
	t.Helper()
	if f.Status != want {
		t.Fatalf("%s: status = %q, want %q\n  title: %s\n  evidence: %v", f.ID, f.Status, want, f.Title, f.Evidence)
	}
}

func wantContains(t *testing.T, f Finding, want string) {
	t.Helper()
	hay := f.Title + "\n" + strings.Join(f.Evidence, "\n") + "\n" + f.Remedy
	if !strings.Contains(hay, want) {
		t.Fatalf("%s: nothing mentions %q:\n%s", f.ID, want, hay)
	}
}

func wantNotContains(t *testing.T, f Finding, unwanted string) {
	t.Helper()
	hay := f.Title + "\n" + strings.Join(f.Evidence, "\n") + "\n" + f.Remedy
	if strings.Contains(hay, unwanted) {
		t.Fatalf("%s: mentions %q and must not:\n%s", f.ID, unwanted, hay)
	}
}

// --- 1. providers ----------------------------------------------------------

func TestCheckProviders(t *testing.T) {
	tests := []struct {
		name string
		in   ProvidersInput
		want Status
		says string
	}{
		{"none installed", ProvidersInput{}, StatusFail, "colima start --vm-type vz"},
		{"installed, nothing running", ProvidersInput{
			Providers: []string{"lima"},
			Instances: []vmprovider.Instance{vz("lima", "drawbridge", false)},
		}, StatusWarn, "limactl start drawbridge"},
		{"running vz", ProvidersInput{
			Providers: []string{"colima"},
			Instances: []vmprovider.Instance{vz("colima", "colima", true)},
		}, StatusOK, "52:55:55:a5:de:d2"},
		{"qemu instance gets the vz switch line", ProvidersInput{
			Providers: []string{"colima"},
			Instances: []vmprovider.Instance{qemu("colima", "colima")},
		}, StatusWarn, "colima start --vm-type vz"},
		{"lima qemu instance", ProvidersInput{
			Providers: []string{"lima"},
			Instances: []vmprovider.Instance{qemu("lima", "old")},
		}, StatusWarn, "limactl edit old"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := CheckProviders(tc.in)
			wantStatus(t, f, tc.want)
			wantContains(t, f, tc.says)
		})
	}
}

// Under euid 0 the instance list is empty because limactl refuses root, not
// because nothing is running — "installed, nothing running" would misread a
// Mac whose VM is up, and the start-a-VM remedy would be wrong.
func TestCheckProvidersRootScoped(t *testing.T) {
	f := CheckProviders(ProvidersInput{
		Providers:  []string{"lima", "colima"},
		ListErrors: []string{"lima: vmprovider: limactl is user-scoped and refuses euid 0"},
		RootScoped: true,
	})
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "root half of the discriminator")
	wantNotContains(t, f, "start a VM")
}

func TestCheckProvidersReportsListErrors(t *testing.T) {
	f := CheckProviders(ProvidersInput{
		Providers:  []string{"lima", "colima"},
		Instances:  []vmprovider.Instance{vz("lima", "drawbridge", true)},
		ListErrors: []string{"colima: limactl list: exit status 1"},
	})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "limactl list: exit status 1")
}

// --- 2. guest-prereqs ------------------------------------------------------

func healthyGuest() GuestProbe {
	return GuestProbe{
		Ran: true, Kernel: "6.8.0-51-generic",
		BTF: true, CGroup2: true, Systemd: true, Sudo: true,
		AgentActive: "active", AgentVersion: "dev",
		GuestIPs:  []string{"192.168.64.2", "192.168.5.15"},
		Listeners: []Listener{{Addr: "192.168.64.2", Port: ControlPort}, {Addr: "127.0.0.1", Port: ControlPort}},
	}
}

func TestCheckGuestPrereqs(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*GuestProbe)
		skip string
		want Status
		says string
	}{
		{"healthy", nil, "", StatusOK, "cgroup v2"},
		{"skipped", nil, "several VMs are running — pass -vm provider:name", StatusSkip, "pass -vm"},
		{"no systemd", func(g *GuestProbe) { g.Systemd = false }, "", StatusFail, "OpenRC"},
		{"no btf", func(g *GuestProbe) { g.BTF = false }, "", StatusFail, "CONFIG_DEBUG_INFO_BTF"},
		{"no cgroup2", func(g *GuestProbe) { g.CGroup2 = false }, "", StatusFail, "unified hierarchy"},
		{"no sudo", func(g *GuestProbe) { g.Sudo = false }, "", StatusFail, "sudoers.d"},
		{"old kernel", func(g *GuestProbe) { g.Kernel = "4.19.0" }, "", StatusWarn, "kernel >= 5.7"},
		{"unparsable kernel", func(g *GuestProbe) { g.Kernel = "linux" }, "", StatusWarn, "kernel >= 5.7"},
		{"oci with old runc", func(g *GuestProbe) {
			g.OCI, g.Runc = true, "runc version 1.0.3"
		}, "", StatusWarn, "runc >= 1.1.0"},
		{"oci with current runc", func(g *GuestProbe) {
			g.OCI, g.Runc = true, "runc version 1.1.12"
		}, "", StatusOK, "runc version 1.1.12"},
		{"oci with crun only", func(g *GuestProbe) {
			g.OCI, g.Crun = true, "crun version 1.14"
		}, "", StatusOK, "crun version 1.14"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := healthyGuest()
			if tc.mut != nil {
				tc.mut(&g)
			}
			f := CheckGuestPrereqs(g, tc.skip)
			wantStatus(t, f, tc.want)
			wantContains(t, f, tc.says)
		})
	}
}

// A guest that never answered is a skip, not a diagnosis: doctor must not
// report "no BTF" for a VM it could not reach.
func TestCheckGuestPrereqsUnreachable(t *testing.T) {
	f := CheckGuestPrereqs(GuestProbe{Err: "the guest shell failed: no answer within 10s"}, "")
	wantStatus(t, f, StatusSkip)
	wantContains(t, f, "no answer within 10s")
	wantNotContains(t, f, "CONFIG_DEBUG_INFO_BTF")
}

func TestParseKernel(t *testing.T) {
	tests := []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"6.8.0-51-generic", 6, 8, true},
		{"5.15.0", 5, 15, true},
		{"6.1", 6, 1, true},
		{"5.7.0", 5, 7, true},
		{"linux", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range tests {
		maj, min, ok := parseKernel(tc.in)
		if maj != tc.maj || min != tc.min || ok != tc.ok {
			t.Errorf("parseKernel(%q) = %d,%d,%v want %d,%d,%v", tc.in, maj, min, ok, tc.maj, tc.min, tc.ok)
		}
	}
}

// The compare is numeric, not lexical: "5.10" must not read as older than
// "5.7" the way a string compare would have it.
func TestKernelCompareIsNumeric(t *testing.T) {
	g := healthyGuest()
	g.Kernel = "5.10.0-generic"
	wantStatus(t, CheckGuestPrereqs(g, ""), StatusOK)
}

func TestParseRuncVersion(t *testing.T) {
	tests := []struct {
		in   string
		want [3]int
		ok   bool
	}{
		{"runc version 1.1.12", [3]int{1, 1, 12}, true},
		{"runc version 1.0.3", [3]int{1, 0, 3}, true},
		{"crun version 1.14", [3]int{1, 14, 0}, true},
		{"runc version v1.2.0-rc.1", [3]int{1, 2, 0}, true},
		{"", [3]int{}, false},
	}
	for _, tc := range tests {
		got, ok := parseRuncVersion(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseRuncVersion(%q) = %v,%v want %v,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// --- 3. agent --------------------------------------------------------------

const ssFixture = `LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*
LISTEN 0      4096       127.0.0.1:4777       0.0.0.0:*
LISTEN 0      128             [::]:22            [::]:*
LISTEN 0      4096    192.168.64.2:4777       0.0.0.0:*
ESTAB  0      0        192.168.64.2:4777   192.168.64.1:52341`

func TestParseSSAndBind(t *testing.T) {
	g := ParseGuestProbe("ss-begin\n" + ssFixture + "\nss-end\n")
	if len(g.Listeners) != 4 {
		t.Fatalf("listeners = %v, want 4 (ESTAB rows are not listeners)", g.Listeners)
	}
	b := BindOf(g.Listeners, []string{"192.168.64.2"})
	if !b.Loopback || !b.VZNAT || b.Wildcard {
		t.Fatalf("bind = %+v, want loopback+vznat and no wildcard", b)
	}
	if !b.Reachable() {
		t.Fatal("a vzNAT-bound agent must read as reachable")
	}
}

func TestBindLoopbackOnly(t *testing.T) {
	b := BindOf([]Listener{{Addr: "127.0.0.1", Port: ControlPort}}, []string{"192.168.64.2"})
	if !b.Loopback || b.VZNAT || b.Reachable() {
		t.Fatalf("bind = %+v, want loopback only and not reachable", b)
	}
}

func TestBindWildcard(t *testing.T) {
	b := BindOf([]Listener{{Addr: "0.0.0.0", Port: ControlPort}}, nil)
	if !b.Wildcard || !b.Reachable() {
		t.Fatalf("bind = %+v, want wildcard and reachable", b)
	}
}

func TestCheckAgent(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*GuestProbe)
		want Status
		says string
	}{
		{"healthy", nil, StatusOK, "listening on :4777"},
		{"unit inactive", func(g *GuestProbe) { g.AgentActive = "inactive" }, StatusFail, "drawbridge up <vm>"},
		{"version skew", func(g *GuestProbe) { g.AgentVersion = "v0.0.9" }, StatusFail, "re-pushes the embedded agent"},
		{"active but nothing bound", func(g *GuestProbe) { g.Listeners = nil }, StatusFail, "nothing on :4777"},
		{"loopback only", func(g *GuestProbe) {
			g.Listeners = []Listener{{Addr: "127.0.0.1", Port: ControlPort}}
		}, StatusWarn, "vznat-direct resolution is impossible"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := healthyGuest()
			if tc.mut != nil {
				tc.mut(&g)
			}
			f := CheckAgent(g, BindOf(g.Listeners, g.GuestIPs), "dev", "")
			wantStatus(t, f, tc.want)
			wantContains(t, f, tc.says)
		})
	}
}

// The transient unit from `just agent-up` shares the persistent unit's name
// by design; doctor says which one is holding it.
func TestCheckAgentNamesTheTransientUnit(t *testing.T) {
	g := healthyGuest()
	g.AgentTransient = true
	f := CheckAgent(g, BindOf(g.Listeners, g.GuestIPs), "dev", "")
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "just agent-up")
}

// --- 4. resolution ---------------------------------------------------------

func TestCheckResolutionDirect(t *testing.T) {
	f := CheckResolution(ResolutionInput{Ran: true, Res: limaaddr.Resolution{
		Endpoint: "tcp://192.168.64.2:4777", Source: limaaddr.SourceVZNATDirect,
	}})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "tcp://192.168.64.2:4777")
}

// vznat-leases is the direct path with a lease-sourced address — the root
// daemon's only candidate source — not a fallback: the "slower and shared"
// forwarder remedy must never attach to it.
func TestCheckResolutionLeasesIsDirect(t *testing.T) {
	f := CheckResolution(ResolutionInput{Ran: true, Res: limaaddr.Resolution{
		Endpoint: "tcp://192.168.64.2:4777", Source: limaaddr.SourceVZNATLeases,
	}})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "-vm-mac")
	wantNotContains(t, f, "slower and shared")
}

// The Note is printed verbatim — doctor does not paraphrase the resolver.
func TestCheckResolutionPrintsNoteVerbatim(t *testing.T) {
	f := CheckResolution(ResolutionInput{Ran: true, Res: limaaddr.Resolution{
		Endpoint: "tcp://127.0.0.1:4777",
		Source:   limaaddr.SourceSSHForwarder,
		Note:     limaaddr.NoteLocalNetworkDenied,
	}})
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, limaaddr.NoteLocalNetworkDenied)
}

// The errno misclassification, named: an agent proven listening in-guest
// refutes NoteAgentNotListening.
func TestCheckResolutionRefutesAgentNotListening(t *testing.T) {
	f := CheckResolution(ResolutionInput{
		Ran:            true,
		AgentListening: true,
		Res: limaaddr.Resolution{
			Endpoint: "tcp://127.0.0.1:4777",
			Source:   limaaddr.SourceSSHForwarder,
			Note:     limaaddr.NoteAgentNotListening,
		},
	})
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "the guest side is listening")
	wantContains(t, f, "check 6 discriminates")
}

func TestCheckResolutionNoCrossReferenceWithoutEvidence(t *testing.T) {
	f := CheckResolution(ResolutionInput{
		Ran: true,
		Res: limaaddr.Resolution{
			Endpoint: "tcp://127.0.0.1:4777",
			Source:   limaaddr.SourceSSHForwarder,
			Note:     limaaddr.NoteAgentNotListening,
		},
	})
	wantNotContains(t, f, "the guest side is listening")
}

// The Phase 3 wrong-VM hazard: the forwarded loopback port is not
// attributable, so more than one running VM is worth naming.
func TestCheckResolutionNamesWrongVMHazard(t *testing.T) {
	f := CheckResolution(ResolutionInput{
		Ran:        true,
		RunningVMs: 2,
		Res:        limaaddr.Resolution{Endpoint: "tcp://127.0.0.1:4777", Source: limaaddr.SourceSSHForwarder},
	})
	wantContains(t, f, "different VM's agent")
}

func TestCheckResolutionSkips(t *testing.T) {
	wantStatus(t, CheckResolution(ResolutionInput{Skip: "no running vz VM"}), StatusSkip)
}

// --- 5. vznat-route --------------------------------------------------------

const netstatFixture = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
192.168.64         link#20            UC                bridge100
192.168.64.2       52:55:55:a5:de:d2  UHLWIi            bridge100   1198
`

const netstatNoRouteFixture = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
`

// Both verbatim from macOS: a miss exits non-zero and prints on stdout, so
// the classifier reads output rather than an exit status.
const arpHit = "? (192.168.64.2) at 52:55:55:a5:de:d2 on bridge100 ifscope [bridge]\n"
const arpMiss = "192.168.64.2 (192.168.64.2) -- no entry\n"

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestRoutePresent(t *testing.T) {
	tests := []struct {
		name    string
		netstat string
		subnet  string
		want    bool
	}{
		{"macOS abbreviates a /24", netstatFixture, "192.168.64.0/24", true},
		{"deleted", netstatNoRouteFixture, "192.168.64.0/24", false},
		{"a /32 host route is not the subnet route", "192.168.64.2 x U x\n", "192.168.64.0/24", false},
		{"an explicit CIDR destination", "192.168.64.0/24 link#20 UC bridge100\n", "192.168.64.0/24", true},
		{"a wider route covers it", "192.168 link#20 UC bridge100\n", "192.168.64.0/24", true},
		{"default never counts", "default 192.168.1.1 UGScg en0\n", "192.168.64.0/24", false},
		{"a non-default subnet", "10.0.5 link#20 UC bridge100\n", "10.0.5.0/24", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RoutePresent(tc.netstat, mustPrefix(tc.subnet)); got != tc.want {
				t.Fatalf("RoutePresent = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestARPPresent(t *testing.T) {
	if !ARPPresent(arpHit) {
		t.Error("a resolved entry must read as present")
	}
	for _, out := range []string{arpMiss, "", "? (192.168.64.2) at (incomplete) on bridge100\n"} {
		if ARPPresent(out) {
			t.Errorf("ARPPresent(%q) = true", out)
		}
	}
}

func TestCheckVZNATRoute(t *testing.T) {
	base := RouteInput{Subnet: mustPrefix("192.168.64.0/24"), CandidateIP: "192.168.64.2", GuestUp: true}

	t.Run("healthy", func(t *testing.T) {
		in := base
		in.NetstatOut, in.ARPOut = netstatFixture, arpHit
		wantStatus(t, CheckVZNATRoute(in), StatusOK)
	})

	t.Run("route deleted", func(t *testing.T) {
		in := base
		in.NetstatOut, in.ARPOut = netstatNoRouteFixture, arpMiss
		f := CheckVZNATRoute(in)
		wantStatus(t, f, StatusFail)
		if f.Remedy != "sudo route -n add -net 192.168.64.0/24 192.168.64.1" {
			t.Fatalf("remedy = %q", f.Remedy)
		}
		wantContains(t, f, "Tailscale")
	})

	// The remedy substitutes a non-default -vm-subnet rather than printing
	// the address that happens to be in the design note.
	t.Run("route deleted on a non-default subnet", func(t *testing.T) {
		in := base
		in.Subnet = mustPrefix("10.11.12.0/24")
		in.CandidateIP = "10.11.12.5"
		in.NetstatOut = netstatNoRouteFixture
		f := CheckVZNATRoute(in)
		if f.Remedy != "sudo route -n add -net 10.11.12.0/24 10.11.12.1" {
			t.Fatalf("remedy = %q", f.Remedy)
		}
	})

	t.Run("route present, no arp", func(t *testing.T) {
		in := base
		in.NetstatOut, in.ARPOut = netstatFixture, arpMiss
		f := CheckVZNATRoute(in)
		wantStatus(t, f, StatusWarn)
		wantContains(t, f, "first traffic populates")
	})

	// A cache line that aged out while the host demonstrably reaches the
	// guest is not a finding — §4's "only meaningful with probes also
	// failing", enforced.
	t.Run("no arp but the probe succeeded", func(t *testing.T) {
		in := base
		in.NetstatOut, in.ARPOut, in.ProbeOK = netstatFixture, arpMiss, true
		f := CheckVZNATRoute(in)
		wantStatus(t, f, StatusOK)
		wantContains(t, f, "aged out")
	})

	t.Run("netstat unavailable", func(t *testing.T) {
		in := base
		in.NetstatErr = "netstat: exec: not found"
		wantStatus(t, CheckVZNATRoute(in), StatusSkip)
	})
}

// --- 6. local-network — the discriminator table ----------------------------

func TestCheckLocalNetworkDiscriminatorTable(t *testing.T) {
	tests := []struct {
		name     string
		in       LocalNetworkInput
		want     Status
		says     string
		mustNot  string
		wantsLS  bool
		remedyLN bool
	}{
		{
			name: "row 1 — user probe ok",
			in:   LocalNetworkInput{UserProbe: ProbeOK, ProbeAddr: "192.168.64.2:4777"},
			want: StatusOK, says: "not blocking this binary",
		},
		{
			name: "row 2 — user fail, tier-1 root ok",
			in: LocalNetworkInput{UserProbe: ProbeFail, ProbeAddr: "192.168.64.2:4777",
				Root: RootEvidence{Kind: "tier1", Probe: ProbeOK}},
			want: StatusFail, says: "GATE CONFIRMED", wantsLS: true, remedyLN: true,
		},
		{
			name: "row 3 — user fail, tier-2 daemon vantage, NE filter present",
			in: LocalNetworkInput{UserProbe: ProbeFail, ProbeAddr: "192.168.64.2:4777",
				Root:            RootEvidence{Kind: "tier2", Probe: ProbeOK, Note: "the root daemon resolved vznat-direct"},
				NEFilterPresent: true},
			want: StatusFail, says: "does not exonerate the filter for this CLI", wantsLS: true, remedyLN: true,
		},
		{
			name: "row 3 without an NE filter drops the per-binary caveat",
			in: LocalNetworkInput{UserProbe: ProbeFail,
				Root: RootEvidence{Kind: "tier2", Probe: ProbeOK}},
			want: StatusFail, says: "gate indicated", mustNot: "does not exonerate", wantsLS: true, remedyLN: true,
		},
		{
			name: "row 4 — both fail",
			in: LocalNetworkInput{UserProbe: ProbeFail,
				Root: RootEvidence{Kind: "tier1", Probe: ProbeFail}, NEFilterPresent: true},
			want: StatusFail, says: "not the gate alone", mustNot: "AllowedEthernetLocalNetworkAddresses", wantsLS: true,
		},
		{
			name: "row 5 — no root evidence",
			in:   LocalNetworkInput{UserProbe: ProbeFail, Root: RootEvidence{Kind: "unknown"}},
			want: StatusWarn, says: discriminatorInstruction, wantsLS: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := CheckLocalNetwork(tc.in)
			wantStatus(t, f, tc.want)
			wantContains(t, f, tc.says)
			if tc.mustNot != "" {
				wantNotContains(t, f, tc.mustNot)
			}
			if tc.wantsLS {
				wantContains(t, f, "absence from Little Snitch's Network Monitor is not exoneration")
			}
			if tc.remedyLN {
				for _, want := range []string{"sudo drawbridge install", "Apple Terminal", "AllowedEthernetLocalNetworkAddresses", "AllowedWiFiLocalNetworkAddresses"} {
					wantContains(t, f, want)
				}
			}
		})
	}
}

// The never-rule, structurally: no combination of a user-only probe and an
// absent root branch may produce the "gate confirmed" verdict.
func TestUserOnlyProbeNeverConcludesLocalNetworkGate(t *testing.T) {
	for _, ne := range []bool{false, true} {
		for _, listening := range []bool{false, true} {
			f := CheckLocalNetwork(LocalNetworkInput{
				UserProbe: ProbeFail, NEFilterPresent: ne, AgentListening: listening,
				Root: RootEvidence{Kind: "unknown"},
			})
			wantStatus(t, f, StatusWarn)
			wantNotContains(t, f, "GATE CONFIRMED")
			wantNotContains(t, f, "gate indicated")
		}
	}
}

func TestCheckLocalNetworkSubstitutesSubnetInRemedies(t *testing.T) {
	f := CheckLocalNetwork(LocalNetworkInput{
		UserProbe: ProbeFail, Subnet: mustPrefix("10.11.12.0/24"),
		Root: RootEvidence{Kind: "tier1", Probe: ProbeOK},
	})
	wantContains(t, f, `-array "10.11.12.0/24"`)
	wantNotContains(t, f, "192.168.64.0/24")
}

func TestCheckLocalNetworkRootBranch(t *testing.T) {
	t.Run("root reaches the guest", func(t *testing.T) {
		f := CheckLocalNetwork(LocalNetworkInput{EUID0: true, UserProbe: ProbeOK, ProbeAddr: "192.168.64.2:4777"})
		wantStatus(t, f, StatusOK)
		wantContains(t, f, "root-probe")
		wantContains(t, f, "the unprivileged branch is not visible from here")
	})
	t.Run("root fails too", func(t *testing.T) {
		f := CheckLocalNetwork(LocalNetworkInput{EUID0: true, UserProbe: ProbeFail, ProbeAddr: "192.168.64.2:4777"})
		wantStatus(t, f, StatusFail)
		wantContains(t, f, "root is exempt")
		wantContains(t, f, "absence from Little Snitch's Network Monitor is not exoneration")
		wantNotContains(t, f, "AllowedEthernetLocalNetworkAddresses")
	})
}

func TestCheckLocalNetworkSkips(t *testing.T) {
	wantStatus(t, CheckLocalNetwork(LocalNetworkInput{UserProbe: ProbeSkipped}), StatusSkip)
	wantStatus(t, CheckLocalNetwork(LocalNetworkInput{Skip: "no running vz VM"}), StatusSkip)
}

// --- 7. ne-filter ----------------------------------------------------------

// Verbatim shape from a live `systemextensionsctl list`, tabs included. The
// version column is `(6.5 nightly (7300)/7300)` — spaces and nested
// parentheses — which is exactly what a whitespace split gets wrong.
const sysextFixture = "3 extension(s)\n" +
	"--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"\t\tW5364U7YZB\tio.tailscale.ipn.macsys.network-extension (1.98.9/101.98.9)\tTailscale Network Extension\t[terminated waiting to uninstall on reboot]\n" +
	"*\t*\tMLZF7K7B5R\tat.obdev.littlesnitch.networkextension (6.5 nightly (7300)/7300)\tLittle Snitch Network Extension\t[activated enabled]\n" +
	"--- com.apple.system_extension.driver_extension\n" +
	"enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n" +
	"*\t*\tABCDE12345\tcom.example.driver (1.0)\tExample Driver\t[activated enabled]\n"

const sysextEmpty = "0 extension(s)\n"

func TestParseSystemExtensions(t *testing.T) {
	exts := ParseSystemExtensions(sysextFixture)
	if len(exts) != 1 {
		t.Fatalf("extensions = %+v, want only the activated network extension", exts)
	}
	e := exts[0]
	if e.BundleID != "at.obdev.littlesnitch.networkextension" {
		t.Errorf("bundleID = %q", e.BundleID)
	}
	if e.TeamID != "MLZF7K7B5R" {
		t.Errorf("teamID = %q", e.TeamID)
	}
	if e.Name != "Little Snitch Network Extension" {
		t.Errorf("name = %q", e.Name)
	}
	if len(ParseSystemExtensions(sysextEmpty)) != 0 {
		t.Error("an empty list produced extensions")
	}
}

func TestCheckNEFilter(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		wantStatus(t, CheckNEFilter(nil, ""), StatusOK)
	})
	t.Run("present", func(t *testing.T) {
		f := CheckNEFilter(ParseSystemExtensions(sysextFixture), "")
		wantStatus(t, f, StatusWarn)
		for _, want := range []string{
			"at.obdev.littlesnitch.networkextension",
			"half-close",
			"per-binary",
			`all three persisted with the filter "disabled"`,
			"benchmark numbers",
			"Network Extensions",
		} {
			wantContains(t, f, want)
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		wantStatus(t, CheckNEFilter(nil, "systemextensionsctl: not found"), StatusSkip)
	})
}

// --- 8. half-close ---------------------------------------------------------
//
// Check 8 lives in probe.go with the client it classifies; its tests are in
// probe_test.go.

// --- 9. daemon -------------------------------------------------------------

func TestCheckDaemon(t *testing.T) {
	running := install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 4242}

	tests := []struct {
		name string
		in   DaemonInput
		want Status
		says string
	}{
		{"running and matched", DaemonInput{Status: running, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0"}, StatusOK, "pid 4242"},
		{"version skew", DaemonInput{Status: running, InstalledVersion: "v0.0.9", CLIVersion: "v0.1.0"}, StatusFail, "sudo drawbridge install"},
		{"not installed", DaemonInput{CLIVersion: "v0.1.0"}, StatusWarn, "drawbridged -vm <vm>"},
		{"installed, not loaded", DaemonInput{
			Status: install.Status{PlistInstalled: true, BinaryInstalled: true}, CLIVersion: "v0.1.0",
		}, StatusWarn, "re-bootstraps"},
		{"loaded, not running", DaemonInput{
			Status: install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "waiting"}, CLIVersion: "v0.1.0",
		}, StatusWarn, "state=waiting"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := CheckDaemon(tc.in)
			wantStatus(t, f, tc.want)
			wantContains(t, f, tc.says)
		})
	}
}

// Rows 7 and 9 of the transport-auth table have no check ID: presence in the
// tail is the alarm, and check 9 is where it surfaces.
func TestCheckDaemonSurfacesUnattributedRefusals(t *testing.T) {
	st := install.Status{
		PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 1,
		LogTail: []string{
			"drawbridged: macsync: refused reverse dial to 127.0.0.1:5432 (proto 6): not a port this Mac advertised",
			"drawbridged: macsync: dropping reverse-stream conn: nonzero reserved byte in activation header (incompatible agent?)",
			"drawbridged: mirror: mirroring guest tcp :8080",
		},
	}
	f := CheckDaemon(DaemonInput{Status: st, InstalledVersion: "dev", CLIVersion: "dev"})
	wantContains(t, f, "refused reverse dial")
	wantContains(t, f, "nonzero reserved byte")
	wantNotContains(t, f, "mirroring guest tcp :8080")
}

// --- 9. daemon, the snapshot tier ------------------------------------------

func snapshot(path string, mutate func(*introspect.State)) *introspect.Snapshot {
	st := introspect.State{
		Schema: introspect.Schema, Version: "v0.1.0", PID: 4242, EUID: 0,
		VM:         introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
		Resolution: introspect.Resolution{Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct"},
		Auth:       introspect.Auth{Mode: introspect.AuthModeStaticHMACv1, SecretState: introspect.SecretOK},
		Mirror: introspect.Mirror{SessionUp: true, Entries: []introspect.MirrorEntry{
			{Proto: "tcp", Port: 8080, State: introspect.EntryBound},
		}},
		Sync: introspect.Sync{SessionUp: true, PoolParked: 4,
			Advertised: []introspect.Advertised{{Proto: "tcp", Port: 5432}}},
	}
	if mutate != nil {
		mutate(&st)
	}
	return &introspect.Snapshot{Path: path, State: st, Usable: true}
}

// A live sync session advertising nothing is never natural — a Mac always
// has LISTEN sockets — so the state itself is evidence, ring or no ring
// (the 2026-08-01 incident: 27.0b4 filters pcblist per responsible app, so
// a terminal-launched daemon is empty from birth and never transitions).
func TestCheckDaemonSurfacesEmptyAdvertisedSet(t *testing.T) {
	st := install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 4242}
	user := snapshot("/Users/x/Library/Application Support/drawbridge/run/introspect-colima-colima.sock",
		func(s *introspect.State) { s.EUID = 501; s.Sync.Advertised = nil })
	f := CheckDaemon(DaemonInput{Status: st, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0",
		Snapshots: []*introspect.Snapshot{user}})
	wantContains(t, f, "advertises nothing")
	wantContains(t, f, "finding 5")
	wantContains(t, f, "sudo drawbridge install")

	// A root daemon is exempt from the filter, so the anomaly line stays but
	// the filter suspicion does not.
	root := snapshot(introspect.RootSocketPath, func(s *introspect.State) { s.Sync.Advertised = nil })
	f = CheckDaemon(DaemonInput{Status: st, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0",
		Snapshots: []*introspect.Snapshot{root}})
	wantContains(t, f, "advertises nothing")
	wantNotContains(t, f, "finding 5")

	// A healthy set draws no anomaly line.
	f = CheckDaemon(DaemonInput{Status: st, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0",
		Snapshots: []*introspect.Snapshot{snapshot(introspect.RootSocketPath, nil)}})
	wantNotContains(t, f, "advertises nothing")
}

// The daemon states its own endpoint, source and auth mode — the vantage
// launchctl and a log file could never reconstruct.
func TestCheckDaemonSnapshotSection(t *testing.T) {
	st := install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 4242}
	f := CheckDaemon(DaemonInput{
		Status: st, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0",
		Snapshots: []*introspect.Snapshot{snapshot(introspect.RootSocketPath, nil)},
	})
	wantStatus(t, f, StatusOK)
	for _, want := range []string{introspect.RootSocketPath, "tcp://192.168.64.5:4777", "source=vznat-direct", "static-hmac-v1", "mirror session up"} {
		wantContains(t, f, want)
	}
}

// The running daemon's own version is the authority on what is running: an
// installed binary can match the CLI while the process serving ports
// predates the upgrade.
func TestCheckDaemonSnapshotVersionSkew(t *testing.T) {
	st := install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 4242}
	f := CheckDaemon(DaemonInput{
		Status: st, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0",
		Snapshots: []*introspect.Snapshot{snapshot(introspect.RootSocketPath, func(s *introspect.State) { s.Version = "v0.0.9" })},
	})
	wantStatus(t, f, StatusFail)
	wantContains(t, f, "sudo drawbridge install")
	wantContains(t, f, "v0.0.9")
}

// §D3: root and user sockets both answering is the fighting-daemons posture,
// detectable for the first time — and the remedy has to name both.
func TestCheckDaemonFightingDaemons(t *testing.T) {
	st := install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 4242}
	user := snapshot("/Users/x/Library/Application Support/drawbridge/run/introspect-colima-colima.sock",
		func(s *introspect.State) { s.EUID, s.PID = 501, 777 })
	f := CheckDaemon(DaemonInput{
		Status: st, InstalledVersion: "v0.1.0", CLIVersion: "v0.1.0",
		Snapshots: []*introspect.Snapshot{snapshot(introspect.RootSocketPath, nil), user},
	})
	wantStatus(t, f, StatusWarn)
	wantContains(t, f, "pid 4242")
	wantContains(t, f, "pid 777")
	wantContains(t, f, "sudo drawbridge uninstall")
}

// A schema this build does not know is version-skew evidence and nothing
// more (D4); an unreadable payload is a warn line, never silence (§3.3).
func TestCheckDaemonSchemaSkewAndProblems(t *testing.T) {
	f := CheckDaemon(DaemonInput{
		CLIVersion: "v0.1.0",
		Snapshots:  []*introspect.Snapshot{{Path: "/tmp/s.sock", State: introspect.State{Schema: 2, Version: "v0.1.0"}}},
		SnapshotProblems: []string{
			"introspect: unreadable snapshot: /tmp/bad.sock: unexpected end of JSON input",
		},
	})
	wantContains(t, f, "speaks introspection schema 2")
	wantContains(t, f, "unreadable snapshot")
}

// A foreground daemon is a legitimate posture, so "not installed" stops
// being the headline when one is actually running.
func TestCheckDaemonForegroundOnly(t *testing.T) {
	f := CheckDaemon(DaemonInput{
		CLIVersion: "v0.1.0",
		Snapshots:  []*introspect.Snapshot{snapshot("/tmp/introspect-colima-colima.sock", func(s *introspect.State) { s.EUID, s.PID = 501, 777 })},
	})
	wantStatus(t, f, StatusOK)
	wantContains(t, f, "foreground drawbridged is running (pid 777)")
}

// --- 10. coexistence -------------------------------------------------------

func TestCheckCoexistence(t *testing.T) {
	active := vmprovider.Forwarding{
		Instance: "colima", HostAgent: true,
		Loopback: vmprovider.PortSet{{Lo: 1, Hi: 65535}},
		Wildcard: vmprovider.PortSet{{Lo: 1, Hi: 65535}},
	}
	t.Run("active", func(t *testing.T) {
		f := CheckCoexistence(CoexistenceInput{Known: true, Fwd: active})
		wantStatus(t, f, StatusWarn)
		for _, want := range []string{`guestIP: "0.0.0.0"`, "guestIPMustBeZero: false", "proto: any", "lima#4403"} {
			wantContains(t, f, want)
		}
		wantNotContains(t, f, "disable the forwarder")
	})
	t.Run("inactive", func(t *testing.T) {
		f := CheckCoexistence(CoexistenceInput{Known: true, Fwd: vmprovider.Forwarding{Instance: "drawbridge", HostAgent: true}})
		wantStatus(t, f, StatusOK)
	})
	// The dev template's deliberate baseline: only the agent control port is
	// forwarded. That is drawbridge's own transport fallback, not coexistence.
	t.Run("control-port-only", func(t *testing.T) {
		f := CheckCoexistence(CoexistenceInput{Known: true, Fwd: vmprovider.Forwarding{
			Instance: "drawbridge", HostAgent: true,
			Loopback: vmprovider.PortSet{{Lo: ControlPort, Hi: ControlPort}},
		}})
		wantStatus(t, f, StatusOK)
		wantContains(t, f, "loopback transport fallback")
	})
	t.Run("control-port-plus-others", func(t *testing.T) {
		f := CheckCoexistence(CoexistenceInput{Known: true, Fwd: vmprovider.Forwarding{
			Instance: "colima", HostAgent: true,
			Loopback: vmprovider.PortSet{{Lo: ControlPort, Hi: ControlPort}, {Lo: 8080, Hi: 8080}},
		}})
		wantStatus(t, f, StatusWarn)
	})
	t.Run("unknown", func(t *testing.T) {
		wantStatus(t, CheckCoexistence(CoexistenceInput{}), StatusSkip)
		wantStatus(t, CheckCoexistence(CoexistenceInput{Err: "limactl list: exit 1"}), StatusSkip)
		wantStatus(t, CheckCoexistence(CoexistenceInput{Skip: "no running vz VM"}), StatusSkip)
	})
}

// --- 11. skip-visibility ---------------------------------------------------

func TestCheckSkipVisibility(t *testing.T) {
	f := CheckSkipVisibility(SkipInput{LogTail: []string{
		"drawbridged: mirror: skipping guest tcp :22 (skip-list; -skip to override)",
		"drawbridged: mirror: mirroring guest tcp :8080",
	}})
	wantStatus(t, f, StatusInfo)
	wantContains(t, f, "skipping guest tcp :22")
	wantContains(t, f, `-skip ""`)
	wantNotContains(t, f, "mirroring guest tcp :8080")
}

// With a daemon answering, the check reports the daemon's own table instead
// of whatever the log happened to retain — the point of the snapshot tier.
func TestCheckSkipVisibilityExactFromSnapshot(t *testing.T) {
	f := CheckSkipVisibility(SkipInput{
		Known:   true,
		Daemon:  "/var/run/drawbridge/introspect.sock",
		Skip:    []uint16{22},
		Skipped: []introspect.MirrorEntry{{Proto: "tcp", Port: 22, State: introspect.EntrySkipped}},
	})
	wantStatus(t, f, StatusInfo)
	wantContains(t, f, "/var/run/drawbridge/introspect.sock")
	wantContains(t, f, "guest tcp/22 is listening and not mirrored")
}

// A daemon installed with -skip "" skips nothing, and that is exactly the
// state a confused user needs stated rather than implied.
func TestCheckSkipVisibilityEmptySkipList(t *testing.T) {
	f := CheckSkipVisibility(SkipInput{Known: true, Daemon: "/tmp/s.sock"})
	wantContains(t, f, `skips nothing (-skip "")`)
}

// It is never a health verdict: an info finding must not colour the run.
func TestSkipVisibilityNeverFails(t *testing.T) {
	r := Report{Findings: []Finding{CheckSkipVisibility(SkipInput{})}}
	if r.ExitCode() != 0 {
		t.Fatal("the skip-visibility check changed the exit code")
	}
}
