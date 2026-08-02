package limaaddr

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(b)
}

// TestLeaseCandidates pins the selection rules the root path depends on:
// exact `lima-<vm>` match (a prefix match would silently hand this VM's
// resolver a sibling VM's address — the probe cannot tell them apart, both
// answer :4777 with the same protocol), Lima's outbound-only usernet subnet
// and non-private addresses excluded, and newest lease first so a recreated
// VM's fresh record is probed before the stale one it left behind.
func TestLeaseCandidates(t *testing.T) {
	multi := readFixture(t, "multi-vm.leases")
	stale := readFixture(t, "stale.leases")
	malformed := readFixture(t, "malformed.leases")
	empty := readFixture(t, "empty.leases")

	for _, tc := range []struct {
		name string
		text string
		vm   string
		want []string
	}{
		{"multi-vm picks only the exact name", multi, "drawbridge", []string{"192.168.64.2"}},
		{"sibling VM is its own name, not a prefix hit", multi, "drawbridge-test", []string{"192.168.64.9"}},
		{"other VM", multi, "default", []string{"192.168.64.7"}},
		{"unknown VM has no candidates", multi, "nope", nil},
		{"stale lease sorts after the fresh one", stale, "drawbridge", []string{"192.168.64.8", "192.168.64.2"}},
		{"malformed records are skipped, not fatal", malformed, "drawbridge", []string{"192.168.64.31"}},
		{"empty file", empty, "drawbridge", nil},
		{"junk is not a lease db", "not a lease file at all\n", "drawbridge", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := leaseCandidatesFrom(tc.text, Target{VM: tc.vm})
			if len(got) != len(tc.want) {
				t.Fatalf("leaseCandidatesFrom(%s) = %v, want %v", tc.vm, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("leaseCandidatesFrom(%s) = %v, want %v", tc.vm, got, tc.want)
				}
			}
		})
	}
}

// A lease db full of stale records must not turn resolution into a
// multi-second stall: every candidate costs up to probeTimeout, on every
// resolver pass.
func TestLeaseCandidatesAreBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&b, "{\n\tname=lima-drawbridge\n\tip_address=192.168.64.%d\n\tlease=0x%x\n}\n", 20+i, 0x6a6c4000+i)
	}
	got, _ := leaseCandidatesFrom(b.String(), Target{VM: "drawbridge"})
	if len(got) != maxLeaseCandidates {
		t.Fatalf("got %d candidates (%v), want the %d cap", len(got), got, maxLeaseCandidates)
	}
	// Newest first: the last-written record has the highest expiry.
	if got[0] != "192.168.64.31" {
		t.Fatalf("candidates not newest-first: %v", got)
	}
}

// Duplicate records for one address (renewals) must not multiply probes.
func TestLeaseCandidatesDedup(t *testing.T) {
	text := "{\n\tname=lima-drawbridge\n\tip_address=192.168.64.2\n\tlease=0x1\n}\n" +
		"{\n\tname=lima-drawbridge\n\tip_address=192.168.64.2\n\tlease=0x2\n}\n"
	if got, _ := leaseCandidatesFrom(text, Target{VM: "drawbridge"}); len(got) != 1 || got[0] != "192.168.64.2" {
		t.Fatalf("leaseCandidatesFrom = %v, want one 192.168.64.2", got)
	}
}

func TestParseLeaseTime(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"0x6a6c420d", 0x6a6c420d},
		{"0X6A6C420D", 0x6a6c420d},
		{"12345", 12345},
		{"", 0},
		{"not-a-number", 0},
		{"-5", 0},
	} {
		if got := parseLeaseTime(tc.in); got != tc.want {
			t.Fatalf("parseLeaseTime(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// A missing lease db is a degradation, not a crash: the resolver still has
// the forwarder, and the caller must be able to say so in words.
func TestLeaseCandidatesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-file")
	got, _, err := leaseCandidates(path, Target{VM: "drawbridge"})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want os.ErrNotExist", err)
	}
	if got != nil {
		t.Fatalf("candidates = %v, want none", got)
	}
	note := classifyNoLeases(path, err)
	for _, want := range []string{path, "SSH forwarder"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q missing %q", note, want)
		}
	}
}

// The root path, proven without root. A root LaunchDaemon cannot run
// limactl — its state lives in the invoking user's $LIMA_HOME — so the lease
// db is the only source it has. Making limactl unfindable reproduces exactly
// that condition, and the resolution that comes back must be a real,
// reachable vzNAT endpoint tagged vznat-leases.
//
// Live: needs the VM up and `just agent-up` current, hence the same gate the
// e2e suite uses.
func TestResolveViaLeasesLive(t *testing.T) {
	if os.Getenv("DRAWBRIDGE_E2E") == "" {
		t.Skip("live test: set DRAWBRIDGE_E2E=1 with the VM up and the agent running")
	}
	vm := os.Getenv("DRAWBRIDGE_VM")
	if vm == "" {
		vm = "drawbridge"
	}
	// DRAWBRIDGE_VM takes drawbridged's `provider:name` grammar elsewhere
	// (internal/e2e, for the Colima recipe). This package deliberately does
	// not import vmprovider — the root path must not depend on limactl
	// tooling, and the lease name is per-provider knowledge that lives there
	// — so a provider ref is skipped rather than mis-parsed into a lease name
	// like "lima-colima:colima" that matches nothing.
	if strings.Contains(vm, ":") {
		t.Skipf("DRAWBRIDGE_VM=%q is a provider ref; this live test takes a bare Lima instance name", vm)
	}
	t.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin") // no limactl here
	r := Resolve(vm, 4777)
	t.Logf("root-path resolution: endpoint=%s source=%s note=%q", r.Endpoint, r.Source, r.Note)
	if r.Source != SourceVZNATLeases {
		t.Fatalf("source = %q, want %q (the lease db is the only source a root daemon has)", r.Source, SourceVZNATLeases)
	}
	if strings.HasPrefix(r.Endpoint, "tcp://127.0.0.1") {
		t.Fatalf("endpoint %q is the forwarder, not a vzNAT address", r.Endpoint)
	}
}

// The format claim is load-bearing for the root daemon, so assert it against
// the real OS file when one exists. Skips (rather than fails) on a machine
// with no vz VMs — but on a dev machine with the drawbridge VM up, this is
// the test that catches Apple changing the format.
func TestParseRealLeasesFile(t *testing.T) {
	b, err := os.ReadFile(LeasesPath)
	if err != nil {
		t.Skipf("no %s on this machine: %v", LeasesPath, err)
	}
	leases := parseLeases(string(b))
	if len(leases) == 0 {
		t.Skipf("%s has no parseable records (no vz VMs have leased?)", LeasesPath)
	}
	for _, l := range leases {
		t.Logf("lease name=%s ip=%s hw=%s expiry=0x%x", l.Name, l.IP, l.HWAddr, l.Expiry)
		if l.Name == "" || l.IP == "" {
			t.Fatalf("parsed record with empty name/ip: %+v", l)
		}
	}
	// Whatever the parse found, the candidate filter must only ever emit
	// addresses the resolver would be willing to dial.
	cands, notes := leaseCandidatesFrom(string(b), Target{VM: "drawbridge"})
	for _, n := range notes {
		t.Logf("note: %s", n)
	}
	for _, ip := range cands {
		t.Logf("candidate for vm=drawbridge: %s", ip)
		if !usableGuestIPv4(ip) {
			t.Fatalf("candidate %q is not a usable guest IPv4", ip)
		}
		if addr, err := netip.ParseAddr(ip); err != nil || !defaultSubnet.Contains(addr) {
			t.Fatalf("candidate %q escaped the vmnet subnet gate", ip)
		}
	}
}
