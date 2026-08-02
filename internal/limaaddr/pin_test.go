package limaaddr

import (
	"net/netip"
	"strings"
	"testing"
)

// The genuine VM's address, as `limactl list --format json` reports it, and
// as /var/db/dhcpd_leases spells the same thing (ARP hardware-type prefix,
// leading zero dropped from the first octet).
const genuineMAC = "52:55:55:a5:de:d2"

// squat.leases' genuine record uses zero-leading octets, so the two
// spellings actually differ: /var/db/dhcpd_leases writes an ARP
// hardware-type prefix and drops the leading zeros, while the user pastes
// back what limactl printed. Both have to reach the same comparison.
const (
	squatMAC      = "52:55:55:0A:DE:02" // as pasted into -vm-mac
	squatMACLease = "1,52:55:55:a:de:2" // as written in the lease db
	squatMACCanon = "52:55:55:0a:de:02"
)

// TestNormalizeHWAddr pins the two spellings that must land on one string.
// If they ever diverge, a MAC pin matches nothing and the daemon falls back
// to the forwarder forever — a security control whose failure mode is "the
// product stops working" gets turned off, so this is the load-bearing test
// of the pin.
func TestNormalizeHWAddr(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string // "" means the input must be rejected
	}{
		{genuineMAC, genuineMAC},
		{"1,52:55:55:a5:de:d2", genuineMAC},
		{"52:55:55:A5:DE:D2", genuineMAC},
		{"1,52:55:55:A5:DE:D2", genuineMAC},

		// The zero-padding half: the lease db drops leading zeros, the user
		// pastes them, and both must canonicalise to the same string.
		{squatMAC, squatMACCanon},
		{squatMACLease, squatMACCanon},
		{"  1,52:55:55:A:DE:2  ", squatMACCanon},
		{"52:55:55:0a:de:02", squatMACCanon},

		{"0:0:0:0:0:0", "00:00:00:00:00:00"},
		{"00:00:00:00:00:00", "00:00:00:00:00:00"},
		{"1,ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"},

		// Rejected: everything that is not six hex octets.
		{"", ""},
		{"1,", ""},
		{"52:55:55:a5:de", ""},
		{"52:55:55:a5:de:d2:99", ""},
		{"52:55:55:a5:de:d222", ""},
		{"52:55:55:a5:de:g2", ""},
		{"52-55-55-a5-de-d2", ""},
		{"52:55:55:a5:de:", ""},
		{"x,52:55:55:a5:de:d2", ""},
		{"1,2,52:55:55:a5:de:d2", ""},
		{"52:55:55:a5:de:+2", ""},
		{"52:55:55:a5:de:0x2", ""},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := normalizeHWAddr(tc.in)
			if tc.want == "" {
				if ok {
					t.Fatalf("normalizeHWAddr(%q) = %q, want rejected", tc.in, got)
				}
				return
			}
			if !ok || got != tc.want {
				t.Fatalf("normalizeHWAddr(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
			}
		})
	}
}

// ParseHWAddr is the flag-time gate: it must canonicalise what it accepts
// (so the plist and the daemon compare the same bytes) and refuse the rest
// loudly (an unreadable pin must not become no pin).
func TestParseHWAddr(t *testing.T) {
	got, err := ParseHWAddr(squatMACLease)
	if err != nil || got != squatMACCanon {
		t.Fatalf("ParseHWAddr = %q, %v; want %q", got, err, squatMACCanon)
	}
	if _, err := ParseHWAddr("not-a-mac"); err == nil {
		t.Fatal("ParseHWAddr accepted a non-MAC")
	}
}

func TestParseSubnet(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"192.168.64.0/24", "192.168.64.0/24"},
		{"192.168.64.7/24", "192.168.64.0/24"}, // masked, so a host address still works
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"172.16.0.0/12", "172.16.0.0/12"},
	} {
		p, err := ParseSubnet(tc.in)
		if err != nil || p.String() != tc.want {
			t.Fatalf("ParseSubnet(%q) = %v, %v; want %s", tc.in, p, err, tc.want)
		}
	}
	// A public or v6 range is not a vmnet subnet, and accepting one only
	// widens what a lease record may claim.
	for _, bad := range []string{"", "192.168.64.0", "1.2.3.0/24", "fd00::/8", "192.168.64.0/33", "junk"} {
		if _, err := ParseSubnet(bad); err == nil {
			t.Fatalf("ParseSubnet(%q) accepted", bad)
		}
	}
}

// The vulnerability, and the fix, in one fixture. squat.leases is what a
// second vmnet VM on this Mac produces when its guest sets hostname
// `lima-drawbridge` and renews DHCP: same name, different hardware address,
// newer expiry. Newest-first ordering — correct for the recreated-VM case —
// is exactly what makes it win, and four of them push the genuine record
// past maxLeaseCandidates entirely.
func TestSquattedLeasesLoseToTheMACPin(t *testing.T) {
	text := readFixture(t, "squat.leases")

	// Unpinned: the squatters take every candidate slot and the genuine
	// record does not survive the cap at all. This is the bug, asserted so a
	// future change to the ordering or the cap cannot quietly restore it as
	// "fine".
	got, _ := leaseCandidatesFrom(text, Target{VM: "drawbridge"})
	want := []string{"192.168.64.80", "192.168.64.79", "192.168.64.78", "192.168.64.77"}
	assertIPs(t, got, want)

	// Pinned: only the record that actually belongs to the VM survives —
	// including across the leases-file spelling of its MAC (leading zero
	// dropped, ARP type prefix) versus the conventional one the pin is
	// written in.
	got, notes := leaseCandidatesFrom(text, Target{VM: "drawbridge", HWAddr: squatMAC})
	assertIPs(t, got, []string{"192.168.64.2"})

	// And the rejection is diagnosable: both reasons named, with a count, an
	// example, and what to do about each.
	joined := strings.Join(notes, " ")
	for _, want := range []string{
		"lima-drawbridge",
		squatMACCanon,       // the pin that did not match
		"ee:ee:ee:ee:ee:01", // an example of what did not match it
		"192.168.64.0/24",   // the subnet gate
		"10.211.55.9",       // the record it dropped
		"-vm-subnet",
		"-vm-mac",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("notes missing %q:\n%s", want, joined)
		}
	}
}

// A record that claims the name but carries no hw_address at all must lose
// to a pin too: "cannot be checked" is not "checks out".
func TestMACPinRejectsRecordWithoutHWAddr(t *testing.T) {
	text := "{\n\tname=lima-drawbridge\n\tip_address=192.168.64.90\n\tlease=0x7fffffff\n}\n"
	got, notes := leaseCandidatesFrom(text, Target{VM: "drawbridge", HWAddr: genuineMAC})
	assertIPs(t, got, nil)
	if !strings.Contains(strings.Join(notes, " "), "no hw_address") {
		t.Fatalf("notes do not name the missing hw_address:\n%v", notes)
	}
}

// An unreadable pin fails closed. Degrading to name-only matching would give
// back exactly the property the caller asked to remove, and would do it
// silently — the worst of both.
func TestMalformedMACPinRejectsEverything(t *testing.T) {
	got, notes := leaseCandidatesFrom(readFixture(t, "multi-vm.leases"), Target{VM: "drawbridge", HWAddr: "nonsense"})
	assertIPs(t, got, nil)
	joined := strings.Join(notes, " ")
	for _, want := range []string{"nonsense", "not a MAC address", "-vm-mac"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("notes missing %q:\n%s", want, joined)
		}
	}
}

// The subnet gate on its own: a private address that is not on the vmnet
// subnet was not handed out by this Mac's VM NAT, whatever it calls itself.
// The exclusion of Lima's outbound-only usernet (192.168.5.0/24) survives
// underneath it — that one is silent, since it is a normal part of a guest's
// address set rather than an anomaly worth a note.
func TestSubnetGate(t *testing.T) {
	const text = "{\n\tname=lima-drawbridge\n\tip_address=10.211.55.9\n\thw_address=1,52:55:55:a5:de:d2\n\tlease=0x30\n}\n" +
		"{\n\tname=lima-drawbridge\n\tip_address=192.168.5.15\n\thw_address=1,52:55:55:a5:de:d2\n\tlease=0x20\n}\n" +
		"{\n\tname=lima-drawbridge\n\tip_address=192.168.64.2\n\thw_address=1,52:55:55:a5:de:d2\n\tlease=0x10\n}\n"

	got, notes := leaseCandidatesFrom(text, Target{VM: "drawbridge"})
	assertIPs(t, got, []string{"192.168.64.2"})
	joined := strings.Join(notes, " ")
	if !strings.Contains(joined, "10.211.55.9") || !strings.Contains(joined, "192.168.64.0/24") {
		t.Fatalf("off-subnet rejection is not diagnosable:\n%s", joined)
	}
	if strings.Contains(joined, "192.168.5.15") {
		t.Fatalf("usernet exclusion should stay silent, not noted:\n%s", joined)
	}

	// A Mac whose vmnet is configured elsewhere must still work — that is
	// why the subnet is a field and not a constant.
	got, _ = leaseCandidatesFrom(text, Target{VM: "drawbridge", Subnet: netip.MustParsePrefix("10.211.55.0/24")})
	assertIPs(t, got, []string{"10.211.55.9"})
}

// The legacy path is unchanged: with no MAC known, name-only matching still
// returns the newest record first, because "the VM was recreated" is the
// common reading of two records with one name and the probe settles the
// rest. The warning that this is happening is Resolve's job, not the
// filter's.
func TestNoMACKnownKeepsNameOnlyBehaviour(t *testing.T) {
	got, notes := leaseCandidatesFrom(readFixture(t, "stale.leases"), Target{VM: "drawbridge"})
	assertIPs(t, got, []string{"192.168.64.8", "192.168.64.2"})
	// 192.168.5.15 is the silent usernet exclusion; 17.253.144.10 is not
	// private at all. Neither is a vmnet-subnet rejection, so neither is
	// noted — the note budget is for anomalies.
	if len(notes) != 0 {
		t.Fatalf("unexpected notes on the legacy path: %v", notes)
	}
}

// The same fixture with the MAC known: "recreated VM" and "another VM
// claiming this name" are indistinguishable by name and expiry, and the pin
// is what separates them.
func TestStaleFixtureWithMACPinned(t *testing.T) {
	got, _ := leaseCandidatesFrom(readFixture(t, "stale.leases"), Target{VM: "drawbridge", HWAddr: genuineMAC})
	assertIPs(t, got, []string{"192.168.64.2"})
}

func TestTargetSubnetDefault(t *testing.T) {
	if got := (Target{VM: "drawbridge"}).subnet().String(); got != DefaultSubnet {
		t.Fatalf("zero Target.subnet() = %s, want %s", got, DefaultSubnet)
	}
	if got := (Target{Subnet: netip.MustParsePrefix("10.0.0.7/8")}).subnet().String(); got != "10.0.0.0/8" {
		t.Fatalf("Target.subnet() = %s, want the masked network", got)
	}
}

func TestNoteNameOnlyMatchingIsActionable(t *testing.T) {
	note := noteNameOnlyMatching(Target{VM: "drawbridge"})
	for _, want := range []string{"lima-drawbridge", "-vm-mac", "limactl list"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q missing %q", note, want)
		}
	}

	// A provider target names the record it actually matched, not a lease
	// name reconstructed from the instance — the note is what a user greps
	// /var/db/dhcpd_leases with.
	note = noteNameOnlyMatching(Target{VM: "colima", LeaseName: "colima"})
	if !strings.Contains(note, "(colima)") {
		t.Fatalf("note %q does not name the colima lease record", note)
	}
}

// The lease-name parameter is the whole of the §3.3 generalization on this
// side, so both halves are pinned: empty means the historical "lima-<VM>",
// and an explicit name is matched exactly.
//
// The fixture is what /var/db/dhcpd_leases really looks like with a Lima VM
// and a Colima VM up (observed live): the Lima guest writes
// `name=lima-drawbridge`, the Colima guest writes `name=colima` — no prefix,
// because the record's name is the guest's hostname and colima sets that to
// the instance name. The fixture also carries a `lima-colima` record, which
// is what a *Lima* instance literally named `colima` would write.
func TestLeaseNameParameterization(t *testing.T) {
	text := readFixture(t, "colima.leases")

	for _, tc := range []struct {
		name   string
		target Target
		want   []string
	}{
		{"colima default profile", Target{VM: "colima", LeaseName: "colima"}, []string{"192.168.64.20"}},
		{"colima named profile", Target{VM: "colima-work", LeaseName: "colima-work"}, []string{"192.168.64.21"}},
		{"lima instance in the same file", Target{VM: "drawbridge"}, []string{"192.168.64.2"}},

		// The default is exactly the old derivation, so every caller that
		// never heard of a lease name keeps its behaviour — including, here,
		// a Lima instance that happens to be called `colima`.
		{"empty lease name defaults to lima-<VM>", Target{VM: "colima"}, []string{"192.168.64.22"}},

		// The two namespaces must not cross. Asking for colima's default
		// profile must not return the address of a Lima instance named
		// `colima`, and vice versa — both are vz guests on the same vmnet
		// answering :4777 with the same protocol, so the probe cannot
		// separate them afterwards.
		{"colima's record is not the lima-colima one", Target{VM: "colima", LeaseName: "colima"}, []string{"192.168.64.20"}},
		{"lima's colima record is not colima's", Target{VM: "colima", LeaseName: "lima-colima"}, []string{"192.168.64.22"}},

		// And the match stays exact within a namespace: `colima` must not
		// collect `colima-work`.
		{"no prefix bleed between profiles", Target{VM: "colima-work", LeaseName: "colima"}, []string{"192.168.64.20"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := leaseCandidatesFrom(text, tc.target)
			assertIPs(t, got, tc.want)
		})
	}

	// The MAC pin is not weakened by the new parameter: a colima record whose
	// hardware address is not the pinned one is refused, and says so.
	got, notes := leaseCandidatesFrom(text, Target{VM: "colima", LeaseName: "colima", HWAddr: "ee:ee:ee:ee:ee:99"})
	assertIPs(t, got, nil)
	joined := strings.Join(notes, " ")
	for _, want := range []string{"named colima", "ee:ee:ee:ee:ee:99", "-vm-mac"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("notes missing %q:\n%s", want, joined)
		}
	}
	// And it still succeeds against the record that does match.
	got, _ = leaseCandidatesFrom(text, Target{VM: "colima", LeaseName: "colima", HWAddr: "52:55:55:0a:de:02"})
	assertIPs(t, got, []string{"192.168.64.20"})
}

func TestTargetLeaseNameDefault(t *testing.T) {
	if got := (Target{VM: "drawbridge"}).leaseName(); got != "lima-drawbridge" {
		t.Fatalf("zero Target.leaseName() = %q, want lima-drawbridge", got)
	}
	if got := (Target{VM: "colima", LeaseName: "colima"}).leaseName(); got != "colima" {
		t.Fatalf("Target.leaseName() = %q, want the explicit name", got)
	}
}

func assertIPs(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("candidates = %v, want %v", got, want)
		}
	}
}
