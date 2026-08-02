package vmprovider

import "testing"

func forwardingFixture(t *testing.T, file, name string) Forwarding {
	t.Helper()
	for _, li := range fixture(t, file) {
		if li.Name == name {
			return forwardingOf(li)
		}
	}
	t.Fatalf("%s has no instance %q", file, name)
	return Forwarding{}
}

// The dev template, which is where this detector earns its keep. Forwarding
// was believed disabled; it is disabled for guest 127.0.0.1 only, so a guest
// listener on 0.0.0.0 is still republished on Mac localhost by Lima. That is
// the Phase 2 e2e attribution hole (docs/ergonomics.md §8), and a detector
// that answered one Boolean would report exactly the belief instead of the
// fact.
func TestForwardingDevTemplate(t *testing.T) {
	f := forwardingFixture(t, "lima-list.json", "drawbridge")
	if !f.HostAgent {
		t.Fatal("hostagent not detected on a running instance with a hostAgentPID")
	}
	// Loopback: only the deliberately forwarded agent control port.
	if got := f.Loopback.String(); got != "4777" {
		t.Fatalf("loopback ports = %s, want just the agent port", got)
	}
	// Wildcard: everything, which is the hole.
	if got := f.Wildcard.String(); got != "1-65535" {
		t.Fatalf("wildcard ports = %s, want the whole space", got)
	}
	if !f.Active() {
		t.Fatal("Active() false with a live hostagent still claiming ports")
	}
	if !f.Wildcard.Contains(8080) || f.Loopback.Contains(8080) {
		t.Fatalf("Contains disagrees with the sets: %s", f)
	}
}

// A stock instance forwards everything on both addresses — the first-run
// case `up` warns about.
func TestForwardingStockInstance(t *testing.T) {
	f := forwardingFixture(t, "lima-list.json", "stock-vz")
	if !f.Active() || f.Loopback.String() != "1-65535" || f.Wildcard.String() != "1-65535" {
		t.Fatalf("stock instance = %s, want everything forwarded on both addresses", f)
	}
	if f.Loopback.Count() != 65535 {
		t.Fatalf("Count() = %d, want 65535", f.Loopback.Count())
	}
}

// Colima out of the box is the stock case with a different home.
func TestForwardingColima(t *testing.T) {
	f := forwardingFixture(t, "colima-list.json", "colima")
	if !f.Active() || f.Wildcard.String() != "1-65535" {
		t.Fatalf("colima = %s, want an active forwarder", f)
	}

	// A stopped instance forwards nothing, whatever its rules say — and its
	// rule list here is empty, i.e. "forward everything", so this is exactly
	// the case where reading the config alone would be wrong.
	stopped := forwardingFixture(t, "colima-list.json", "colima-work")
	if stopped.HostAgent || stopped.Active() {
		t.Fatalf("stopped instance = %s, want no live forwarder", stopped)
	}
	if stopped.Wildcard.String() != "1-65535" {
		t.Fatalf("stopped instance's rules = %s; the config still says forward-all, HostAgent is what gates it", stopped.Wildcard)
	}
}

// Forwarding fully disabled: a wildcard-guestIP catch-all ignore rule covers
// both addresses. This is the shape `doctor` tells a user to write when they
// want full drawbridge semantics.
func TestForwardingDisabled(t *testing.T) {
	f := forwardingFixture(t, "forwarding-off.json", "quiet")
	if f.Active() {
		t.Fatalf("quiet = %s, want nothing forwarded", f)
	}
	if !f.HostAgent {
		t.Fatal("hostagent should still be detected — it is running, it just forwards nothing")
	}
	if f.Loopback.String() != "none" || f.Wildcard.String() != "none" {
		t.Fatalf("quiet = %s, want empty port sets", f)
	}
}

// First matching rule wins, guestSocket rules are not port rules, and an
// unmatched port is forwarded (Lima's default is forward-everything, and
// over-warning is the safe direction for a warning).
func TestForwardingRuleOrderAndSockets(t *testing.T) {
	f := forwardingFixture(t, "forwarding-off.json", "partial")
	if f.Active() {
		t.Fatalf("partial = %s: the second catch-all ignore covers the space", f)
	}

	// The narrower rule first, then a catch-all that forwards: the first
	// match must win, leaving a hole in the middle of the range.
	rules := []portForward{
		{GuestIP: guestWildcard, GuestPortRange: [2]int{8000, 8999}, Ignore: true},
		{GuestIP: guestWildcard, GuestPortRange: [2]int{1, 65535}},
	}
	if got := forwardedPorts(rules, guestWildcard).String(); got != "1-7999,9000-65535" {
		t.Fatalf("forwardedPorts = %s, want the ignored block punched out", got)
	}

	// No rules at all: Lima forwards everything.
	if got := forwardedPorts(nil, guestLoopback).String(); got != "1-65535" {
		t.Fatalf("forwardedPorts(no rules) = %s, want everything", got)
	}

	// A socket rule is not a port rule and must not swallow the space.
	sock := []portForward{{GuestSocket: "/run/docker.sock", GuestPortRange: [2]int{1, 65535}, Ignore: true}}
	if got := forwardedPorts(sock, guestLoopback).String(); got != "1-65535" {
		t.Fatalf("forwardedPorts(socket rule) = %s, want it ignored", got)
	}
}

// guestIPMustBeZero restricts a rule to wildcard-bound listeners only.
func TestForwardingGuestIPMustBeZero(t *testing.T) {
	rules := []portForward{{GuestIPMustBeZero: true, GuestPortRange: [2]int{1, 65535}, Ignore: true}}
	if got := forwardedPorts(rules, guestWildcard).String(); got != "none" {
		t.Fatalf("wildcard = %s, want the rule to apply", got)
	}
	if got := forwardedPorts(rules, guestLoopback).String(); got != "1-65535" {
		t.Fatalf("loopback = %s, want the rule skipped", got)
	}
}

// A rule limactl has not materialized carries guestPort alone; the range
// falls back to it rather than collapsing to [0,0] and matching nothing.
func TestPortRangeFallsBackToGuestPort(t *testing.T) {
	r := portForward{GuestPort: 4777}
	if lo, hi := r.portRange(); lo != 4777 || hi != 4777 {
		t.Fatalf("portRange() = %d-%d, want 4777-4777", lo, hi)
	}
	rules := []portForward{{GuestPort: 4777, Ignore: true}}
	if got := forwardedPorts(rules, guestLoopback).String(); got != "1-4776,4778-65535" {
		t.Fatalf("forwardedPorts = %s, want a single-port hole", got)
	}
}

func TestPortSetString(t *testing.T) {
	for _, tc := range []struct {
		in   PortSet
		want string
	}{
		{nil, "none"},
		{PortSet{{80, 80}}, "80"},
		{PortSet{{80, 80}, {443, 443}, {8000, 8999}}, "80,443,8000-8999"},
	} {
		if got := tc.in.String(); got != tc.want {
			t.Fatalf("PortSet%v.String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The Forwarder interface is what `up`/`doctor` will hold. Assert the
// concrete driver satisfies it so a signature drift is a compile error here
// rather than in a later phase.
var _ Forwarder = (*Lima)(nil)
var _ Provider = (*Lima)(nil)
