package vmprovider

// Coexistence detection (docs/ergonomics.md §3.4).
//
// An end user's Lima or Colima VM runs Lima's own port forwarder, which
// watches guest listeners and republishes them on Mac localhost — the same
// ports drawbridge mirrors. The decided posture is coexist and warn, never
// auto-disable: a mirror bind that loses the race gets EADDRINUSE, takes the
// existing log-and-skip path, and the guest listener is still reachable on
// Mac localhost via the provider's forwarder. Degraded (no synchronous bind
// arbitration on that port's Mac side) but working.
//
// What that posture costs is attribution, and attribution is what this file
// buys back: without it, "my port works" and "my port works *because
// drawbridge mirrored it*" are indistinguishable, and so are the two
// explanations for a failed mirror bind.
//
// Detection only. `drawbridge up` and `drawbridge doctor` are the callers,
// in later phases.

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The port space, and the two guest bind addresses drawbridge mirrors —
// which are also the two Lima evaluates its rules against.
const (
	minPort, maxPort = 1, 65535

	guestLoopback = "127.0.0.1"
	guestWildcard = "0.0.0.0"
)

// Forwarding is what the provider's own forwarder does for one instance.
type Forwarding struct {
	Instance string

	// HostAgent reports a live forwarder process holding this instance.
	// Rules in a stopped instance's config forward nothing, so this gates
	// the rest.
	HostAgent bool

	// Loopback and Wildcard are the guest ports still forwarded for a guest
	// listener bound to 127.0.0.1 and to 0.0.0.0.
	//
	// Two answers, not one, because an `ignore` rule can cover one address
	// and not the other — and that is not hypothetical: this repo's own dev
	// template ignored `guestIP: 127.0.0.1` only (until 2026-07-31), so
	// wildcard binds were still forwarded by Lima, which is how e2e legs that
	// bind 0.0.0.0 could pass without drawbridge doing anything
	// (docs/ergonomics.md §8, Phase 2 results). A single Boolean would have
	// hidden exactly that.
	//
	// Port sets, not Booleans, for the same reason at finer grain: that same
	// template forwards guest 127.0.0.1:4777 deliberately (drawbridge's own
	// control port). "Something is forwarded" would make it indistinguishable
	// from a stock instance forwarding all 65535, and those two warrant
	// opposite messages.
	Loopback PortSet
	Wildcard PortSet
}

// Active is the condition worth warning about: a running forwarder that
// still claims guest ports.
func (f Forwarding) Active() bool {
	return f.HostAgent && (len(f.Loopback) > 0 || len(f.Wildcard) > 0)
}

func (f Forwarding) String() string {
	return fmt.Sprintf("forwarding{instance:%s hostagent:%v loopback:%s wildcard:%s}",
		f.Instance, f.HostAgent, f.Loopback, f.Wildcard)
}

// PortRange is an inclusive port interval.
type PortRange struct{ Lo, Hi int }

// PortSet is a sorted, merged set of intervals — the shape a rule list
// evaluates to, and the shape a warning wants to print.
type PortSet []PortRange

// Contains answers the question a caller asks about one mirror: would the
// provider's forwarder claim this port too?
func (s PortSet) Contains(port int) bool {
	for _, r := range s {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// Count is how many ports the set covers.
func (s PortSet) Count() int {
	n := 0
	for _, r := range s {
		n += r.Hi - r.Lo + 1
	}
	return n
}

// String renders the set the way a port list is written: "4777",
// "1-65535", "80,443,8000-8999". Empty is "none", not "", so a message that
// interpolates it cannot read as a truncation.
func (s PortSet) String() string {
	if len(s) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(s))
	for _, r := range s {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(r.Lo))
			continue
		}
		parts = append(parts, strconv.Itoa(r.Lo)+"-"+strconv.Itoa(r.Hi))
	}
	return strings.Join(parts, ",")
}

// Forwarding reports whether this instance's own port forwarder is active.
// It re-reads `limactl list --json` for the one instance rather than reusing
// what List saw: the answer is a live process fact, and a stale "no
// forwarder" is precisely the reading that turns into an unexplained
// EADDRINUSE.
func (l *Lima) Forwarding(inst string) (Forwarding, error) {
	out, err := l.limactl(nil, "list", "--json", inst)
	if err != nil {
		return Forwarding{}, err
	}
	raw, err := decodeList(bytes.NewReader(out))
	if err != nil {
		return Forwarding{}, err
	}
	for _, li := range raw {
		if li.Name == inst {
			return forwardingOf(li), nil
		}
	}
	return Forwarding{}, fmt.Errorf("vmprovider: no %s instance named %q", l.provider, inst)
}

// forwardingOf is the pure half — fixture-testable, no limactl in the path.
func forwardingOf(li limaJSON) Forwarding {
	rules := li.Config.PortForwards
	return Forwarding{
		Instance:  li.Name,
		HostAgent: li.running() && li.HostAgentPID != 0,
		Loopback:  forwardedPorts(rules, guestLoopback),
		Wildcard:  forwardedPorts(rules, guestWildcard),
	}
}

// portForward is the subset of a materialized Lima port-forward rule that
// decides whether a guest listener reaches the Mac. `limactl list --json`
// emits the merged config — guestPort and guestPortRange both filled in,
// guestIP defaulted — so nothing here has to reproduce Lima's defaulting.
type portForward struct {
	GuestIP           string `json:"guestIP"`
	GuestIPMustBeZero bool   `json:"guestIPMustBeZero"`
	GuestPort         int    `json:"guestPort"`
	GuestPortRange    [2]int `json:"guestPortRange"`
	Ignore            bool   `json:"ignore"`

	// GuestSocket rules forward a unix socket, not a TCP port, and never
	// participate in the question this file asks.
	GuestSocket string `json:"guestSocket"`
}

// portRange is the rule's guest port interval, falling back to the single
// guestPort for a rule limactl has not materialized.
func (r portForward) portRange() (lo, hi int) {
	lo, hi = r.GuestPortRange[0], r.GuestPortRange[1]
	if lo == 0 && hi == 0 {
		return r.GuestPort, r.GuestPort
	}
	return lo, hi
}

// matches models Lima's rule matching for a TCP listener on guestIP:port.
//
// It is a model, not a transcription of upstream's matcher, and it is
// calibrated on the one behaviour this repo has measured: a `guestIP:
// 127.0.0.1` catch-all ignore rule (the dev template's shape until
// 2026-07-31) does not suppress forwarding of a guest listener bound to
// 0.0.0.0. Hence a rule's guestIP restricts it unless that guestIP is itself
// the wildcard.
func (r portForward) matches(guestIP string, port int) bool {
	if r.GuestSocket != "" {
		return false
	}
	if lo, hi := r.portRange(); port < lo || port > hi {
		return false
	}
	if r.GuestIPMustBeZero && guestIP != guestWildcard {
		return false
	}
	if r.GuestIP != "" && r.GuestIP != guestWildcard && r.GuestIP != guestIP {
		return false
	}
	return true
}

// forwards evaluates the rule list for one guest listener: first matching
// rule wins, and a matching `ignore: true` rule means the port does not
// reach the Mac.
//
// A listener no rule matches is forwarded. Lima's default is to forward
// everything, so "no rule has an opinion" is "yes" — and that is the safe
// direction for a detector whose output is a warning: over-warning costs a
// line of text, under-warning costs an unexplained bind failure.
func forwards(rules []portForward, guestIP string, port int) bool {
	for _, r := range rules {
		if r.matches(guestIP, port) {
			return !r.Ignore
		}
	}
	return true
}

// forwardedPorts evaluates the whole port space for one guest address.
//
// Rules are port intervals, so `forwards` can only change value at a rule
// boundary: evaluating once per segment between boundaries is exact, and
// 65535 evaluations cheaper than the obvious loop.
func forwardedPorts(rules []portForward, guestIP string) PortSet {
	bounds := breakpoints(rules)
	var out PortSet
	for i, lo := range bounds {
		hi := maxPort
		if i+1 < len(bounds) {
			hi = bounds[i+1] - 1
		}
		if !forwards(rules, guestIP, lo) {
			continue
		}
		if n := len(out); n > 0 && out[n-1].Hi == lo-1 {
			out[n-1].Hi = hi // adjacent segments merge
			continue
		}
		out = append(out, PortRange{Lo: lo, Hi: hi})
	}
	return out
}

// breakpoints are the ports at which the rule list's verdict can change:
// the bottom of the space, and each rule's first and just-past-last port.
func breakpoints(rules []portForward) []int {
	set := map[int]bool{minPort: true}
	add := func(p int) {
		if p >= minPort && p <= maxPort {
			set[p] = true
		}
	}
	for _, r := range rules {
		lo, hi := r.portRange()
		add(lo)
		add(hi + 1)
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
