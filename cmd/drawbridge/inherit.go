package main

// `drawbridge install`'s inheritance from the daemon already installed
// (decision E3, docs/privileged-daemon.md §2).
//
// There is one LaunchDaemon. Before this, every flag the user left out took
// its built-in default, so the documented upgrade — a bare `sudo drawbridge
// install` — re-targeted a colima or podman daemon at lima:drawbridge and
// dropped any -vm-mac pin, -vm-subnet, -udp and -skip on the way (audit
// 2026-10-28 H3, M15). Now every flag not given explicitly defaults from the
// installed plist, and each value kept that way is printed before anything is
// installed. An explicit flag always wins, including an explicit "".
//
// Two of the rendered values belong to a VM rather than to the Mac: -vm-mac
// pins one guest's hardware address and -secret-file is one VM's transport
// secret (the -agent pin is the third, and install derives it rather than
// taking it as a flag). When the target VM changes they are never carried
// over: they are derived for the new VM exactly as a fresh install would, and
// the command says so.

import (
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// readInstalledArgs is the seam the tests replace: a test must never read
// (or depend on) the real plist on the machine it runs on, which on a
// developer's Mac is a live install.
var readInstalledArgs = install.ReadInstalledArgs

// installFlags are install's flag values that the installed plist can supply.
type installFlags struct {
	vm, mac, subnet, udp, skip, secretFile string
}

// inherited is the merge of the flags given with the installed daemon's.
type inherited struct {
	flags installFlags

	// notes are printed before anything is installed: one line per value
	// kept from the installed daemon, per per-VM value not kept because the
	// VM changed, and per installed value an explicit "" dropped.
	notes []string

	// from names the flags whose value came from the plist, so a parse
	// error on one can say where the bad value came from.
	from map[string]bool

	installed  bool   // a plist was read
	prevVM     string // its -vm, verbatim ("" when it carries none)
	prevTarget string // the VM that daemon serves: prevVM, else drawbridged's default
	prevAgent  string // its -agent, "" for auto or absent
	sameVM     bool   // the install targets prevTarget (canonical refs)
}

// fromInstalled is the suffix a parse error carries for an inherited value.
func (h inherited) fromInstalled(name string) string {
	if h.from[name] {
		return " (kept from " + install.PlistPath + "; pass -" + name + " to override)"
	}
	return ""
}

// explicitFlags is every flag the command line set, by name. flag.Visit
// walks only flags that were set, which is the one way to tell an explicit
// `-vm-mac ""` from an omitted -vm-mac.
func explicitFlags(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// sameVM compares two -vm spellings as the daemon would read them: provider
// and instance after ParseRef, never the raw text. `colima:default` and
// `colima:colima` are one VM; `colima` (a bare name, so Lima) and
// `colima:colima` are two. A spelling that does not parse matches nothing.
func sameVM(a, b string) bool {
	ra, err := vmprovider.ParseRef(a)
	if err != nil {
		return false
	}
	rb, err := vmprovider.ParseRef(b)
	if err != nil {
		return false
	}
	return ra.Provider == rb.Provider && ra.Instance == rb.Instance
}

// showArg renders a value the way it would be typed: quoted when it is empty
// or holds a space (the secret path lives under "Application Support").
func showArg(v string) string {
	if v == "" || strings.ContainsAny(v, " \t") {
		return strconv.Quote(v)
	}
	return v
}

// inheritInstall merges the given flags with the installed daemon's
// arguments. set is explicitFlags' answer; prev/ok is ReadInstalledArgs'.
// With no installed plist it returns the flags unchanged: today's behavior.
func inheritInstall(f installFlags, set map[string]bool, prev install.InstalledArgs, ok bool) inherited {
	h := inherited{flags: f, from: map[string]bool{}}
	if !ok {
		return h
	}
	h.installed = true
	h.prevVM, _ = prev.Get("-vm")
	if a, _ := prev.Get("-agent"); a != "auto" {
		h.prevAgent = a
	}

	keep := func(name, v string, dst *string) {
		*dst = v
		h.from[name] = true
		h.notes = append(h.notes, fmt.Sprintf("keeping -%s %s from the installed daemon", name, showArg(v)))
	}

	if !set["vm"] && h.prevVM != "" {
		keep("vm", h.prevVM, &h.flags.vm)
	}
	// A plist with no -vm (no install has ever written one, but the daemon
	// has a default) runs drawbridged's default VM, and is compared as that.
	h.prevTarget = h.prevVM
	if h.prevTarget == "" {
		h.prevTarget = install.DefaultVM
	}
	h.sameVM = sameVM(h.prevTarget, h.flags.vm)

	// Mac-wide values: the vmnet subnet is the Mac's, and -udp/-skip name
	// Mac ports. They survive a change of VM.
	for _, m := range []struct {
		name string
		dst  *string
	}{
		{"udp", &h.flags.udp},
		{"skip", &h.flags.skip},
		{"vm-subnet", &h.flags.subnet},
	} {
		v, has := prev.Get("-" + m.name)
		switch {
		case !has:
		case !set[m.name]:
			keep(m.name, v, m.dst)
		case *m.dst == "" && v != "":
			h.notes = append(h.notes, fmt.Sprintf("dropping -%s %s from the installed daemon (-%s \"\" given)", m.name, showArg(v), m.name))
		}
	}

	// Per-VM values: kept only while the VM is the same one.
	for _, m := range []struct {
		name, whose string
		dst         *string
	}{
		{"vm-mac", "pins the hardware address of", &h.flags.mac},
		{"secret-file", "is the transport secret of", &h.flags.secretFile},
	} {
		v, has := prev.Get("-" + m.name)
		switch {
		case !has || v == "":
		case set[m.name]:
			if *m.dst == "" {
				line := fmt.Sprintf("dropping -%s %s from the installed daemon (-%s \"\" given)", m.name, showArg(v), m.name)
				if m.name == "secret-file" {
					line += "; derived as a fresh install would"
				}
				h.notes = append(h.notes, line)
			}
		case h.sameVM:
			keep(m.name, v, m.dst)
		default:
			h.notes = append(h.notes, fmt.Sprintf("not keeping -%s %s: it %s %s, not %s; derived for %s as a fresh install would",
				m.name, showArg(v), m.whose, h.prevTarget, h.flags.vm, h.flags.vm))
		}
	}
	return h
}

// agentNote says what happened to an installed -agent pin, given the
// endpoint this install renders ("" for auto). install never takes -agent as
// a flag: a podman machine's endpoint is re-read from the record `up` wrote
// (the source of truth, checked against the machine on every install), and
// every other provider resolves with auto. So a pin is never inherited, only
// re-derived, and a pin that changes is said out loud.
func (h inherited) agentNote(agent string) string {
	if !h.installed || h.prevAgent == "" || h.prevAgent == agent {
		return ""
	}
	switch {
	case !h.sameVM:
		return fmt.Sprintf("not keeping -agent %s: it is the endpoint of %s, not %s; derived for %s as a fresh install would",
			h.prevAgent, h.prevTarget, h.flags.vm, h.flags.vm)
	case agent == "":
		return fmt.Sprintf("not keeping -agent %s: install pins an endpoint only for a podman machine, and %s resolves with -agent auto",
			h.prevAgent, h.flags.vm)
	default:
		return fmt.Sprintf("the installed daemon pins -agent %s; the record `drawbridge up` wrote now says %s, which is what installs",
			h.prevAgent, agent)
	}
}
