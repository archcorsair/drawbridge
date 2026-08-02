package limaaddr

// Root-path endpoint discovery. `limactl` is unusable from a root daemon —
// its state lives in the invoking user's $LIMA_HOME and root's HOME is
// /var/root — so the vzNAT address has to come from somewhere that does not
// depend on who is asking. macOS's own DHCP server (the one
// Virtualization.framework's NAT uses) keeps its lease database in a
// world-readable plain-text file; parsing it is a read-only look at an
// OS-owned file, which is how Tart/UTM tooling finds VM IPs too.
//
// The parser is a pure function over the file's text (fixture-tested, no
// root needed). What the parser cannot do is establish trust: the `name`
// field is DHCP option 12, the client's own choice, so every VM on this Mac
// can write a record named `lima-<vm>`. The root LaunchDaemon has no second
// source to cross-check against, so the candidate filter — not the probe —
// has to carry that weight: an address is only a candidate if it also sits
// in the vmnet subnet, and, when the caller knows the guest's MAC, only if
// the record's hardware address matches it. See Target.

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

// LeasesPath is the macOS DHCP server's lease database. Format (stable for
// many years, and widely depended on): a sequence of brace-delimited
// records of `key=value` lines.
//
//	{
//		name=lima-drawbridge
//		ip_address=192.168.64.2
//		hw_address=1,52:55:55:a5:de:d2
//		identifier=1,52:55:55:a5:de:d2
//		lease=0x6a6c420d
//	}
const LeasesPath = "/var/db/dhcpd_leases"

// maxLeaseCandidates bounds how many lease-derived addresses we are willing
// to probe. Each probe costs up to probeTimeout, and this runs on every
// resolver pass (startup plus every session reconnect behind the 3 s
// minimum interval), so a lease db full of stale records must not turn
// resolution into a multi-second stall.
const maxLeaseCandidates = 4

// lease is one record of the lease database. Unknown keys are ignored, so a
// future field cannot break parsing.
type lease struct {
	Name   string
	IP     string
	HWAddr string
	Expiry int64 // seconds since epoch; 0 when absent or unparseable
}

// parseLeases is the pure half: text in, records out. It is deliberately
// forgiving — a malformed record is skipped, not fatal, because the file is
// written by the OS and read by us on every resolve. Records without a name
// or without an IP are dropped (nothing downstream can use them).
func parseLeases(text string) []lease {
	var (
		out []lease
		cur lease
		in  bool
	)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		switch {
		case line == "{":
			cur, in = lease{}, true
			continue
		case line == "}":
			if in && cur.Name != "" && cur.IP != "" {
				out = append(out, cur)
			}
			cur, in = lease{}, false
			continue
		case !in || line == "":
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch key {
		case "name":
			cur.Name = val
		case "ip_address":
			cur.IP = val
		case "hw_address":
			cur.HWAddr = val
		case "lease":
			cur.Expiry = parseLeaseTime(val)
		}
	}
	return out
}

// parseLeaseTime reads the `lease=` value, which macOS writes as a 0x-prefixed
// hex expiry timestamp. Anything else parses as 0, which sorts last — an
// unreadable timestamp costs a record its ordering priority, never its
// candidacy.
func parseLeaseTime(v string) int64 {
	s := strings.TrimSpace(v)
	base := 10
	if l := strings.ToLower(s); strings.HasPrefix(l, "0x") {
		s, base = l[2:], 16
	}
	n, err := strconv.ParseInt(s, base, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// normalizeHWAddr canonicalises a hardware address to lowercase
// colon-separated octets with leading zeros ("52:55:55:a5:de:d2").
//
// Two spellings have to land on the same string. /var/db/dhcpd_leases writes
// an ARP hardware-type prefix and drops leading zeros on single-digit octets
// ("1,5:55:55:a5:de:d2"); Lima reports the conventional form
// ("52:55:55:A5:DE:D2"). Comparing them as written never matches, which
// would turn a MAC pin into a permanent resolution failure rather than a
// working one — the failure mode a security control must not have.
//
// The second return is false for anything that is not six hex octets. It is
// never treated as "no pin": an unreadable pin fails closed (see
// leaseCandidatesFrom).
func normalizeHWAddr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	// Strip the ARP hardware type ("1," = Ethernet). Only a numeric type is
	// this format; anything else is some other string entirely.
	if i := strings.IndexByte(s, ','); i >= 0 {
		t := s[:i]
		if t == "" || strings.TrimLeft(t, "0123456789") != "" {
			return "", false
		}
		s = s[i+1:]
	}
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return "", false
	}
	var b strings.Builder
	b.Grow(len("52:55:55:a5:de:d2"))
	for i, p := range parts {
		// ParseUint rejects signs and (outside base 0) underscores and the
		// 0x prefix, so the only accepted shape here is 1–2 hex digits.
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil || len(p) == 0 || len(p) > 2 {
			return "", false
		}
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02x", v)
	}
	return b.String(), true
}

// leaseCandidatesFrom picks this VM's addresses out of already-read lease
// text, newest lease first, and reports in words every record it refused.
//
// The record's name is Target.LeaseName — the guest's hostname, which Lima
// defaults to `lima-<vm>` and colima sets to the bare instance name
// (`colima`); vmprovider.LeaseName is where that per-provider knowledge
// lives. The match is exact: a prefix match would hand `drawbridge`'s
// resolver the address of a `drawbridge-test` VM, which the probe cannot tell
// apart (both answer on :4777 with the same protocol). But the name alone is
// not evidence — it is the guest's own DHCP option 12 — so two further gates
// apply:
//
//   - the address must sit in the vmnet subnet (Target.Subnet). A record
//     outside it was not handed out by the VM NAT this resolver is for.
//   - when Target.HWAddr is set, the record's hw_address must match it.
//     This is the only gate a guest cannot satisfy by choosing a string.
//
// Ordering is newest-expiry-first because a recreated VM leaves the old
// record behind with an older expiry; probing the fresh one first means the
// common case costs one probe. Correctness of *which* VM answers is the
// gates' job, not the ordering's — newest-first is also exactly the ranking
// a squatter would exploit, which is why the gates run before the sort.
func leaseCandidatesFrom(text string, t Target) (ips, notes []string) {
	want := t.leaseName()
	subnet := t.subnet()

	var wantHW string
	if t.HWAddr != "" {
		hw, ok := normalizeHWAddr(t.HWAddr)
		if !ok {
			// Fail closed. An unreadable pin is not the same as no pin:
			// degrading to name-only matching here would silently give back
			// the property the caller asked for.
			return nil, []string{noteBadHWPin(t.HWAddr, want)}
		}
		wantHW = hw
	}

	// Rejections are aggregated per reason — a lease db with fifty stale
	// records must produce a sentence, not fifty.
	var (
		matched            []lease
		offNet, offNetSeen = 0, ""
		badHW, badHWSeen   = 0, ""
	)
	for _, l := range parseLeases(text) {
		if l.Name != want || !usableGuestIPv4(l.IP) {
			continue
		}
		ip, err := netip.ParseAddr(l.IP)
		if err != nil || !subnet.Contains(ip) {
			if offNet++; offNetSeen == "" {
				offNetSeen = l.IP
			}
			continue
		}
		if wantHW != "" {
			got, ok := normalizeHWAddr(l.HWAddr)
			if !ok || got != wantHW {
				if badHW++; badHWSeen == "" {
					badHWSeen = describeLeaseHW(l)
				}
				continue
			}
		}
		matched = append(matched, l)
	}
	if offNet > 0 {
		notes = append(notes, noteOffSubnet(offNet, want, offNetSeen, subnet))
	}
	if badHW > 0 {
		notes = append(notes, noteHWMismatch(badHW, want, badHWSeen, wantHW))
	}

	sort.SliceStable(matched, func(i, j int) bool { return matched[i].Expiry > matched[j].Expiry })

	seen := make(map[string]bool, len(matched))
	for _, l := range matched {
		if seen[l.IP] {
			continue
		}
		seen[l.IP] = true
		ips = append(ips, l.IP)
		if len(ips) == maxLeaseCandidates {
			break
		}
	}
	return ips, notes
}

// describeLeaseHW names a rejected record the way a user can find it in the
// file: by address, and by the hardware address it claimed.
func describeLeaseHW(l lease) string {
	if strings.TrimSpace(l.HWAddr) == "" {
		return l.IP + " (no hw_address)"
	}
	return l.IP + " (hw_address " + l.HWAddr + ")"
}

// leaseCandidates reads the lease db and returns this VM's addresses plus
// the rejection notes. A missing or unreadable file is an error the caller
// turns into a resolver Note, not a panic: the forwarder fallback still
// works, it is just slower.
func leaseCandidates(path string, t Target) (ips, notes []string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	ips, notes = leaseCandidatesFrom(string(b), t)
	return ips, notes, nil
}

// usableGuestIPv4 is the basic shape filter both candidate sources share: a
// private IPv4 that is not on Lima's outbound-only usernet subnet
// (192.168.5.0/24 — reachable from the guest outward only, so dialing it
// from the Mac never works).
//
// It is deliberately *not* the vmnet subnet pin. That gate applies only to
// the lease db, which any VM on this Mac can write into; `limactl` output
// comes from the instance Lima itself owns, so narrowing it would buy no
// trust and would break a non-default vmnet install on the path that has no
// -vm-subnet to fix it with.
func usableGuestIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return false
	}
	return !strings.HasPrefix(s, "192.168.5.")
}

// classifyNoLeases explains "no candidates at all, and the lease db could
// not even be read" — the shape the root path degrades into if Apple ever
// changes the file's location or permissions. Said in words, per the
// diagnosis discipline in docs/transport.md.
func classifyNoLeases(path string, err error) string {
	return fmt.Sprintf("no vzNAT candidates: limactl did not answer (running as root?) and the DHCP lease db %s is unreadable (%v) — falling back to the SSH forwarder (slower, shared tunnel).", path, err)
}

// noteOffSubnet explains a lease record dropped for sitting outside the
// vmnet subnet. Both halves matter: what was skipped, and the one legitimate
// reason it might have been (a vmnet configured off the default).
func noteOffSubnet(n int, want, first string, subnet netip.Prefix) string {
	return fmt.Sprintf("ignored %d DHCP lease record(s) named %s outside the vmnet subnet %s (first %s) — "+
		"an address from another subnet was not handed out by this Mac's VM NAT. If vmnet here is configured "+
		"on a different subnet (/etc/bootpd.plist, com.apple.vmnet Shared_Net_Address), pass -vm-subnet with it.",
		n, want, subnet, first)
}

// noteHWMismatch explains a lease record dropped for claiming the VM's name
// with someone else's hardware address — which is both the recreated-VM case
// and the name-squatting case, so the note has to name both remedies.
func noteHWMismatch(n int, want, first, wantHW string) string {
	return fmt.Sprintf("ignored %d DHCP lease record(s) named %s whose hardware address is not the pinned %s (first %s) — "+
		"the DHCP name is chosen by the guest, so a second VM on this Mac claiming this name looks exactly like this. "+
		"If instead you recreated the VM, re-run `sudo drawbridge install -vm-mac` with its new address.",
		n, want, wantHW, first)
}

// noteBadHWPin explains the fail-closed path: the caller asked for a MAC pin
// and gave something that is not a MAC, so nothing from the lease db is
// trusted at all.
func noteBadHWPin(given, want string) string {
	return fmt.Sprintf("expected hardware address %q is not a MAC address — every DHCP lease record named %s was ignored "+
		"rather than falling back to name-only matching. Fix -vm-mac: six colon-separated hex octets, e.g. 52:55:55:a5:de:d2.",
		given, want)
}

// noteNameOnlyMatching is the standing warning for the unpinned case. The
// DHCP `name` is option 12 — the client's own choice — so any VM on this Mac
// can write a record with the matched name, and the newest expiry wins the
// sort. Logged once per process, not per resolve: the resolver re-runs on
// every session reconnect.
//
// The wording is unchanged from the pre-provider version for a Lima target;
// only the two interpolations are now the Target's own lease name and
// instance name rather than "lima-"+vm twice. docs/transport.md §2.2 and
// (later) `doctor` quote these strings.
func noteNameOnlyMatching(t Target) string {
	return fmt.Sprintf("vzNAT address taken from the DHCP lease db matched by name only (%s). The DHCP name is chosen "+
		"by the guest, so another VM on this Mac could claim it and be dialed instead. Pin the guest's hardware address with "+
		"-vm-mac (read it from `limactl list --format json %s`).", t.leaseName(), t.VM)
}
