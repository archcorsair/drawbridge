// Package limaaddr resolves the dev VM's best transport endpoint. The vzNAT
// guest IP is preferred — plain end-to-end TCP, no forwarder in the path —
// but host→guest traffic needs macOS Local Network permission, so it is
// probed before use. Fallback is the Lima-forwarded loopback port, which
// must be forwarded by the SSH forwarder (LIMA_SSH_PORT_FORWARDER=true,
// pinned in `just vm-up`): the default gRPC tunnel drops TCP half-close.
//
// Two independent ways to learn the vzNAT address: `limactl` (user-scoped)
// and the macOS DHCP lease db (leases.go, user-independent — the root
// LaunchDaemon's path). Both feed the same probe.
package limaaddr

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Endpoint sources, as reported in logs and bench headers.
const (
	SourceVZNATDirect  = "vznat-direct"
	SourceVZNATLeases  = "vznat-leases"
	SourceSSHForwarder = "ssh-forwarder"
)

// probeTimeout bounds the vzNAT reachability check at startup.
const probeTimeout = 800 * time.Millisecond

// DefaultSubnet is macOS's vmnet shared-mode subnet — where a
// Virtualization.framework NAT guest gets its DHCP lease on a stock install.
// It is a default and not a constant of the system: vmnet's range is
// configurable (/etc/bootpd.plist, the com.apple.vmnet preference's
// Shared_Net_Address), so Target.Subnet exists to say otherwise.
const DefaultSubnet = "192.168.64.0/24"

var defaultSubnet = netip.MustParsePrefix(DefaultSubnet)

// Target is what to resolve, and how much of the lease db to believe. The
// zero value beyond VM is the historical behaviour — name-only matching
// inside the default subnet, against the ambient LIMA_HOME.
type Target struct {
	// VM is the Lima instance name. Colima instances are Lima instances
	// (`colima`, `colima-<profile>`) and go here too — internal/vmprovider
	// does that mapping.
	VM string

	// LeaseName is the DHCP record name to match. Empty means "lima-<VM>",
	// which is what Lima's own guests claim and what every caller before
	// provider support wanted.
	//
	// It is a parameter rather than a derivation because the record name is
	// the guest's hostname, not a Lima-side fact: colima's guests are named
	// for the instance with no `lima-` prefix (`colima`), so `lima-`+VM is a
	// Lima default and not a rule. vmprovider.LeaseName holds the
	// per-provider knowledge; this package stays deliberately ignorant of
	// which providers exist. And because the name is DHCP option 12, chosen
	// by the guest, it is a match key and never evidence (leases.go).
	LeaseName string

	// LimaHome is the LIMA_HOME the limactl candidate source runs under.
	// Empty means the ambient environment, which is right for the user's own
	// Lima instances and wrong for colima's, whose limactl state lives in
	// colima's own config directory (vmprovider.ColimaHome discovers it —
	// colima moved that directory in v0.9). It has no bearing on the lease-db
	// source: that file is the OS's, not any provider's.
	LimaHome string

	// Subnet bounds lease-derived addresses. Unset means DefaultSubnet.
	Subnet netip.Prefix

	// HWAddr is the guest's expected hardware address, in any spelling
	// normalizeHWAddr accepts. When set, a lease record whose hw_address
	// does not match it is not a candidate — this is the only property of a
	// lease record a guest cannot simply choose, since the record's `name`
	// is DHCP option 12. When unset, matching is by name alone and Resolve
	// says so once (noteNameOnlyMatching).
	HWAddr string
}

// leaseName is Target.LeaseName with the historical default filled in.
func (t Target) leaseName() string {
	if t.LeaseName != "" {
		return t.LeaseName
	}
	return "lima-" + t.VM
}

// subnet is Target.Subnet with the default filled in, masked so a caller
// that passed a host address ("192.168.64.7/24") still gets the network.
func (t Target) subnet() netip.Prefix {
	if !t.Subnet.IsValid() {
		return defaultSubnet
	}
	return t.Subnet.Masked()
}

// Resolution is the outcome of endpoint resolution: which endpoint to use,
// which path it rides, and — when we fell back, or when a lease record was
// refused — why.
type Resolution struct {
	Endpoint string // canonical, e.g. "tcp://192.168.64.5:4777"
	Source   string // SourceVZNATDirect | SourceVZNATLeases | SourceSSHForwarder
	Note     string // non-empty when falling back or refusing a lease: reason + remediation
}

// candidate is one address worth probing, tagged with the source that would
// be reported had it answered.
type candidate struct{ ip, source string }

// Resolve picks the agent transport endpoint: the vzNAT address when
// reachable, else the forwarded loopback.
//
// Candidates are gathered from two independent sources and probed in order
// (docs/privileged-daemon.md §4):
//
//  1. `limactl shell … hostname -I` — authoritative, but only works when run
//     as the user who owns the VM. A root LaunchDaemon has no $LIMA_HOME, so
//     this fails fast there.
//  2. the macOS DHCP lease db — user-independent, hence the root path. Stale
//     records (recreated VM) are disambiguated by the probe, not by parsing.
//
// The first candidate that answers wins and names its own source; if none
// do, we fall back to the Lima-forwarded loopback with the classification of
// the first probe failure — the informative one, since candidate 1 is the
// address the user's own tooling reports.
//
// Resolve keeps the historical two-argument shape for callers that have no
// trust configuration to express; ResolveTarget is the full form.
func Resolve(vmName string, port uint16) Resolution {
	return ResolveTarget(Target{VM: vmName}, port)
}

// nameOnlyOnce keeps the unpinned-matching warning to one line per process.
// The resolver re-runs on every session reconnect, so a per-resolve warning
// would be a log flood that nobody reads — which is the same as no warning.
var nameOnlyOnce sync.Once

// ResolveTarget is Resolve with the lease-db trust gates spelled out. Notes
// produced while filtering lease records ride along on the Resolution
// whether or not the resolve succeeded: "your legitimate VM stopped
// resolving" and "something claimed your VM's name" are the same observation
// from different sides, and both have to be readable.
func ResolveTarget(t Target, port uint16) Resolution {
	p := strconv.Itoa(int(port))

	var leaseNotes []string
	withNotes := func(note string) string {
		parts := leaseNotes
		if note != "" {
			parts = append([]string{note}, leaseNotes...)
		}
		return strings.Join(parts, " ")
	}
	fallback := func(note string) Resolution {
		return Resolution{
			Endpoint: "tcp://" + net.JoinHostPort("127.0.0.1", p),
			Source:   SourceSSHForwarder,
			Note:     withNotes(note),
		}
	}

	var (
		cands []candidate
		seen  = map[string]bool{}
	)
	add := func(ip, source string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		cands = append(cands, candidate{ip, source})
	}
	if ip, err := guestIP(t); err == nil {
		add(ip, SourceVZNATDirect)
	}
	leased, notes, leasesErr := leaseCandidates(LeasesPath, t)
	leaseNotes = notes
	for _, ip := range leased {
		add(ip, SourceVZNATLeases)
	}
	if len(leased) > 0 && t.HWAddr == "" {
		nameOnlyOnce.Do(func() { log.Printf("drawbridge: warning: %s", noteNameOnlyMatching(t)) })
	}
	if len(cands) == 0 {
		if leasesErr != nil {
			return fallback(classifyNoLeases(LeasesPath, leasesErr))
		}
		return fallback(classifyNoGuestIP())
	}

	var (
		firstErr  error
		firstAddr string
	)
	for _, c := range cands {
		addr := net.JoinHostPort(c.ip, p)
		conn, err := net.DialTimeout("tcp", addr, probeTimeout)
		if err != nil {
			if firstErr == nil {
				firstErr, firstAddr = err, addr
			}
			continue
		}
		conn.Close()
		return Resolution{Endpoint: "tcp://" + addr, Source: c.source, Note: withNotes("")}
	}
	return fallback(classifyProbe(firstAddr, firstErr))
}

// ParseHWAddr validates a hardware address the way the resolver will read
// it, returning the canonical spelling. Callers use it to reject a bad
// -vm-mac at startup instead of discovering at first resolve that the pin
// matches nothing.
func ParseHWAddr(s string) (string, error) {
	hw, ok := normalizeHWAddr(s)
	if !ok {
		return "", fmt.Errorf("invalid hardware address %q: want six colon-separated hex octets, e.g. 52:55:55:a5:de:d2", s)
	}
	return hw, nil
}

// ParseSubnet validates a vmnet subnet override. It is deliberately narrow:
// an IPv4 CIDR in a private range. A public or v6 range here would not be a
// vmnet subnet, and accepting one only widens what a lease record can claim.
func ParseSubnet(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid subnet %q: want an IPv4 CIDR, e.g. %s", s, DefaultSubnet)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid subnet %q: want IPv4, e.g. %s", s, DefaultSubnet)
	}
	if !p.Addr().IsPrivate() {
		return netip.Prefix{}, fmt.Errorf("invalid subnet %q: vmnet hands out private addresses; a public range here would widen what a lease record may claim", s)
	}
	return p.Masked(), nil
}

// Notes returned by the probe classifier. They are the actionable half of
// the diagnosis — the resolver's caller logs them verbatim — and are the
// classification table in docs/transport.md §2.2.
const (
	// NoteLocalNetworkDenied: the route and the ARP entry exist, the guest
	// is up, and the SYN still cannot leave the host — on macOS that is the
	// Local Network privacy gate, not a network fault.
	NoteLocalNetworkDenied = "host→guest vzNAT blocked — likely macOS Local Network permission. " +
		"Grant it in System Settings → Privacy & Security → Local Network for your terminal app " +
		"(CLI tools inherit the terminal's grant) and/or drawbridged if listed; a cached denial may " +
		"need the app relaunched or a reboot. Falling back to the SSH forwarder (slower, shared tunnel)."

	// NoteAgentNotListening: the host reached the guest and got either
	// silence (no listener on that address, packets dropped) or an active
	// refusal — the agent is stale, down, or bound loopback-only.
	NoteAgentNotListening = "agent not reachable on the vzNAT address — is `just agent-up` current? " +
		"Falling back to the SSH forwarder."

	// NoteNoGuestIP: no vzNAT address to probe at all.
	NoteNoGuestIP = "no host-reachable guest IP (vzNAT missing?) — falling back to the SSH forwarder."
)

// classifyProbe explains a failed vzNAT probe. It is deliberately a single
// seam: the EHOSTUNREACH / timeout / ECONNREFUSED classification table in
// docs/transport.md §2.2 lands here, and nothing else in the resolver has
// to change for it.
//
// The errors arrive wrapped (*net.OpError around *os.SyscallError around a
// syscall.Errno), so every test is errors.Is / errors.As, never a string
// match on the message.
func classifyProbe(addr string, err error) string {
	switch {
	case errors.Is(err, syscall.EHOSTUNREACH):
		return NoteLocalNetworkDenied
	case errors.Is(err, syscall.ECONNREFUSED), isTimeout(err):
		return NoteAgentNotListening
	}
	// Unclassified: keep the raw diagnosis rather than guess at a remedy.
	return fmt.Sprintf("vzNAT endpoint %s not reachable (%v) — falling back to the SSH forwarder (slower, shared tunnel).", addr, err)
}

// isTimeout covers both shapes a dial timeout arrives in: a net.Error whose
// Timeout() reports true, and the deadline sentinels.
func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT)
}

// classifyNoGuestIP explains the absence of a host-reachable guest IPv4.
// The lookup error itself is a limactl invocation detail (almost always "VM
// not running", which every caller checks first), so the note stays the
// actionable sentence from the table.
func classifyNoGuestIP() string {
	return NoteNoGuestIP
}

// guestIP finds the VM's host-reachable IPv4. Lima's usernet subnet
// (192.168.5.0/24) is outbound-only and skipped. Unusable from a root
// daemon: limactl's state lives in the invoking user's $LIMA_HOME — that
// failure is expected there, and the lease db (leases.go) covers it.
//
// Target.LimaHome selects which state directory that is. Colima's instances
// are Lima instances in colima's own config directory, and limactl run with
// the ambient environment simply does not see them — which would silently
// cost every colima user the direct path and leave them on the forwarder.
func guestIP(t Target) (string, error) {
	cmd := exec.Command("limactl", "shell", t.VM, "--", "hostname", "-I")
	if t.LimaHome != "" {
		cmd.Env = append(os.Environ(), "LIMA_HOME="+t.LimaHome)
	}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("limactl shell hostname -I: %w", err)
	}
	for _, f := range strings.Fields(string(out)) {
		if !usableGuestIPv4(f) {
			continue
		}
		return f, nil
	}
	return "", fmt.Errorf("no host-reachable guest IPv4 in %q", strings.TrimSpace(string(out)))
}
