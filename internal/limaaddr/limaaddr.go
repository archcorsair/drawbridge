// Package limaaddr resolves the dev VM's best transport endpoint. The vzNAT
// guest IP is preferred — plain end-to-end TCP, no forwarder in the path —
// but host→guest traffic needs macOS Local Network permission, so it is
// probed before use. Fallback, for a Lima target only, is the Lima-forwarded
// loopback port, which must be forwarded by the SSH forwarder
// (LIMA_SSH_PORT_FORWARDER=true, pinned in `just vm-up`): the default gRPC
// tunnel drops TCP half-close. Any other provider has no such forward, and
// that port would be some other VM's, so it resolves to no endpoint instead.
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

	// SourceUnresolved marks a Resolution that carries no endpoint: the
	// target is not a Lima instance, nothing usable answered, and the
	// loopback forward is not this target's to dial (Target.Provider).
	SourceUnresolved = "unresolved"
)

// providerLima is vmprovider.ProviderLima. limaaddr stays ignorant of which
// providers exist (Target.LeaseName makes the same point), so the one name it
// does need is spelled here and pinned to vmprovider's by a test.
const providerLima = "lima"

// loopbackHost is where Lima's SSH port forwarder publishes the agent port.
const loopbackHost = "127.0.0.1"

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

	// Provider is the VM provider name (vmprovider.Provider*). Empty means
	// Lima, the historical meaning of a bare Target{VM: ...}.
	//
	// It decides exactly one thing: whether the resolver may fall back to
	// 127.0.0.1:<port>. That port is the SSH forward of a *Lima* instance
	// (`just vm-up` pins LIMA_SSH_PORT_FORWARDER); a colima instance has no
	// such forward, so for it the loopback port reaches whichever Lima VM
	// owns it, and a root daemon would dial that VM as if it were the
	// target (audit NEW-X1, decision E5). Any provider that is not Lima gets
	// an empty-endpoint Resolution instead of the fallback. The value is
	// Ref.Provider, which ParseRef derives without exec, so the root
	// daemon can supply it.
	Provider string

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

// mayUseLoopbackForward reports whether 127.0.0.1:<port> is this target's own
// SSH forward. Only a Lima instance owns it.
func (t Target) mayUseLoopbackForward() bool {
	return t.Provider == "" || t.Provider == providerLima
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
//
// Endpoint is empty only when the target is not a Lima instance and nothing
// usable answered (Source == SourceUnresolved): there is deliberately nothing
// to dial, and Note says why. Callers retry resolution on their own cadence.
type Resolution struct {
	Endpoint string // canonical, e.g. "tcp://192.168.64.5:4777"; empty when Source == SourceUnresolved
	Source   string // SourceVZNATDirect | SourceVZNATLeases | SourceSSHForwarder | SourceUnresolved
	Note     string // non-empty when falling back, refusing a lease, or resolving nothing: reason + remediation
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
// do, a Lima target falls back to the Lima-forwarded loopback with the
// classification of the first probe failure — the informative one, since
// candidate 1 is the address the user's own tooling reports. Any other
// provider returns an empty Endpoint (SourceUnresolved) carrying that same
// classification: the loopback port is Lima's, not theirs.
//
// Resolve keeps the historical two-argument shape for callers that have no
// trust configuration to express; ResolveTarget is the full form.
func Resolve(vmName string, port uint16) Resolution {
	return ResolveTarget(Target{VM: vmName}, port)
}

// Test seams: the limactl candidate source, the DHCP lease db location and the
// reachability probe are the resolver's three inputs from the machine. They
// are package variables only so the table tests can drive every branch
// without a VM; nothing outside this package's tests assigns them.
var (
	guestIPFn  = guestIP
	leasesPath = LeasesPath
	probeDial  = net.DialTimeout
)

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
	// fallback is the end of the road: nothing answered. Lima has the SSH
	// forward on loopback; every other provider gets no endpoint at all
	// rather than a port some other VM owns (Target.Provider).
	fallback := func(d diagnosis) Resolution {
		if t.mayUseLoopbackForward() {
			return Resolution{
				Endpoint: "tcp://" + net.JoinHostPort(loopbackHost, p),
				Source:   SourceSSHForwarder,
				Note:     withNotes(d.note),
			}
		}
		return Resolution{Source: SourceUnresolved, Note: withNotes(noteNoFallback(t, p, d))}
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
	if ip, err := guestIPFn(t); err == nil {
		add(ip, SourceVZNATDirect)
	}
	leased, notes, leasesErr := leaseCandidates(leasesPath, t)
	leaseNotes = notes
	for _, ip := range leased {
		add(ip, SourceVZNATLeases)
	}
	if len(leased) > 0 && t.HWAddr == "" {
		nameOnlyOnce.Do(func() { log.Printf("drawbridge: warning: %s", noteNameOnlyMatching(t)) })
	}
	if len(cands) == 0 {
		if leasesErr != nil {
			return fallback(diagnoseNoLeases(leasesPath, leasesErr))
		}
		return fallback(diagnoseNoGuestIP())
	}

	var (
		firstErr  error
		firstAddr string
	)
	for _, c := range cands {
		addr := net.JoinHostPort(c.ip, p)
		conn, err := probeDial("tcp", addr, probeTimeout)
		if err != nil {
			if firstErr == nil {
				firstErr, firstAddr = err, addr
			}
			continue
		}
		conn.Close()
		return Resolution{Endpoint: "tcp://" + addr, Source: c.source, Note: withNotes("")}
	}
	return fallback(diagnoseProbe(firstAddr, firstErr))
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
//
// Each is a cause plus the sentence about what happens next. The cause is
// kept separate so a target with no loopback forward to fall back to
// (noteNoFallback) can say the same thing without promising a fallback it
// does not have. The composed constants are byte-identical to what they were
// before the split.
const (
	causeLocalNetworkDenied = "host→guest vzNAT blocked — likely macOS Local Network permission. " +
		"Grant it in System Settings → Privacy & Security → Local Network for your terminal app " +
		"(CLI tools inherit the terminal's grant) and/or drawbridged if listed; a cached denial may " +
		"need the app relaunched or a reboot."
	causeAgentNotListening = "agent not reachable on the vzNAT address — is `just agent-up` current?"
	causeNoGuestIP         = "no host-reachable guest IP (vzNAT missing?)"

	// NoteLocalNetworkDenied: the route and the ARP entry exist, the guest
	// is up, and the SYN still cannot leave the host — on macOS that is the
	// Local Network privacy gate, not a network fault.
	NoteLocalNetworkDenied = causeLocalNetworkDenied + " Falling back to the SSH forwarder (slower, shared tunnel)."

	// NoteAgentNotListening: the host reached the guest and got either
	// silence (no listener on that address, packets dropped) or an active
	// refusal — the agent is stale, down, or bound loopback-only.
	NoteAgentNotListening = causeAgentNotListening + " Falling back to the SSH forwarder."

	// NoteNoGuestIP: no vzNAT address to probe at all.
	NoteNoGuestIP = causeNoGuestIP + " — falling back to the SSH forwarder."
)

// diagnosis is one classified failure in both spellings: note is the Lima
// text (cause plus "falling back to the SSH forwarder"), cause is the same
// diagnosis as a sentence with no promise attached.
type diagnosis struct{ cause, note string }

// noteNoFallback is the Resolution.Note for a target that is not a Lima
// instance and found nothing to dial. It states the cause, then the refusal:
// the loopback port belongs to a Lima VM, and dialing it would attach a root
// daemon to that VM in place of this one (audit NEW-X1). The retry clause is
// accurate: drawbridged re-resolves on every session reconnect.
func noteNoFallback(t Target, port string, d diagnosis) string {
	what := t.Provider + " instance " + t.VM
	return fmt.Sprintf("no endpoint for %s: %s Not falling back to %s: it is a Lima VM's SSH forward, not this "+
		"VM's, and would reach whichever Lima instance owns it. Start the VM; drawbridged retries on its own.",
		what, d.cause, net.JoinHostPort(loopbackHost, port))
}

// classifyProbe explains a failed vzNAT probe. It is deliberately a single
// seam: the EHOSTUNREACH / timeout / ECONNREFUSED classification table in
// docs/transport.md §2.2 lands here, and nothing else in the resolver has
// to change for it.
//
// The errors arrive wrapped (*net.OpError around *os.SyscallError around a
// syscall.Errno), so every test is errors.Is / errors.As, never a string
// match on the message.
func classifyProbe(addr string, err error) string { return diagnoseProbe(addr, err).note }

func diagnoseProbe(addr string, err error) diagnosis {
	switch {
	case errors.Is(err, syscall.EHOSTUNREACH):
		return diagnosis{causeLocalNetworkDenied, NoteLocalNetworkDenied}
	case errors.Is(err, syscall.ECONNREFUSED), isTimeout(err):
		return diagnosis{causeAgentNotListening, NoteAgentNotListening}
	}
	// Unclassified: keep the raw diagnosis rather than guess at a remedy.
	cause := fmt.Sprintf("vzNAT endpoint %s not reachable (%v)", addr, err)
	return diagnosis{cause + ".", cause + " — falling back to the SSH forwarder (slower, shared tunnel)."}
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
func classifyNoGuestIP() string { return diagnoseNoGuestIP().note }

func diagnoseNoGuestIP() diagnosis {
	return diagnosis{causeNoGuestIP + ".", NoteNoGuestIP}
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
