// drawbridged is the Mac-side daemon. Phase 2: subscribe to the guest
// agent's listener events and mirror guest TCP listeners onto Mac
// localhost. Phase 3: the reverse — poll the Mac's own TCP listeners into
// the guest's mac_ports and serve reverse streams, so container connects to
// 127.0.0.1 reach native Mac services.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/macsync"
	"github.com/archcorsair/drawbridge/internal/mirror"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func main() {
	agentFlag := flag.String("agent", "auto", "guest agent transport endpoint (auto: vzNAT IP if reachable, else 127.0.0.1:4777; accepts tcp://host:port, unix:///path, or bare host:port)")
	vmName := flag.String("vm", install.DefaultVM, "VM to resolve, used by -agent auto: a bare name is a Lima instance; `provider:name` selects one explicitly (lima:myvm, colima:default)")
	vmMAC := flag.String("vm-mac", "", "guest's expected hardware address (e.g. 52:55:55:a5:de:d2); DHCP lease records that do not match it are ignored. Unset matches lease records by the guest-chosen name alone")
	vmSubnet := flag.String("vm-subnet", "", "vmnet subnet a DHCP lease address must fall inside (default "+limaaddr.DefaultSubnet+"); only needed when this Mac's vmnet is configured elsewhere")
	mirrorIP := flag.String("mirror-ip", "127.0.0.1", "local address to bind mirrors on")
	udpFlag := flag.String("udp", "", "comma-separated Mac UDP ports to offer the guest (explicit only; UDP has no LISTEN state to discover)")
	secretFile := flag.String("secret-file", "",
		"transport secret file (64 hex characters, mode 0600); default is the per-VM file `drawbridge up` writes under ~/Library/Application Support/drawbridge. Passing a path that does not exist is fatal")
	skipFlag := flag.String("skip", defaultSkip, "comma-separated ports to leave alone in BOTH directions: guest listeners on them are not mirrored, Mac listeners on them are not synced into the guest. Passing a list replaces the default; -skip \"\" skips nothing")
	introspectFlag := flag.String("introspect", "auto", "read-only introspection socket: `auto` (the per-euid default path), `off`, or an explicit unix socket path. The daemon writes one JSON state snapshot per connection and never reads a byte from it")
	versionFlag := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	started := time.Now()

	// Same spelling as `drawbridge version`, on stdout, so the CLI can read
	// the installed daemon's version back out of it (ergonomics.md §5 check 9).
	if *versionFlag {
		fmt.Println("drawbridged", buildinfo.Version)
		return
	}

	if err := checkMirrorIP(os.Geteuid(), *mirrorIP); err != nil {
		log.Fatalf("drawbridged: %v", err)
	}
	log.Printf("drawbridged: version %s", buildinfo.Version)

	udpPorts, err := parsePorts(*udpFlag)
	if err != nil {
		log.Fatalf("drawbridged: -udp: %v", err)
	}
	skipPorts, err := parsePorts(*skipFlag)
	if err != nil {
		log.Fatalf("drawbridged: -skip: %v", err)
	}
	skip := portSet(skipPorts)
	if len(skip) == 0 {
		log.Printf("drawbridged: skip-list: empty — every guest and Mac listener is in scope")
	} else {
		log.Printf("drawbridged: skip-list: %s ignored in both directions (not mirrored, not synced); -skip replaces the list, -skip \"\" empties it", *skipFlag)
	}

	// -vm is parsed once, here, into everything resolution needs: the Lima
	// instance to shell into, the DHCP record name to match, and the
	// LIMA_HOME limactl runs under (colima's instances live under their
	// own). Parsing is pure — vmprovider's limactl half is user-scoped and
	// this daemon usually runs as root, which is exactly why the lease db
	// stays its resolution source.
	ref, err := vmprovider.ParseRef(*vmName)
	if err != nil {
		log.Fatalf("drawbridged: -vm: %v", err)
	}

	// Transport auth (docs/transport-auth.md §5–§6). The default path is
	// derived from the canonical -vm ref — the same derivation `up` writes
	// with, so provisioner and daemon agree by construction — and under sudo
	// it resolves to the invoking user's home, not root's.
	secretPath, explicitSecret := *secretFile, *secretFile != ""
	if !explicitSecret {
		p, err := transportauth.PathForRef(ref)
		if err != nil {
			log.Printf("drawbridged: warning: cannot derive the transport secret path (%v)", err)
		} else {
			secretPath = p
		}
	}
	// One ring for the whole daemon, shared by both directions and the auth
	// throttle: the introspection payload's recentRefusals is a single
	// chronology, and it is the only auth evidence a foreground daemon (no
	// log file) can offer doctor.
	ring := &introspect.Ring{}
	auth := transportauth.MacConfig{
		SecretFile: secretPath,
		VM:         ref.Spec,
		Throttle:   transportauth.NewThrottle(transportauth.RefusalLogEvery),
		Refusals:   ring,
	}
	secret, err := transportauth.LoadOptional(secretPath)
	if err != nil {
		log.Fatalf("drawbridged: %v — the transport secret must be 64 hex characters, mode 0600; re-run `drawbridge up %s` to reprovision", err, ref.Spec)
	}
	switch {
	case secret != nil:
		log.Printf("drawbridged: transport auth: enabled (%s)", secretPath)
	case explicitSecret:
		// An explicit flag states intent; degrading to unauthenticated
		// silently would be the forbidden weakening (§5).
		log.Fatalf("drawbridged: -secret-file %s: no such file — pass a path that exists, or omit the flag to use the per-VM default; `drawbridge up %s` writes it", secretPath, ref.Spec)
	default:
		lookedFor := secretPath
		if lookedFor == "" {
			lookedFor = "no path could be derived"
		}
		log.Printf("drawbridged: transport auth: no secret configured (looked for %s) — transport is UNAUTHENTICATED; any process that reaches it is trusted. Run `drawbridge up %s` to provision one", lookedFor, ref.Spec)
	}

	// A malformed -vm-mac or -vm-subnet is fatal rather than ignored: both
	// are trust narrowing, and silently dropping one would leave an operator
	// believing the daemon is pinned when it is not.
	target := limaaddr.Target{VM: ref.Instance, LeaseName: ref.LeaseName, LimaHome: ref.LimaHome}
	if ref.Spec != ref.Instance {
		// Only when the spelling and the instance differ, i.e. a provider ref
		// was given. The mapping (colima:default → the Lima instance `colima`
		// → the DHCP record `colima`, prefixless because colima names its
		// guest after the instance) is not guessable from the flag value, and
		// a resolver note naming a record nobody asked for is the confusing
		// half of every wrong--vm report.
		log.Printf("drawbridged: -vm %s → %s instance %s (DHCP lease record %s)", ref.Spec, ref.Provider, ref.Instance, ref.LeaseName)
	}
	if *vmMAC != "" {
		hw, err := limaaddr.ParseHWAddr(*vmMAC)
		if err != nil {
			log.Fatalf("drawbridged: -vm-mac: %v", err)
		}
		target.HWAddr = hw
	}
	if *vmSubnet != "" {
		p, err := limaaddr.ParseSubnet(*vmSubnet)
		if err != nil {
			log.Fatalf("drawbridged: -vm-subnet: %v", err)
		}
		target.Subnet = p
	}

	addr, source, note := *agentFlag, "flag", ""
	if addr == "auto" {
		r := limaaddr.ResolveTarget(target, 4777)
		addr, source, note = r.Endpoint, r.Source, r.Note
		if r.Note != "" {
			log.Printf("drawbridged: warning: %s", r.Note)
		}
	}
	ep, err := transport.Parse(addr)
	if err != nil {
		log.Fatalf("drawbridged: -agent: %v", err)
	}
	agentAddr := ep.String()
	agentPort := ep.Port()

	// Re-resolve hook (docs/transport.md §2.2): when -agent auto fell back to
	// the forwarder, a session reconnect re-runs Resolve so a permission
	// grant — or an agent that has since bound its vzNAT address — heals to
	// vznat-direct without restarting drawbridged. One shared resolver
	// behind one atomic string, handed to both the mirror ('E') and the
	// syncer ('M'); nil when -agent is explicit, since the user pinned it.
	// curSource is what row 5 names: a wrong-peer refusal has to say whether
	// the endpoint came from vznat-direct, the loopback forwarder, or -agent.
	var reResolve func() string
	curSource := func() string { return source }
	// resolution is what the introspection payload reports: the *live*
	// endpoint, source and note, which is precisely what `status` could never
	// reconstruct from launchctl and a log file.
	resolution := func() introspect.Resolution {
		return introspect.Resolution{Endpoint: agentAddr, Source: source, Note: note, ResolvedAt: started}
	}
	if *agentFlag == "auto" {
		r := newResolver(target, agentPort, agentAddr, source, note)
		reResolve, curSource, resolution = r.refresh, r.currentSource, r.resolution
	}
	auth.Source = curSource

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m := mirror.New(agentAddr, *mirrorIP)
	m.ReResolve = reResolve
	m.Skip = skip
	m.Auth = auth
	m.Refusals = ring
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		ReResolve: reResolve,
		Exclude:   newExclude(agentPort, skip, m.Mirrors),
		UDPPorts:  udpPorts,
		Auth:      auth, // one config, one throttle: the daemon speaks once per cause
		Refusals:  ring,
	}

	snapshot := func() introspect.State {
		return introspect.State{
			Schema:         introspect.Schema,
			Version:        buildinfo.Version,
			PID:            os.Getpid(),
			EUID:           os.Geteuid(),
			StartedAt:      started,
			VM:             introspect.VM{Ref: ref.Spec, Provider: ref.Provider, Instance: ref.Instance},
			MirrorIP:       *mirrorIP,
			Resolution:     resolution(),
			Auth:           authState(secretPath),
			Mirror:         m.Snapshot(),
			Sync:           s.Snapshot(),
			RecentRefusals: ring.Snapshot(),
		}
	}
	if srv := serveIntrospection(ctx, *introspectFlag, ref, snapshot); srv != nil {
		defer srv.Close()
	}

	log.Printf("drawbridged: agent %s (source=%s); mirroring guest listeners onto %s; syncing Mac listeners into the guest", agentAddr, source, *mirrorIP)
	go m.Run(ctx)
	s.Run(ctx)
}

// serveIntrospection starts the read-only snapshot socket (docs/doctor.md
// §3). It is an enrichment tier, never a dependency: every failure here is a
// log line and a daemon that goes on mirroring, because a Mac that cannot
// bind a diagnostic socket still wants its ports forwarded.
func serveIntrospection(ctx context.Context, flagValue string, ref vmprovider.Ref, snapshot func() introspect.State) *introspect.Server {
	if flagValue == "off" {
		log.Printf("drawbridged: introspection: off (-introspect off) — `drawbridge doctor` and `status` fall back to inference")
		return nil
	}
	path := flagValue
	if flagValue == "auto" {
		p, err := introspect.AutoPath(os.Geteuid(), ref)
		if err != nil {
			log.Printf("drawbridged: introspection disabled: cannot derive the socket path (%v)", err)
			return nil
		}
		path = p
	}
	srv, err := introspect.Listen(path, os.Geteuid(), snapshot)
	if err != nil {
		log.Printf("drawbridged: introspection disabled: %v", err)
		return nil
	}
	if srv.Note != "" {
		log.Printf("drawbridged: introspection: warning: %s", srv.Note)
	}
	log.Printf("drawbridged: introspection: %s (one state snapshot per connection; the daemon never reads from it)", srv.Path())
	context.AfterFunc(ctx, func() { srv.Close() })
	go srv.Serve()
	return srv
}

// authState reports the transport-auth posture for a snapshot: the mode, the
// path, and whether the file there is usable. Re-read per snapshot, like
// every per-conn read, so a rotation or a broken file shows up without a
// restart. Bytes, proofs, and digests never enter the payload — doctor
// compares digests itself, directly against the files.
func authState(path string) introspect.Auth {
	a := introspect.Auth{Mode: introspect.AuthModeNone, SecretPath: path, SecretState: introspect.SecretAbsent}
	switch sec, err := transportauth.LoadOptional(path); {
	case err != nil:
		a.Mode, a.SecretState = introspect.AuthModeStaticHMACv1, introspect.SecretMalformed
	case sec != nil:
		a.Mode, a.SecretState = introspect.AuthModeStaticHMACv1, introspect.SecretOK
	}
	return a
}

// defaultSkip is the shipped skip-list (docs/ergonomics.md §7). `22` only:
// syncing the Mac's Remote Login into the guest's mac_ports would steer an
// in-guest `ssh localhost` at the Mac's sshd, which is the one default worth
// paying for. Nothing speculative goes here — a list users have come to
// depend on is not cheap to shrink. install.DefaultSkip carries the same
// value for the plist, exactly as install.DefaultVM mirrors -vm's default.
const defaultSkip = install.DefaultSkip

// parsePorts is the daemon's comma-separated port-list parser, shared by
// -udp and -skip so the two flags cannot drift. install.ParsePorts is the
// same code because `drawbridge install` must never render a value this
// daemon would reject at boot.
func parsePorts(s string) ([]uint16, error) { return install.ParsePorts("", s) }

func portSet(ports []uint16) map[uint16]bool {
	set := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		set[p] = true
	}
	return set
}

// newExclude builds the syncer's exclusion predicate: our own infrastructure
// (the forwarded agent port and the mirrors of guest listeners, which would
// bounce guest traffic through the Mac) plus the skip-list.
//
// The skip-list's other half. The mirror direction logs every skip on the
// spot, but this side is polled every 75ms against the Mac's whole listener
// table, so per-decision logging would be a firehose: each skipped port is
// announced once per process instead. Silence here would be its own bug
// report — "why can't my container reach the Mac's sshd" has to be
// answerable from the log.
func newExclude(agentPort uint16, skip map[uint16]bool, mirrored func(string, uint16) bool) func(macsync.Listener) bool {
	var (
		mu   sync.Mutex
		said = map[macsync.Listener]bool{}
	)
	return func(l macsync.Listener) bool {
		if skip[l.Port] {
			key := macsync.Listener{Proto: l.Proto, Port: l.Port}
			mu.Lock()
			first := !said[key]
			said[key] = true
			mu.Unlock()
			if first {
				log.Printf("drawbridged: sync: not syncing Mac %s :%d into the guest (skip-list; -skip to override)", l.Proto, l.Port)
			}
			return true
		}
		return l.Port == agentPort || mirrored(l.Proto, l.Port)
	}
}

// checkMirrorIP enforces the standing invariant — mirrors bind 127.0.0.1
// only — as a hard gate when we are root. Unprivileged, a wildcard
// -mirror-ip is the operator's own foot and stays allowed (it is how the
// harness binds on odd interfaces); as root it would expose every guest
// listener on every interface of the machine, which is a different product.
// There is deliberately no override flag: root has no legitimate reason to
// want it, so the answer is "run it unprivileged", not "pass --i-mean-it".
//
// Anything that is not provably a loopback literal is refused under root,
// including a hostname: the check has to be decidable without a resolver in
// the path, and "" means wildcard.
func checkMirrorIP(euid int, mirrorIP string) error {
	if euid != 0 {
		return nil
	}
	if ip := net.ParseIP(mirrorIP); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-mirror-ip %q: as root, mirrors may only bind loopback (127.0.0.1 or ::1). "+
		"Binding guest listeners onto a non-loopback address as root would publish them to the network; "+
		"run drawbridged unprivileged if you really want that", mirrorIP)
}

// resolver is the shared re-resolve hook plus the two read-only views the
// rest of the daemon takes off it: the current source, which the refusal
// lines name (§7 row 5), and the whole resolution, which the introspection
// snapshot publishes.
//
// Both the 'E' and 'M' reconnect loops call refresh, so the work is coalesced
// behind a mutex and a minimum interval — Resolve shells out to limactl and
// probes with an 800ms timeout, and while the agent is down both loops retry
// every second. Endpoint flips are logged once, keyed on the source changing:
// that line is the only externally visible evidence that a fallback healed.
type resolver struct {
	target limaaddr.Target
	port   uint16

	mu     sync.Mutex
	cur    string
	source string
	note   string
	at     time.Time // when the current resolution was produced
	last   time.Time // when refresh last ran, for coalescing
}

const resolveMinInterval = 3 * time.Second

func newResolver(target limaaddr.Target, port uint16, startAddr, startSource, startNote string) *resolver {
	return &resolver{target: target, port: port, cur: startAddr, source: startSource, note: startNote, at: time.Now()}
}

func (r *resolver) currentSource() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.source
}

func (r *resolver) resolution() introspect.Resolution {
	r.mu.Lock()
	defer r.mu.Unlock()
	return introspect.Resolution{Endpoint: r.cur, Source: r.source, Note: r.note, ResolvedAt: r.at}
}

func (r *resolver) refresh() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.last.IsZero() && time.Since(r.last) < resolveMinInterval {
		return r.cur
	}
	r.last = time.Now()
	res := limaaddr.ResolveTarget(r.target, r.port)
	ep, err := transport.Parse(res.Endpoint)
	if err != nil {
		return r.cur // keep what works rather than act on a malformed probe
	}
	if res.Source != r.source {
		log.Printf("drawbridged: agent transport %s (source=%s) → %s (source=%s)", r.cur, r.source, ep.String(), res.Source)
		if res.Note != "" {
			log.Printf("drawbridged: warning: %s", res.Note)
		}
		r.source = res.Source
	}
	r.cur, r.note, r.at = ep.String(), res.Note, r.last
	return r.cur
}
