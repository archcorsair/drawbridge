package macsync

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/proxy"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/udpframe"
)

// event is one JSON line on the 'M' stream (same shape as the agent's
// transport events, direction reversed: Mac → guest).
type event struct {
	Op        string     `json:"op"` // snapshot | add | del | ping
	Proto     string     `json:"proto,omitempty"`
	Port      uint16     `json:"port,omitempty"`
	Addr      string     `json:"addr,omitempty"`
	Listeners []Listener `json:"listeners,omitempty"`
}

// Syncer streams the Mac's listener set to the guest agent ('M') and keeps
// parked reverse-stream connections ('D') that the guest's gateway proxies
// activate to reach Mac loopback services.
type Syncer struct {
	AgentAddr string                              // agent transport endpoint (bare host:port accepted as tcp)
	Poll      func() ([]Listener, error)          // defaults to Listeners (darwin)
	Exclude   func(Listener) bool                 // extra exclusions (mirror-owned ports)
	Interval  time.Duration                       // poll cadence, default 75ms
	DialLocal func(port uint16) (net.Conn, error) // defaults to 127.0.0.1:port
	PoolSize  int                                 // parked 'D' conns, default DefaultPoolSize

	// UDPPorts are Mac UDP services to offer the guest, synced
	// unconditionally as udp 0.0.0.0:P (docs/udp.md: no liveness probe —
	// if nothing is bound, guest datagrams drop, which is honest UDP).
	// Explicit configuration only: udp.pcblist_n has no LISTEN state, so
	// auto-discovery is deferred (U5).
	UDPPorts []uint16
	// DialLocalUDP opens the per-flow socket to a local UDP service;
	// defaults to a connected socket to 127.0.0.1:port. Test seam.
	DialLocalUDP func(port uint16) (*net.UDPConn, error)

	// ReResolve, when non-nil, is consulted after a dropped 'M' session and
	// returns the endpoint to use for the next attempt — the same hook
	// mirror.Client carries, wired by drawbridged to one shared resolution
	// so a startup fallback to the SSH forwarder heals to vznat-direct
	// without a restart (docs/transport.md §2.2).
	ReResolve func() string

	// Auth carries the transport secret and the context its refusal lines
	// need (docs/transport-auth.md §6–§7). The zero value is unauthenticated
	// mode: today's wire, byte-identical.
	Auth transportauth.MacConfig

	// Refusals, when set, receives the ID-tagged refusal lines this syncer
	// logs (docs/doctor.md §3.2). Nil-safe: the package stays
	// daemon-independent, and tests inject their own ring.
	Refusals *introspect.Ring

	curAddr atomic.Pointer[string] // last ReResolve result; nil ⇒ AgentAddr

	// Introspection counters: conns currently parked waiting for an
	// activation header, and whether the 'M' session is up.
	parked    atomic.Int64
	sessionUp atomic.Bool

	// advertised is the set of (proto, port) pairs this syncer most recently
	// offered the guest — the bound handleStream dials within (Q8 c,
	// docs/transport-auth.md §7). Primed in Run before the pool loops start
	// (else the first poll interval refuses legitimate activations) and kept
	// across 'M' session drops (parked conns outlive an 'M' blip; the agent
	// independently drops sync-owned mac_ports when the conn dies, so
	// staleness is bounded by the reconnect).
	advertised atomic.Pointer[map[advKey]struct{}]

	// lastEmptiedLog throttles the non-empty→empty advertised-set line to
	// one per 30s (§7 discipline — the edge can flap under a churning
	// poller). Plain field: setAdvertised runs only on Run's goroutine.
	lastEmptiedLog time.Time

	logf func(string, ...any) // test seam; nil ⇒ log.Printf
}

// advKey is a normalized advertisement: the wire's proto byte (6/17) and the
// port, which is all an activation header names.
type advKey struct {
	proto uint8
	port  uint16
}

func advKeyOf(l Listener) (advKey, bool) {
	switch l.Proto {
	case "tcp":
		return advKey{6, l.Port}, true
	case "udp":
		return advKey{17, l.Port}, true
	}
	return advKey{}, false
}

// authRefused logs a pool-path handshake failure and returns it. The pool
// dials once per second per loop, so these lines are throttled (§7) — unlike
// the 'M' session's, which the reconnect loop already paces.
func (s *Syncer) authRefused(err error) error {
	ep := s.addr()
	if line := s.Auth.Report(err, ep); line != "" {
		s.log("drawbridged: macsync: %s", line)
	}
	return s.Auth.Wrap(err, ep)
}

// Snapshot is the introspection view of this syncer (docs/doctor.md §3.2):
// what the guest is currently allowed to activate, the explicitly configured
// UDP ports, how many reverse-stream conns are parked, and whether the 'M'
// session is up.
func (s *Syncer) Snapshot() introspect.Sync {
	out := introspect.Sync{
		SessionUp:  s.sessionUp.Load(),
		PoolParked: int(s.parked.Load()),
		UDPPorts:   append([]uint16(nil), s.UDPPorts...),
	}
	if adv := s.advertised.Load(); adv != nil {
		for k := range *adv {
			out.Advertised = append(out.Advertised, introspect.Advertised{Proto: protoName(k.proto), Port: k.port})
		}
	}
	sort.Slice(out.Advertised, func(i, j int) bool {
		if out.Advertised[i].Proto != out.Advertised[j].Proto {
			return out.Advertised[i].Proto < out.Advertised[j].Proto
		}
		return out.Advertised[i].Port < out.Advertised[j].Port
	})
	sort.Slice(out.UDPPorts, func(i, j int) bool { return out.UDPPorts[i] < out.UDPPorts[j] })
	return out
}

// protoName spells the wire's proto byte the way the payload does.
func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return "proto-" + strconv.Itoa(int(p))
}

func (s *Syncer) log(format string, args ...any) {
	if s.logf != nil {
		s.logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// setAdvertised publishes the set the guest may activate against.
func (s *Syncer) setAdvertised(set map[Listener]struct{}) {
	adv := make(map[advKey]struct{}, len(set))
	for l := range set {
		if k, ok := advKeyOf(l); ok {
			adv[k] = struct{}{}
		}
	}
	prev := s.advertised.Swap(&adv)
	if len(adv) == 0 && prev != nil && len(*prev) > 0 && s.sessionUp.Load() {
		s.noteEmptied(len(*prev))
	}
}

// noteEmptied is the non-empty→empty transition alarm: an empty advertised
// set refuses every reverse activation (§7), so a healthy session that
// suddenly offers nothing deserves its line — either every Mac listener
// really closed at once, or the listener poll returned a torn result
// (2026-08-01: a live daemon showed adv 0 for 28s while parked and synced).
func (s *Syncer) noteEmptied(had int) {
	now := time.Now()
	if now.Sub(s.lastEmptiedLog) < 30*time.Second {
		return
	}
	s.lastEmptiedLog = now
	line := fmt.Sprintf("advertised set went %d -> 0 while the 'M' session is up — every reverse activation will be refused until listeners reappear; if Mac listeners did not all just close, suspect a torn listener poll (the next tick heals it; 'drawbridge doctor' shows the live set)", had)
	s.log("drawbridged: macsync: %s", line)
	s.Refusals.Record(introspect.IDAdvertisedEmptied, line)
}

// noteEmptySession fires when a session is established advertising nothing —
// the shape noteEmptied cannot catch (a daemon gated from birth never makes
// the non-empty→empty transition), and the shape the 2026-08-01 incident
// actually had: on macOS 27.0b4 an unprivileged daemon launched from a
// terminal receives a per-responsible-app-filtered pcblist — empty, no error
// — while a Mac never legitimately has zero LISTEN sockets
// (local-network-permission.md finding 5). Once per established session:
// reconnects are second-paced and a healthy-but-gated session stays up, so
// this cannot spam.
func (s *Syncer) noteEmptySession() {
	line := "session established advertising no Mac listeners — the enumeration returned zero LISTEN sockets, which a Mac never legitimately has; " +
		"a terminal-launched daemon on macOS 27.0b4 gets a per-responsible-app-filtered pcblist (local-network-permission.md finding 5) — `sudo drawbridge install` runs exempt"
	s.log("drawbridged: macsync: %s", line)
	s.Refusals.Record(introspect.IDAdvertisedNone, line)
}

// isAdvertised reports whether an activation names something we offered. An
// unprimed set (Run has not reached its first poll) refuses everything, which
// is why Run primes before parking anything.
func (s *Syncer) isAdvertised(proto uint8, port uint16) bool {
	adv := s.advertised.Load()
	if adv == nil {
		return false
	}
	_, ok := (*adv)[advKey{proto, port}]
	return ok
}

// addr is the endpoint the 'M' session and every parked 'D' dial use.
// AgentAddr stays the configured value; only ReResolve moves the target,
// through an atomic because poolSize() park loops dial concurrently.
func (s *Syncer) addr() string {
	if p := s.curAddr.Load(); p != nil {
		return *p
	}
	return s.AgentAddr
}

// refreshAddr re-runs the hook between session attempts.
func (s *Syncer) refreshAddr() {
	if s.ReResolve == nil {
		return
	}
	if a := s.ReResolve(); a != "" {
		s.curAddr.Store(&a)
	}
}

// DefaultPoolSize per the burst benchmark (2026-07-30): pop stays fast at
// every tested wave size (connect p50 ≤ ~150µs at k=32), so the pool is not
// the burst bottleneck at ≥4 — the shared forwarded transport is. 8 buys
// tail headroom for parallel-connect patterns (browsers, db pools) at the
// cost of four idle conns; raising it further is not what improves bursts.
const DefaultPoolSize = 8

func (s *Syncer) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return 75 * time.Millisecond
}

func (s *Syncer) poolSize() int {
	if s.PoolSize > 0 {
		return s.PoolSize
	}
	return DefaultPoolSize
}

func (s *Syncer) poll() ([]Listener, error) {
	if s.Poll != nil {
		return s.Poll()
	}
	return Listeners()
}

func (s *Syncer) dialLocal(port uint16) (net.Conn, error) {
	if s.DialLocal != nil {
		return s.DialLocal(port)
	}
	return net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
}

func (s *Syncer) dialLocalUDP(port uint16) (*net.UDPConn, error) {
	if s.DialLocalUDP != nil {
		return s.DialLocalUDP(port)
	}
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, err
	}
	// macOS caps a UDP send at the socket's send-buffer size (seeded from
	// net.inet.udp.maxdgram, ~9216): without this, any guest datagram over
	// ~9 KiB dies EMSGSIZE on the delivery hop. Best-effort — the sysctl
	// does not gate SO_SNDBUF raises.
	uc.SetWriteBuffer(udpframe.MaxPayload)
	return uc, nil
}

// Run maintains the event session and the dial pool, reconnecting with
// backoff, until ctx is done.
func (s *Syncer) Run(ctx context.Context) error {
	// Prime the advertised set before any 'D' conn can be parked: a guest
	// gateway proxy can activate one the moment it is parked, and an empty
	// set refuses everything (§7).
	if set, err := s.currentSet(); err == nil {
		s.setAdvertised(set)
	} else {
		s.setAdvertised(nil) // an empty set, not a nil pointer: refuse, don't panic
	}
	for i := 0; i < s.poolSize(); i++ {
		go s.poolLoop(ctx)
	}
	for {
		if err := s.session(ctx); err != nil && ctx.Err() == nil {
			// The reconnect loop paces this line at one per second, so the
			// session's own auth diagnosis (§7 rows 4–5) rides it unthrottled.
			s.log("drawbridged: macsync session: %v (reconnecting)", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		s.refreshAddr()
	}
}

var (
	v4Loopback = netip.MustParseAddr("127.0.0.1")
	v4Any      = netip.MustParseAddr("0.0.0.0")
	v6Any      = netip.MustParseAddr("::")
)

// normalize maps a raw Mac listener to what we sync, or reports false.
// Phase 3 scope is the v4 path: dual-stack :: binds accept v4 (the Mac-side
// backend dial is 127.0.0.1) and become v4-any keys, so guest v6 connects
// keep native semantics; ::1-only and LAN-scoped binds are skipped.
func (s *Syncer) normalize(l Listener) (Listener, bool) {
	if l.Proto != "tcp" || l.Port == 0 {
		return l, false
	}
	switch l.Addr {
	case v4Loopback, v4Any:
	case v6Any:
		l.Addr = v4Any
	default:
		return l, false
	}
	if s.Exclude != nil && s.Exclude(l) {
		return l, false
	}
	return l, true
}

func (s *Syncer) currentSet() (map[Listener]struct{}, error) {
	ls, err := s.poll()
	if err != nil {
		return nil, err
	}
	set := make(map[Listener]struct{}, len(ls))
	for _, l := range ls {
		if n, ok := s.normalize(l); ok {
			set[n] = struct{}{}
		}
	}
	// Explicitly configured Mac UDP services (normalize stays tcp-only for
	// polled listeners — the poller cannot tell a UDP server from a
	// transient client socket, so UDP is opt-in by port).
	for _, p := range s.UDPPorts {
		l := Listener{Proto: "udp", Port: p, Addr: v4Any}
		if p == 0 || (s.Exclude != nil && s.Exclude(l)) {
			continue
		}
		set[l] = struct{}{}
	}
	return set, nil
}

func (s *Syncer) session(ctx context.Context) error {
	conn, err := transport.Dial(s.addr())
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	sec, err := s.Auth.Secret()
	if err != nil {
		return s.Auth.Wrap(err, s.addr())
	}
	// Hello and proof in one Write, then the agent's proof before the
	// snapshot: 'M' poisons mac_ports, so not one advertisement crosses to an
	// unverified peer (§3.2).
	frame, err := transportauth.ClientHello(conn, sec, 'M', nil)
	if err != nil {
		return err
	}
	if err := transportauth.AwaitAgentProof(conn, sec, frame, transportauth.HandshakeTimeout); err != nil {
		return s.Auth.Wrap(err, s.addr())
	}
	// The agent never sends on 'M'; a pending read returns the moment the
	// peer closes (agent restart), so the session ends and re-snapshots
	// without waiting out the idle-ping interval. Started only after the
	// handshake, or it would swallow the agent's proof.
	peerClosed := make(chan struct{})
	go func() {
		io.Copy(io.Discard, conn)
		close(peerClosed)
	}()
	enc := json.NewEncoder(conn)
	last, err := s.currentSet()
	if err != nil {
		return err
	}
	snap := make([]Listener, 0, len(last))
	for l := range last {
		snap = append(snap, l)
	}
	if err := enc.Encode(event{Op: "snapshot", Listeners: snap}); err != nil {
		return err
	}
	s.setAdvertised(last)
	s.sessionUp.Store(true)
	defer s.sessionUp.Store(false)
	if len(last) == 0 {
		s.noteEmptySession()
	}
	tick := time.NewTicker(s.interval())
	defer tick.Stop()
	lastSent := time.Now()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-peerClosed:
			return fmt.Errorf("agent closed events conn")
		case <-tick.C:
		}
		cur, err := s.currentSet()
		if err != nil {
			return err // session restart re-snapshots, which heals any gap
		}
		for l := range last {
			if _, ok := cur[l]; !ok {
				if err := enc.Encode(event{Op: "del", Proto: l.Proto, Port: l.Port, Addr: l.Addr.String()}); err != nil {
					return err
				}
				lastSent = time.Now()
			}
		}
		for l := range cur {
			if _, ok := last[l]; !ok {
				if err := enc.Encode(event{Op: "add", Proto: l.Proto, Port: l.Port, Addr: l.Addr.String()}); err != nil {
					return err
				}
				lastSent = time.Now()
			}
		}
		last = cur
		// Publish what the guest has now been told. A del the guest has not
		// processed yet loses the race against an in-flight activation, and
		// that resolves as a refusal (row 7) — correct, and worth its line.
		s.setAdvertised(last)
		if time.Since(lastSent) > 10*time.Second {
			if err := enc.Encode(event{Op: "ping"}); err != nil {
				return err
			}
			lastSent = time.Now()
		}
	}
}

// poolLoop keeps one parked 'D' connection against the agent. When the guest
// activates it (writes the 4-byte {proto, port BE, reserved} header), the
// stream is handed off and a fresh connection is parked immediately.
func (s *Syncer) poolLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := s.parkOne(ctx); err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

func (s *Syncer) parkOne(ctx context.Context) error {
	conn, err := transport.Dial(s.addr())
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	sec, err := s.Auth.Secret()
	if err != nil {
		conn.Close()
		return s.authRefused(err)
	}
	// The whole exchange happens before the conn parks, so the parked wire is
	// byte-identical to the unauthenticated one: Mac silent, guest silent
	// until the 4-byte activation header (§3.3).
	frame, err := transportauth.ClientHello(conn, sec, 'D', nil)
	if err != nil {
		conn.Close()
		return err
	}
	if err := transportauth.AwaitAgentProof(conn, sec, frame, transportauth.HandshakeTimeout); err != nil {
		conn.Close()
		return s.authRefused(err)
	}
	var hdr [4]byte
	// Parked: the wire is silent in both directions until the guest writes
	// the activation header, so this read is exactly the parked lifetime.
	s.parked.Add(1)
	_, err = io.ReadFull(conn, hdr[:])
	s.parked.Add(-1)
	if err != nil {
		conn.Close()
		return err
	}
	if hdr[3] != 0 {
		// The activation header's reserved byte is the framing-version
		// escape hatch the agent has always enforced and this side never
		// did (§7 row 9): an incompatible future header must close the
		// conn, not be spliced as if it were understood.
		const line = "dropping reverse-stream conn: nonzero reserved byte in activation header (incompatible agent?)"
		s.log("drawbridged: macsync: %s", line)
		s.Refusals.Record(introspect.IDActivationReserved, line)
		conn.Close()
		return fmt.Errorf("activation header reserved byte %d", hdr[3])
	}
	go s.handleStream(conn, hdr[0], binary.BigEndian.Uint16(hdr[1:3]))
	return nil
}

func (s *Syncer) handleStream(conn net.Conn, proto uint8, port uint16) {
	if port == 0 {
		conn.Close()
		return
	}
	// Q8 (c): dial only what we advertised. This bounds the blast radius of
	// any peer confusion that survives transport auth — an authenticated but
	// wrong or buggy agent still cannot reach a Mac port the syncer never
	// offered (§7 row 7).
	if !s.isAdvertised(proto, port) {
		line := fmt.Sprintf("refused reverse dial to 127.0.0.1:%d (proto %d): not a port this Mac advertised — the guest asked for something the syncer never offered (agent bug or hostile peer); conn closed", port, proto)
		s.log("drawbridged: macsync: %s", line)
		s.Refusals.Record(introspect.IDReverseDialRefused, line)
		conn.Close()
		return
	}
	switch proto {
	case 6:
		b, err := s.dialLocal(port)
		if err != nil {
			// Backend gone between sync and connect: close, which the guest
			// proxy surfaces as connect-then-close (Phase 1 semantics).
			conn.Close()
			return
		}
		proxy.Splice(conn, b)
	case 17:
		// Framed datagrams (docs/udp.md): one socket per guest client to
		// the local service; the relay owns flow state and expiry.
		udpframe.RelayStream(conn, func() (*net.UDPConn, error) {
			return s.dialLocalUDP(port)
		})
	default:
		conn.Close()
	}
}
