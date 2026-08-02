// Package mirror is the Mac-side client: it subscribes to the guest agent's
// listener-event stream and mirrors guest TCP listeners onto local
// addresses, splicing each accepted connection back over the transport.
// Portable Go — runs on macOS (drawbridged) and in tests anywhere.
package mirror

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/proxy"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// event mirrors agent.TransportEvent (that package is linux-only).
type event struct {
	Op        string         `json:"op"`
	Proto     string         `json:"proto,omitempty"`
	Port      uint16         `json:"port,omitempty"`
	Addr      string         `json:"addr,omitempty"`
	Listeners []listenerInfo `json:"listeners,omitempty"`
}

type listenerInfo struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
	Addr  string `json:"addr"`
}

type mirrorEntry struct {
	stop    func() // closes the TCP listener or the UDP socket+stream
	refs    int
	pending bool      // Phase 4 reservation awaiting its listener event
	since   time.Time // when this mirror was opened (introspection)
}

// observed is a non-bound outcome for a port — skipped by the skip-list, or a
// bind we lost — and when it was entered. Bound entries are deliberately not
// tracked here: they are read off c.mirrors, which is authoritative and
// cannot go stale behind a missed transition.
type observed struct {
	state string
	since time.Time
}

// mirrorKey identifies one mirror: a guest TCP and UDP listener on the
// same port are independent mirrors.
type mirrorKey struct {
	proto string
	port  uint16
}

// Client maintains mirror listeners against one agent transport endpoint.
type Client struct {
	AgentAddr  string        // agent transport endpoint (bare host:port accepted as tcp)
	MirrorIP   string        // where mirrors bind, normally 127.0.0.1
	ReserveTTL time.Duration // pending-reservation lifetime, default 10s

	// ReResolve, when non-nil, is consulted after a dropped 'E' session and
	// returns the endpoint to use for the next attempt. It exists for one
	// scenario: the transport resolved to the SSH forwarder at startup
	// because vzNAT was unreachable, and the cause (macOS Local Network
	// permission, or an agent that had not bound vzNAT yet) is fixed while
	// drawbridged runs — the reconnect then heals to vznat-direct instead of
	// needing a restart. Deliberately one nullable field: cheap to delete.
	ReResolve func() string

	// Skip is drawbridged's port skip-list (-skip, default {22}): guest
	// listeners on these ports are not mirrored, and bind arbitration answers
	// "no Mac-side interest" for them so the guest bind proceeds on guest
	// semantics (without that, a Mac holding :22 for Remote Login would
	// EADDRINUSE a container's sshd — the pathology the list exists to avoid).
	//
	// The filter lives HERE, at the Mac-side consumer, and deliberately not in
	// the agent's event hub. AGENTS.md requires the 'E' stream to "filter
	// churn at the source and never drop silently"; that rule is about churn
	// (UDP autobind noise), whose only sane filter point is the source. A
	// skip-list is not churn: it is Mac-side policy over an event the stream
	// delivered correctly, and every skip is logged, so the mirror declines
	// audibly rather than dropping silently. Filtering in the hub instead
	// would push a Mac-side flag into the guest agent's configuration (making
	// a flag flip need a guest restart), hide the port from every other
	// subscriber, and turn a policy decision into exactly the silent drop the
	// invariant forbids.
	Skip map[uint16]bool

	// Auth carries the transport secret and the context its refusal lines
	// need (docs/transport-auth.md §6–§7). The zero value is unauthenticated
	// mode: today's wire, byte-identical.
	Auth transportauth.MacConfig

	// Refusals, when set, receives the ID-tagged skip and refusal lines this
	// client logs (docs/doctor.md §3.2). Nil-safe: the package stays
	// daemon-independent, and tests inject their own ring.
	Refusals *introspect.Ring

	agentPort uint16
	curAddr   atomic.Pointer[string] // last ReResolve result; nil ⇒ AgentAddr
	mu        sync.Mutex
	mirrors   map[mirrorKey]*mirrorEntry

	// Introspection state. obs has its own mutex because the skip and
	// bind-failure sites run outside c.mu; the lock order is c.mu → obsMu and
	// never the reverse.
	obsMu       sync.Mutex
	obs         map[mirrorKey]observed
	sessionUp   atomic.Bool
	lastEventAt atomic.Int64 // unix nanos; 0 ⇒ no event yet
}

// observe records a non-bound outcome, keeping the time of the transition
// into that state rather than the time of the latest repeat (a skip logs on
// every reconcile).
func (c *Client) observe(key mirrorKey, state string) {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()
	if c.obs == nil {
		c.obs = map[mirrorKey]observed{}
	}
	if cur, ok := c.obs[key]; ok && cur.state == state {
		return
	}
	c.obs[key] = observed{state: state, since: time.Now()}
}

// forget drops a port's non-bound outcome. Called when the mirror opens: a
// bind-failure that healed must not keep reporting itself.
func (c *Client) forget(key mirrorKey) {
	c.obsMu.Lock()
	defer c.obsMu.Unlock()
	delete(c.obs, key)
}

// Snapshot is the introspection view of this client (docs/doctor.md §3.2).
// Bound entries come from the live mirror table; skipped and bind-failed
// come from the observation map, so every state in the payload is one a call
// site actually reached.
func (c *Client) Snapshot() introspect.Mirror {
	m := introspect.Mirror{SessionUp: c.sessionUp.Load()}
	if ns := c.lastEventAt.Load(); ns != 0 {
		m.LastEventAt = time.Unix(0, ns)
	}
	bound := map[mirrorKey]bool{}
	c.mu.Lock()
	for key, e := range c.mirrors {
		bound[key] = true
		m.Entries = append(m.Entries, introspect.MirrorEntry{
			Proto: key.proto, Port: key.port, State: introspect.EntryBound, Since: e.since,
		})
	}
	c.mu.Unlock()
	c.obsMu.Lock()
	for key, o := range c.obs {
		if bound[key] {
			continue
		}
		m.Entries = append(m.Entries, introspect.MirrorEntry{
			Proto: key.proto, Port: key.port, State: o.state, Since: o.since,
		})
	}
	c.obsMu.Unlock()
	for p := range c.Skip {
		m.Skip = append(m.Skip, p)
	}
	sort.Slice(m.Entries, func(i, j int) bool {
		if m.Entries[i].Proto != m.Entries[j].Proto {
			return m.Entries[i].Proto < m.Entries[j].Proto
		}
		return m.Entries[i].Port < m.Entries[j].Port
	})
	sort.Slice(m.Skip, func(i, j int) bool { return m.Skip[i] < m.Skip[j] })
	return m
}

// addr is the endpoint every dial site uses. AgentAddr stays the immutable
// configured value so a Client built by a test or by New is complete without
// the hook; only ReResolve ever moves the target, and it moves it through an
// atomic because splices and the reserve session dial concurrently.
func (c *Client) addr() string {
	if p := c.curAddr.Load(); p != nil {
		return *p
	}
	return c.AgentAddr
}

// refreshAddr re-runs the hook between session attempts.
func (c *Client) refreshAddr() {
	if c.ReResolve == nil {
		return
	}
	if a := c.ReResolve(); a != "" {
		c.curAddr.Store(&a)
	}
}

func New(agentAddr, mirrorIP string) *Client {
	c := &Client{AgentAddr: agentAddr, MirrorIP: mirrorIP, mirrors: map[mirrorKey]*mirrorEntry{}}
	if e, err := transport.Parse(agentAddr); err == nil {
		c.agentPort = e.Port()
	}
	return c
}

// Run keeps a session against the agent, reconnecting with backoff, until
// ctx is done. It also parks the 'R' reservation conn (Phase 4).
func (c *Client) Run(ctx context.Context) error {
	go c.reserveLoop(ctx)
	for {
		if err := c.session(ctx); err != nil {
			log.Printf("drawbridged: session: %v (reconnecting)", err)
		}
		c.closeAll()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		c.refreshAddr()
	}
}

func (c *Client) session(ctx context.Context) error {
	conn, err := transport.Dial(c.addr())
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	sec, err := c.Auth.Secret()
	if err != nil {
		return c.Auth.Wrap(err, c.addr())
	}
	// Hello and proof in one Write, then the agent's proof before the JSON
	// decoder: not one event byte is trusted from an unverified peer (§3.2).
	frame, err := transportauth.ClientHello(conn, sec, 'E', nil)
	if err != nil {
		return err
	}
	if err := transportauth.AwaitAgentProof(conn, sec, frame, transportauth.HandshakeTimeout); err != nil {
		return c.Auth.Wrap(err, c.addr())
	}
	c.sessionUp.Store(true)
	defer c.sessionUp.Store(false)
	dec := json.NewDecoder(conn)
	events := 0
	for {
		var ev event
		if err := dec.Decode(&ev); err != nil {
			// Row 6: we sent auth=0 because we have no secret, and the agent
			// hung up before saying anything. The likeliest reason is a guest
			// that *is* provisioned — this is the one vantage point where
			// that is unambiguous, since 'E' expects an immediate snapshot.
			if sec == nil && events == 0 {
				line := c.Auth.ClosedEarly(c.addr())
				c.Auth.Record(transportauth.CheckAuthMacMissing, line)
				return errors.New(line)
			}
			return err
		}
		events++
		c.lastEventAt.Store(time.Now().UnixNano())
		switch ev.Op {
		case "snapshot":
			c.reconcile(ev.Listeners)
		case "add":
			c.add(listenerInfo{Proto: ev.Proto, Port: ev.Port, Addr: ev.Addr})
		case "del":
			c.del(listenerInfo{Proto: ev.Proto, Port: ev.Port, Addr: ev.Addr})
		case "ping":
		}
	}
}

// linuxEphemeralLo/Hi is the guest kernel's default autobind range. Every
// UDP client socket's kernel autobind lands here and is indistinguishable
// by address from a wildcard server (udp_get_port fires for both), so UDP
// listeners in this range are not mirrored — see docs/udp.md, "The
// client-socket problem". The precise upgrade path is a tracker snum flag
// (BPF event-ABI change, deliberately deferred).
const (
	linuxEphemeralLo = 32768
	linuxEphemeralHi = 60999
)

// mirrorable: guest listeners on addresses reachable via guest loopback
// that make sense as Mac localhost mirrors. The agent's own transport port
// is infrastructure (and already occupied on the Mac by the Lima forward).
func (c *Client) mirrorable(l listenerInfo) bool {
	if l.Port == 0 || l.Port == c.agentPort {
		return false
	}
	switch l.Proto {
	case "tcp":
	case "udp":
		if l.Port >= linuxEphemeralLo && l.Port <= linuxEphemeralHi {
			return false // autobound client socket, not a server
		}
	default:
		return false
	}
	switch l.Addr {
	case "0.0.0.0", "::", "127.0.0.1", "::1":
		return true
	}
	return false
}

// declined reports whether the skip-list covers this listener, logging the
// decision. Logged on every decision by design (see Client.Skip): a silent
// skip turns "my container's port never appeared on the Mac" into an
// undiagnosable mystery, and the log line is what names the flag that undoes
// it. Callers only consult it on paths that would otherwise open a mirror —
// del needs no check, since a skipped port never entered c.mirrors.
func (c *Client) declined(proto string, port uint16) bool {
	if !c.Skip[port] {
		return false
	}
	line := "skipping guest " + proto + " :" + strconv.Itoa(int(port)) + " (skip-list; -skip to override)"
	log.Printf("drawbridged: mirror: %s", line)
	c.observe(mirrorKey{proto, port}, introspect.EntrySkipped)
	c.Refusals.Record(introspect.IDMirrorSkip, line)
	return true
}

func (c *Client) reconcile(snapshot []listenerInfo) {
	want := map[mirrorKey]int{}
	skipped := map[mirrorKey]bool{} // one log line per port, not per refcount
	for _, l := range snapshot {
		if !c.mirrorable(l) {
			continue
		}
		key := mirrorKey{l.Proto, l.Port}
		if c.Skip[l.Port] {
			if !skipped[key] {
				skipped[key] = true
				c.declined(l.Proto, l.Port)
			}
			continue
		}
		want[key]++
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, e := range c.mirrors {
		if want[key] == 0 {
			if e.pending {
				continue // reservation not yet in the guest's snapshot
			}
			e.stop()
			delete(c.mirrors, key)
		} else {
			e.pending = false
			e.refs = want[key]
		}
	}
	for key, refs := range want {
		if _, ok := c.mirrors[key]; !ok {
			c.openLocked(key, refs)
		}
	}
}

func (c *Client) add(l listenerInfo) {
	if !c.mirrorable(l) {
		return
	}
	if c.declined(l.Proto, l.Port) {
		return
	}
	key := mirrorKey{l.Proto, l.Port}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.mirrors[key]; ok {
		if e.pending { // the reserved bind landed: adopt
			e.pending = false
			e.refs = 1
		} else {
			e.refs++
		}
		return
	}
	c.openLocked(key, 1)
}

func (c *Client) del(l listenerInfo) {
	if !c.mirrorable(l) {
		return
	}
	key := mirrorKey{l.Proto, l.Port}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.mirrors[key]
	if !ok || e.pending {
		return
	}
	e.refs--
	if e.refs <= 0 {
		e.stop()
		delete(c.mirrors, key)
	}
}

// logBindError explains a mirror bind failure. macOS reserves ports <1024
// for root (no reservedhigh sysctl), for UDP exactly as for TCP.
func (c *Client) logBindError(key mirrorKey, err error) {
	c.observe(key, introspect.EntryBindFailed)
	if errors.Is(err, syscall.EACCES) && key.port < 1024 {
		log.Printf("drawbridged: cannot mirror guest %s :%d — macOS reserves ports <1024 for root; run `sudo drawbridge install` (root LaunchDaemon) or run drawbridged as root to mirror it", key.proto, key.port)
	} else {
		log.Printf("drawbridged: mirror %s %s:%d unavailable: %v", key.proto, c.MirrorIP, key.port, err)
	}
}

func (c *Client) openLocked(key mirrorKey, refs int) {
	if key.proto == "udp" {
		c.openUDPLocked(key, refs)
		return
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(c.MirrorIP, strconv.Itoa(int(key.port))))
	if err != nil {
		// Mac-side collision or privilege gap: log-and-skip (Phase 4 makes
		// the collision case synchronous).
		c.logBindError(key, err)
		return
	}
	log.Printf("drawbridged: mirroring guest :%d on %s", key.port, ln.Addr())
	c.mirrors[key] = &mirrorEntry{stop: func() { ln.Close() }, refs: refs, since: time.Now()}
	c.forget(key)
	go c.acceptLoop(ln, key.port)
}

func (c *Client) acceptLoop(ln net.Listener, port uint16) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go c.splice(conn, port)
	}
}

func (c *Client) splice(conn net.Conn, port uint16) {
	up, err := c.dialStream(6, port)
	if err != nil {
		conn.Close()
		return
	}
	proxy.Splice(conn, up)
}

// dialStream opens an authenticated 'S' conn for proto/port. The stream
// header rides in the same Write as the frame and the proof, and the agent's
// proof is verified BEFORE the caller forwards a single client byte — the
// splice is the payload gate this phase exists to close (§3.2).
func (c *Client) dialStream(proto uint8, port uint16) (net.Conn, error) {
	sec, err := c.Auth.Secret()
	if err != nil {
		c.logAuthRefusal(err)
		return nil, err
	}
	up, err := transport.Dial(c.addr())
	if err != nil {
		return nil, err
	}
	var hdr [4]byte // {proto, port BE, reserved}
	hdr[0] = proto
	binary.BigEndian.PutUint16(hdr[1:3], port)
	frame, err := transportauth.ClientHello(up, sec, 'S', hdr[:])
	if err != nil {
		up.Close()
		return nil, err
	}
	if err := transportauth.AwaitAgentProof(up, sec, frame, transportauth.HandshakeTimeout); err != nil {
		up.Close()
		c.logAuthRefusal(err)
		return nil, err
	}
	return up, nil
}

// logAuthRefusal reports a per-connection handshake failure. These paths run
// once per accepted client (or once per UDP stream retry), so the lines are
// throttled (§7); the long-lived sessions' errors are paced by their own
// reconnect loops instead.
func (c *Client) logAuthRefusal(err error) {
	if line := c.Auth.Report(err, c.addr()); line != "" {
		log.Printf("drawbridged: mirror: %s", line)
	}
}

func (c *Client) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, e := range c.mirrors {
		e.stop()
		delete(c.mirrors, key)
	}
}

// --- Phase 4 reservations: the guest agent's bind supervisor asks us to
// reserve a port BEFORE the container's bind() proceeds. Reserving means
// binding the real mirror listener now (reserve-before-ack — no TOCTOU
// window) as a pending entry; the tracker's add event adopts it, and an
// unadopted reservation (the guest bind failed natively) expires after
// ReserveTTL.

type reserveReq struct {
	Op    string `json:"op"`
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
	Addr  string `json:"addr"`
}

type reserveResp struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

func (c *Client) reserveLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := c.reserveSession(ctx); err != nil && ctx.Err() == nil {
			log.Printf("drawbridged: reserve session: %v (reconnecting)", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (c *Client) reserveSession(ctx context.Context) error {
	conn, err := transport.Dial(c.addr())
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	sec, err := c.Auth.Secret()
	if err != nil {
		return c.Auth.Wrap(err, c.addr())
	}
	// The reservation RPC binds real Mac listeners on the guest's word, so
	// the peer is verified before a single request is read (§3.2).
	frame, err := transportauth.ClientHello(conn, sec, 'R', nil)
	if err != nil {
		return err
	}
	if err := transportauth.AwaitAgentProof(conn, sec, frame, transportauth.HandshakeTimeout); err != nil {
		return c.Auth.Wrap(err, c.addr())
	}
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)
	for {
		var req reserveReq
		if err := dec.Decode(&req); err != nil {
			return err
		}
		if err := enc.Encode(c.handleReserve(req)); err != nil {
			return err
		}
	}
}

func (c *Client) handleReserve(r reserveReq) reserveResp {
	if r.Op != "reserve" || r.Proto != "tcp" || r.Port == 0 {
		return reserveResp{Reason: "unsupported"}
	}
	if c.Skip[r.Port] {
		// A skipped port is none of our business, so we take no interest and
		// bind nothing: the guest bind is decided by the guest kernel alone.
		// This branch is load-bearing, not symmetry — without it the Mac would
		// try the bind, and a Mac that holds the port itself (:22 with Remote
		// Login on, precisely the case the list exists for) would answer
		// "inuse" and refuse the container's sshd with EADDRINUSE.
		line := "not arbitrating guest bind :" + strconv.Itoa(int(r.Port)) + " (skip-list; -skip to override)"
		log.Printf("drawbridged: mirror: %s", line)
		c.observe(mirrorKey{"tcp", r.Port}, introspect.EntrySkipped)
		c.Refusals.Record(introspect.IDMirrorSkip, line)
		return reserveResp{OK: true}
	}
	key := mirrorKey{"tcp", r.Port}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.mirrors[key]; ok {
		// Already ours (mirror or earlier reservation) — not a Mac-native
		// conflict; the guest bind succeeds or fails on guest semantics.
		return reserveResp{OK: true}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(c.MirrorIP, strconv.Itoa(int(r.Port))))
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return reserveResp{Reason: "inuse"}
		}
		// e.g. privileged port without root: we cannot know — degrade.
		return reserveResp{Reason: "unknown"}
	}
	e := &mirrorEntry{stop: func() { ln.Close() }, pending: true, since: time.Now()}
	c.mirrors[key] = e
	c.forget(key)
	go c.acceptLoop(ln, r.Port)
	ttl := c.ReserveTTL
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	time.AfterFunc(ttl, func() { c.releaseIfPending(key, e) })
	log.Printf("drawbridged: reserved :%d ahead of guest bind", r.Port)
	return reserveResp{OK: true}
}

func (c *Client) releaseIfPending(key mirrorKey, e *mirrorEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, ok := c.mirrors[key]; ok && cur == e && e.pending {
		e.stop()
		delete(c.mirrors, key)
		log.Printf("drawbridged: reservation :%d expired unadopted", key.port)
	}
}

// Mirrors reports whether proto:port is currently mirrored by this client.
// The mirror bind and its registration are atomic under mu, so the Phase 3
// listener sync uses this to exclude our own listeners without a window
// where a fresh mirror could be mistaken for a native Mac service.
func (c *Client) Mirrors(proto string, port uint16) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.mirrors[mirrorKey{proto, port}]
	return ok
}

// MirroredPorts returns currently mirrored ports for proto (test helper).
func (c *Client) MirroredPorts(proto string) []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint16, 0, len(c.mirrors))
	for k := range c.mirrors {
		if k.proto == proto {
			out = append(out, k.port)
		}
	}
	return out
}
