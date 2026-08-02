//go:build linux

package agent

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/archcorsair/drawbridge/internal/proxy"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// Transport protocol (one TCP connection per purpose, always dialed from
// the Mac via the Lima-forwarded control port; swappable for vsock later).
//
// Every conn opens with a 4-byte type frame {type u8, auth u8, 0, 0},
// written by the Mac in ONE Write syscall — followed, when auth is 1, by a
// 32-byte HMAC proof in the same segment (docs/transport-auth.md §3.2).
// Byte 1 is permanently the auth-scheme byte (0 none, 1 static-HMAC-v1;
// anything else closes pre-dispatch); bytes 2–3 remain the reserved-zero
// version escape hatch, so an incompatible future revision degrades to a
// failed conn, never a misdispatched stream. The frame is 4 bytes rather
// than a lone type byte because DPI middleboxes (Little Snitch's network
// extension here, corporate endpoint security generally) hold a lone byte
// that prefixes an HTTP method ('D' → DELETE) for ~2s waiting for a request
// line — see docs/transport.md §2.6. Never shrink it back. Frame and
// handshake are consumed here, pre-dispatch, so every downstream reader (the
// 'S' header parse, the JSON decoders, the dial pool's byte-silent park)
// sees the same stream it always has.
//
// Types:
//
//	'E' — events: server sends JSON lines (snapshot first, then add/del,
//	      periodic {"op":"ping"} for liveness).
//	'S' — stream: 4-byte header {proto u8, port u16 BE, reserved u8}.
//	      proto 6: raw bytes spliced to 127.0.0.1:port inside the guest.
//	      proto 17: v1 datagram frames (internal/udpframe) relayed to the
//	      guest UDP listener, one relay socket per Mac client.
//	      reserved MUST be 0 (framing-version escape hatch): nonzero closes
//	      the conn, so an incompatible future framing degrades to no-UDP,
//	      never to corrupt splicing.
//	'M' — Mac listener events (Phase 3): client sends the same JSON lines,
//	      describing Mac listeners; the agent reconciles mac_ports and
//	      drops sync-owned entries when the conn dies.
//	'D' — dial stream (Phase 3): parked until a gateway proxy activates it
//	      with the same 4-byte header; bytes then splice to the Mac, which
//	      dials its own 127.0.0.1:port.
//	'R' — reservation RPC (Phase 4): parked; the agent's bind supervisor
//	      sends {op:"reserve",...} JSON lines and the Mac answers after
//	      binding the mirror listener (reserve-before-ack).

// ServeTransport accepts transport connections until the listener closes.
func (a *Agent) ServeTransport(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go a.handleTransportConn(c)
	}
}

func (a *Agent) handleTransportConn(c net.Conn) {
	// A dialer that connects and then says nothing used to pin this
	// goroutine forever; the frame read now carries the handshake deadline
	// (docs/transport-auth.md §3.2).
	c.SetReadDeadline(time.Now().Add(transportauth.HandshakeTimeout))
	var frame [transportauth.FrameLen]byte
	if _, err := io.ReadFull(c, frame[:]); err != nil {
		c.Close()
		return
	}
	if frame[2] != 0 || frame[3] != 0 { // version escape hatch: still reserved
		c.Close()
		return
	}
	if frame[1] != transportauth.AuthNone && frame[1] != transportauth.AuthStaticHMACv1 {
		c.Close() // unknown auth scheme (a future auth=2 peer): fail closed
		return
	}
	// Re-read per accepted conn: rotation heals live, without an agent
	// restart (§5). The file is ~65 bytes next to a TCP accept.
	sec, err := transportauth.LoadOptional(a.SecretFile)
	if err != nil {
		a.refuseConn(c, frame[0], transportauth.CauseSecretUnreadable, err)
		return
	}
	if err := transportauth.ServerHandshake(c, sec, frame, transportauth.HandshakeTimeout); err != nil {
		cause, _ := transportauth.CauseOf(err)
		a.refuseConn(c, frame[0], cause, err)
		return
	}
	// Dispatch must inherit no deadline: above all, a parked 'D' conn is
	// silent for as long as the guest likes, and the pool's watchdog would
	// fire the instant a stale deadline expired.
	c.SetDeadline(time.Time{})
	switch frame[0] {
	case 'E':
		a.serveEvents(c)
	case 'S':
		a.serveStream(c)
	case 'M':
		a.serveMacSync(c)
	case 'D':
		a.pool.park(c)
	case 'R':
		a.setReserveConn(c)
	default:
		c.Close()
	}
}

// authLogKey is the throttle unit: one line per cause per source host.
type authLogKey struct {
	cause transportauth.Cause
	src   string
}

// authLogEvery throttles refusal lines per (cause, source): the Mac retries
// every second, and journal spam would bury the diagnosis (§7).
const authLogEvery = 30 * time.Second

// refuseConn closes a conn that failed the handshake and logs the diagnosis
// for its cause: the condition, the likeliest reason, and the one command
// that fixes it (§7 rows 1–3, 8). Refusal is always a closed conn — never a
// warning-and-continue.
func (a *Agent) refuseConn(c net.Conn, typ byte, cause transportauth.Cause, err error) {
	src := "unknown"
	if ra := c.RemoteAddr(); ra != nil {
		src = ra.String()
	}
	key := src
	if ip, ok := peerIP(c); ok {
		key = ip.String() // throttle per source host, not per ephemeral port
	}
	c.Close()
	if !a.allowAuthLog(cause, key) {
		return
	}
	var why string
	switch cause {
	case transportauth.CausePeerUnauthenticated: // row 1
		why = "peer sent no authentication but this guest has a transport secret — the Mac daemon has no secret configured or predates transport auth; re-run 'sudo drawbridge install' (or pass -secret-file) and restart it"
	case transportauth.CauseProofMismatch: // row 2
		why = "invalid transport secret — the peer holds a different secret than this guest (stale after re-provisioning?); re-run 'drawbridge up <vm>' to converge, then retry"
	case transportauth.CauseNoLocalSecret: // row 3
		why = fmt.Sprintf("peer requires authentication but this guest has no transport secret (%s missing) — run 'drawbridge up <vm>' to provision one", a.SecretFile)
	case transportauth.CauseSecretUnreadable: // row 8
		why = fmt.Sprintf("this guest's transport secret is unusable (%v) — it must be 64 hex characters, mode 0600; re-run 'drawbridge up <vm>' to reprovision", err)
	default: // stalled or vanished mid-handshake
		why = fmt.Sprintf("peer closed or stalled during transport authentication (%v)", err)
	}
	a.log("drawbridge-agent: transport: refused '%c' conn from %s: %s", typ, src, why)
}

// allowAuthLog reports whether a refusal line should be emitted now for
// (cause, source), recording the decision.
func (a *Agent) allowAuthLog(cause transportauth.Cause, src string) bool {
	now := time.Now()
	if a.now != nil {
		now = a.now()
	}
	k := authLogKey{cause, src}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if a.authLast == nil {
		a.authLast = map[authLogKey]time.Time{}
	}
	if t, ok := a.authLast[k]; ok && now.Sub(t) < authLogEvery {
		return false
	}
	if len(a.authLast) > 1024 { // a scanner must not grow the map forever
		for key, t := range a.authLast {
			if now.Sub(t) >= authLogEvery {
				delete(a.authLast, key)
			}
		}
	}
	a.authLast[k] = now
	return true
}

func (a *Agent) log(format string, args ...any) {
	if a.logf != nil {
		a.logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (a *Agent) serveEvents(c net.Conn) {
	defer c.Close()
	ch, cancel := a.Hub.Subscribe()
	defer cancel()
	enc := json.NewEncoder(c)
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				// The hub closed us out (subscriber overflow): end the
				// session; the client reconnects and the snapshot heals.
				return
			}
			if err := enc.Encode(ev); err != nil {
				return
			}
		case <-ping.C:
			if err := enc.Encode(TransportEvent{Op: "ping"}); err != nil {
				return
			}
		}
	}
}

func (a *Agent) serveStream(c net.Conn) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		c.Close()
		return
	}
	proto := hdr[0]
	port := binary.BigEndian.Uint16(hdr[1:3])
	if port == 0 || hdr[3] != 0 { // reserved must be 0 (version rule)
		c.Close()
		return
	}
	switch proto {
	case 6:
		// Dials the guest loopback; the connect4 hook passes it natively
		// because the port is in guest_ports (that's why it was mirrored).
		b, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			c.Close()
			return
		}
		proxy.Splice(c, b)
	case 17:
		a.serveUDPStream(c, port)
	default:
		c.Close()
	}
}
