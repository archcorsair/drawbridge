//go:build linux

package agent

import (
	"encoding/json"
	"net"
	"strconv"
	"time"
)

// 'R' reservation RPC (Phase 4): the Mac parks one conn; the notify path
// calls ReservePort with a hard deadline and treats every failure as
// "unknown", which the caller degrades to CONTINUE.

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

type reserveChan struct {
	c   net.Conn
	dec *json.Decoder
	enc *json.Encoder
}

func (a *Agent) setReserveConn(c net.Conn) {
	rc := &reserveChan{c: c, dec: json.NewDecoder(c), enc: json.NewEncoder(c)}
	a.resMu.Lock()
	old := a.resConn
	a.resConn = rc
	a.resMu.Unlock()
	if old != nil {
		old.c.Close()
	}
}

const reserveTimeout = 500 * time.Millisecond

// macPortHeld reports whether proto:port is a Mac-owned port in this agent's
// mac set (sync-owned entries and harness/testctl ones alike): exactly the
// ports mac_ports steers guest loopback connects for, and the ones the agent
// serves on its 127.0.0.2 gateway.
//
// known is false when the set cannot be read without waiting: a.mu can be
// held for seconds (RemoveMacPort closes a UDP stream proxy under it, and
// that close can wait out a reverse-stream dial), and the bind supervisor
// must never block between receiving a notification and answering it. The
// caller then asks the Mac, whose own backstop sees the same holder.
func (a *Agent) macPortHeld(proto string, port uint16) (held, known bool) {
	pn, ok := protoNum(proto)
	if !ok {
		return false, true
	}
	if !a.mu.TryLock() {
		return false, false
	}
	defer a.mu.Unlock()
	_, held = a.mac[portID{pn, port}]
	return held, true
}

// ReservePort asks the Mac to reserve proto:port before a guest bind
// proceeds (reserve-before-ack). Returns "ok", "inuse", or "unknown".
//
// A port already in the agent's Mac set is answered "inuse" here, without a
// round trip and without a reservation (audit H1, NEW-A1). Every synced
// listener answers Mac 127.0.0.1:port (the reverse dial targets it, and
// normalize syncs only 127.0.0.1, 0.0.0.0 and dual-stack `::`), and every
// mirrorable guest bind (127.0.0.1, 0.0.0.0, `::`, `::1`) would be mirrored
// onto that same Mac 127.0.0.1:port. So the answer is the one a Linux host
// gives when the Mac's listener is a local one: a guest bind to 127.0.0.1,
// 0.0.0.0 or `[::]` on that port is EADDRINUSE. Asking the Mac instead was
// the bug: on XNU its 127.0.0.1 reservation bind succeeds beside a wildcard
// holder, so a guest loopback bind was allowed and took the Mac service's
// loopback traffic, and a guest wildcard bind (which fails natively against
// the 127.0.0.2 gateway) still held Mac 127.0.0.1 for ReserveTTL.
//
// Everything else falls through to the Mac as before: skip-list ports (never
// synced; the Mac answers "ok" and binds nothing), holders newer than the
// last sync tick (the Mac's fresh listener read is the backstop for those),
// and a contended mac set. A filtered, empty Mac enumeration blinds both
// layers alike, and the Mac's bind result decides, as it always did.
func (a *Agent) ReservePort(proto string, port uint16, addr string) string {
	if held, known := a.macPortHeld(proto, port); held && known {
		a.log("reserve: %s %s is a synced Mac port: answering inuse without asking the Mac",
			proto, net.JoinHostPort(addr, strconv.Itoa(int(port))))
		return "inuse"
	}
	a.resMu.Lock()
	defer a.resMu.Unlock() // serializes RPCs on the single parked conn
	rc := a.resConn
	if rc == nil {
		return "unknown"
	}
	rc.c.SetDeadline(time.Now().Add(reserveTimeout))
	var resp reserveResp
	err := rc.enc.Encode(reserveReq{Op: "reserve", Proto: proto, Port: port, Addr: addr})
	if err == nil {
		err = rc.dec.Decode(&resp)
	}
	if err != nil {
		rc.c.Close()
		if a.resConn == rc {
			a.resConn = nil
		}
		return "unknown"
	}
	rc.c.SetDeadline(time.Time{})
	switch {
	case resp.OK:
		return "ok"
	case resp.Reason == "inuse":
		return "inuse"
	default:
		return "unknown"
	}
}
