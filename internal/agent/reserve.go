//go:build linux

package agent

import (
	"encoding/json"
	"net"
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

// ReservePort asks the Mac to reserve proto:port before a guest bind
// proceeds (reserve-before-ack). Returns "ok", "inuse", or "unknown".
func (a *Agent) ReservePort(proto string, port uint16, addr string) string {
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
