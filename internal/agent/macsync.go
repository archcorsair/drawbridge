//go:build linux

package agent

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/archcorsair/drawbridge/internal/bpf"
)

// Mac listener sync ('M' transport conns): the Mac streams its own listener
// set (snapshot, then add/del, ping when idle) and this side keeps mac_ports
// plus the per-port gateway proxies in step. Entries created here are
// sync-owned: they are dropped when the session ends, so a vanished Mac
// yields fast native ECONNREFUSED instead of connect-then-hang.

const syncReadTimeout = 45 * time.Second // Mac pings at >=10s idle

// macDialer returns the backend DialFunc for a Mac-owned port: pop a parked
// reverse-stream conn and activate it with the {proto, port BE, reserved}
// header. The Mac end then dials its own 127.0.0.1:port and splices.
func (a *Agent) macDialer(proto uint8, port uint16) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		c, err := a.pool.pop(3 * time.Second)
		if err != nil {
			return nil, err
		}
		var hdr [4]byte
		hdr[0] = proto
		binary.BigEndian.PutUint16(hdr[1:3], port)
		c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(hdr[:]); err != nil {
			c.Close()
			return nil, err
		}
		c.SetWriteDeadline(time.Time{})
		return c, nil
	}
}

func (a *Agent) serveMacSync(c net.Conn) {
	defer c.Close()
	// Kick any previous session, then wait for its cleanup: syncSession is
	// held across a session's whole lifetime including the removal of its
	// entries, so this session's snapshot can never be undone by a stale
	// disconnect cleanup.
	a.syncMu.Lock()
	if a.syncConn != nil {
		a.syncConn.Close()
	}
	a.syncMu.Unlock()
	a.syncSession.Lock()
	defer a.syncSession.Unlock()
	a.syncMu.Lock()
	a.syncConn = c
	a.syncMu.Unlock()
	defer func() {
		a.removeSyncOwned()
		a.syncMu.Lock()
		if a.syncConn == c {
			a.syncConn = nil
		}
		a.syncMu.Unlock()
	}()

	dec := json.NewDecoder(c)
	for {
		c.SetReadDeadline(time.Now().Add(syncReadTimeout))
		var ev TransportEvent
		if err := dec.Decode(&ev); err != nil {
			return
		}
		switch ev.Op {
		case "snapshot":
			a.applySyncSnapshot(ev.Listeners)
		case "add":
			a.addSyncPort(ev.Proto, ev.Port, ev.Addr)
		case "del":
			a.delSyncPort(ev.Proto, ev.Port)
		case "ping":
		}
	}
}

func protoNum(proto string) (uint8, bool) {
	switch proto {
	case "tcp":
		return bpf.ProtoTCP, true
	case "udp":
		return bpf.ProtoUDP, true
	}
	return 0, false
}

func (a *Agent) addSyncPort(proto string, port uint16, addr string) {
	pn, ok := protoNum(proto)
	if !ok {
		return
	}
	bind, err := netip.ParseAddr(addr)
	if err != nil {
		log.Printf("macsync: bad addr %q for port %d: %v", addr, port, err)
		return
	}
	id := portID{pn, port}
	a.mu.Lock()
	_, exists := a.mac[id]
	if !exists {
		a.syncOwned[id] = struct{}{} // reserve before the unlocked Add below
	}
	a.mu.Unlock()
	if exists {
		// Harness/testctl entry or duplicate add: leave it alone.
		return
	}
	if err := a.AddMacPort(pn, port, bind, ""); err != nil {
		a.mu.Lock()
		delete(a.syncOwned, id)
		a.mu.Unlock()
		log.Printf("macsync: add %s:%d on %s: %v", proto, port, addr, err)
	}
}

func (a *Agent) delSyncPort(proto string, port uint16) {
	pn, ok := protoNum(proto)
	if !ok {
		return
	}
	id := portID{pn, port}
	a.mu.Lock()
	_, owned := a.syncOwned[id]
	a.mu.Unlock()
	if !owned {
		return
	}
	if err := a.RemoveMacPort(pn, port); err != nil {
		log.Printf("macsync: del %s:%d: %v", proto, port, err)
	}
}

func (a *Agent) applySyncSnapshot(listeners []Listener) {
	want := map[portID]Listener{}
	for _, l := range listeners {
		if pn, ok := protoNum(l.Proto); ok {
			want[portID{pn, l.Port}] = l
		}
	}
	a.mu.Lock()
	var stale []portID
	for id := range a.syncOwned {
		if _, ok := want[id]; !ok {
			stale = append(stale, id)
		}
	}
	a.mu.Unlock()
	for _, id := range stale {
		if err := a.RemoveMacPort(id.proto, id.port); err != nil {
			log.Printf("macsync: snapshot del %d/%d: %v", id.proto, id.port, err)
		}
	}
	for id, l := range want {
		a.addSyncPort(l.Proto, id.port, l.Addr.String())
	}
}

func (a *Agent) removeSyncOwned() {
	a.mu.Lock()
	ids := make([]portID, 0, len(a.syncOwned))
	for id := range a.syncOwned {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	for _, id := range ids {
		if err := a.RemoveMacPort(id.proto, id.port); err != nil {
			log.Printf("macsync: session cleanup %d/%d: %v", id.proto, id.port, err)
		}
	}
}

// SyncOwnedPorts returns the ports currently owned by the Mac sync session
// (test helper).
func (a *Agent) SyncOwnedPorts() []uint16 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint16, 0, len(a.syncOwned))
	for id := range a.syncOwned {
		out = append(out, id.port)
	}
	return out
}
