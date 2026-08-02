package udpframe

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// RelayStream pumps a proto-17 framed stream against per-peer UDP sockets:
// the stateful end of a UDP path (docs/udp.md), used by the guest agent
// for inbound mirrors (relay sockets to the guest listener) and by the Mac
// syncer for outbound flows (sockets to the local service). Each new flow
// peer gets its own socket from dial — distinct source ports preserve the
// backend's per-peer demux — and socket reads are framed back tagged with
// the peer. Flows expire after FlowIdleTimeout (UDP has no FIN) and the
// table is capped at MaxFlows. Returns when the stream dies (read error or
// desync); all flow sockets are closed on the way out.
func RelayStream(stream net.Conn, dial func() (*net.UDPConn, error)) {
	defer stream.Close()

	type flow struct {
		conn     *net.UDPConn
		lastSeen time.Time
	}
	var (
		wmu   sync.Mutex // frame writes to stream
		mu    sync.Mutex // flows table
		flows = map[netip.AddrPort]*flow{}
	)
	stop := make(chan struct{})
	defer close(stop)
	defer func() {
		mu.Lock()
		for _, f := range flows {
			f.conn.Close()
		}
		mu.Unlock()
	}()

	touch := func(peer netip.AddrPort) {
		mu.Lock()
		if f, ok := flows[peer]; ok {
			f.lastSeen = time.Now()
		}
		mu.Unlock()
	}

	go func() { // idle-flow sweeper
		t := time.NewTicker(FlowSweepInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			cutoff := time.Now().Add(-FlowIdleTimeout)
			mu.Lock()
			for peer, f := range flows {
				if f.lastSeen.Before(cutoff) {
					f.conn.Close() // unblocks its reader goroutine
					delete(flows, peer)
				}
			}
			mu.Unlock()
		}
	}()

	get := func(peer netip.AddrPort) *net.UDPConn {
		mu.Lock()
		defer mu.Unlock()
		if f, ok := flows[peer]; ok {
			f.lastSeen = time.Now()
			return f.conn
		}
		if len(flows) >= MaxFlows {
			return nil // at cap: drop new-peer datagrams
		}
		uc, err := dial()
		if err != nil {
			return nil
		}
		flows[peer] = &flow{conn: uc, lastSeen: time.Now()}
		go func() { // backend replies -> framed back to this peer
			rbuf := make([]byte, MaxPayload)
			for {
				n, err := uc.Read(rbuf)
				if err != nil {
					return
				}
				touch(peer)
				if err := WriteFrame(stream, &wmu, peer, rbuf[:n]); err != nil {
					stream.Close() // dead stream: owner redials/re-parks
					return
				}
			}
		}()
		return uc
	}

	buf := make([]byte, MaxPayload)
	for {
		peer, payload, err := ReadFrame(stream, buf)
		if err != nil {
			return // closed or desync — either way this stream is done
		}
		if uc := get(peer); uc != nil {
			uc.Write(payload)
		}
	}
}
