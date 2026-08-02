//go:build linux

package agent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/archcorsair/drawbridge/internal/bpf"
)

// Listener describes one guest socket endpoint.
type Listener struct {
	Proto string     `json:"proto"` // "tcp" | "udp"
	Port  uint16     `json:"port"`
	Addr  netip.Addr `json:"addr"` // bind address, unmapped
}

// TransportEvent is one JSON line on the transport events stream.
type TransportEvent struct {
	Op        string     `json:"op"` // snapshot | add | del | ping
	Proto     string     `json:"proto,omitempty"`
	Port      uint16     `json:"port,omitempty"`
	Addr      string     `json:"addr,omitempty"`
	Listeners []Listener `json:"listeners,omitempty"`
}

// TrackerHub owns the current guest-listener set: seeded from /proc/net,
// kept current by tracker ringbuf events, fanned out to subscribers.
type TrackerHub struct {
	mu   sync.Mutex
	set  map[Listener]struct{}
	subs map[chan TransportEvent]struct{}
}

func NewTrackerHub() *TrackerHub {
	return &TrackerHub{
		set:  map[Listener]struct{}{},
		subs: map[chan TransportEvent]struct{}{},
	}
}

// Subscribe returns an event channel primed with a snapshot, plus a cancel.
func (h *TrackerHub) Subscribe() (<-chan TransportEvent, func()) {
	ch := make(chan TransportEvent, 256)
	h.mu.Lock()
	snap := make([]Listener, 0, len(h.set))
	for l := range h.set {
		snap = append(snap, l)
	}
	h.subs[ch] = struct{}{}
	// Enqueue the snapshot BEFORE releasing the lock: publishes also take
	// it, so no add/del can slip into the channel ahead of the snapshot.
	// (An add outrunning its own snapshot gets its mirror destroyed by the
	// stale reconcile a moment later — seen as bench's sink/source mirrors
	// vanishing while echo survived.) The fresh channel can't block: its
	// buffer is 256 and this is its first event.
	ch <- TransportEvent{Op: "snapshot", Listeners: snap}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

// Has reports whether the listener is currently in the set.
func (h *TrackerHub) Has(l Listener) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.set[l]
	return ok
}

// linuxEphemeralLo/Hi is the kernel's default autobind range.
// udp_get_port fires for every UDP socket — including each client
// socket's kernel autobind — so guest DNS churn alone generates hundreds
// of add/del pairs per minute. Those can never be mirrored (the Mac side
// rejects the range too, see mirror.mirrorable), so they are dropped here
// before they consume subscriber buffers and transport bytes: during a
// bench a burst of them plus a bulk-transfer-stalled 'E' conn overflowed
// a subscriber and silently swallowed a real TCP add. Pure function of
// the port, applied to adds and dels alike — no set skew.
const (
	linuxEphemeralLo = 32768
	linuxEphemeralHi = 60999
)

func eventWorthy(l Listener) bool {
	return !(l.Proto == "udp" && l.Port >= linuxEphemeralLo && l.Port <= linuxEphemeralHi)
}

func (h *TrackerHub) apply(op string, l Listener) {
	if !eventWorthy(l) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if op == "add" {
		if _, ok := h.set[l]; ok {
			return
		}
		h.set[l] = struct{}{}
	} else {
		if _, ok := h.set[l]; !ok {
			return
		}
		delete(h.set, l)
	}
	ev := TransportEvent{Op: op, Proto: l.Proto, Port: l.Port, Addr: l.Addr.String()}
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
			// Overflowing subscriber: a silent drop would leave it
			// diverged until it happens to reconnect. Close the channel
			// instead — its session ends, the client redials, and the
			// fresh snapshot heals. Losing the conn is recoverable;
			// losing an event is not.
			delete(h.subs, ch)
			close(ch)
		}
	}
}

func listenerFromEvent(e *bpf.ListenerEvent) Listener {
	proto := "tcp"
	if e.Proto == bpf.ProtoUDP {
		proto = "udp"
	}
	return Listener{
		Proto: proto,
		Port:  e.Port,
		Addr:  netip.AddrFrom16(e.Addr).Unmap(),
	}
}

// RunTracker consumes ringbuf events until the reader is closed.
func (h *TrackerHub) RunTracker(rd *ringbuf.Reader) {
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("tracker: ringbuf read: %v", err)
			continue
		}
		var ev bpf.ListenerEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		op := "add"
		if ev.Op == bpf.EventDel {
			op = "del"
		}
		h.apply(op, listenerFromEvent(&ev))
	}
}
