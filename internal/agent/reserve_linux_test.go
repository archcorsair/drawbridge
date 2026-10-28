//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/bpf"
)

// fakeReserveMac is the Mac end of a parked 'R' conn: it records every
// request and answers ok. No BPF, no root: these tests build the Agent by
// hand and run anywhere Linux does.
type fakeReserveMac struct {
	reqs chan reserveReq
}

func parkFakeMac(t *testing.T, a *Agent) *fakeReserveMac {
	t.Helper()
	agentEnd, macEnd := net.Pipe()
	t.Cleanup(func() { macEnd.Close(); agentEnd.Close() })
	f := &fakeReserveMac{reqs: make(chan reserveReq, 16)}
	go func() {
		dec, enc := json.NewDecoder(macEnd), json.NewEncoder(macEnd)
		for {
			var r reserveReq
			if err := dec.Decode(&r); err != nil {
				return
			}
			f.reqs <- r
			if err := enc.Encode(reserveResp{OK: true}); err != nil {
				return
			}
		}
	}()
	a.setReserveConn(agentEnd)
	return f
}

func (f *fakeReserveMac) none(t *testing.T, why string) {
	t.Helper()
	select {
	case r := <-f.reqs:
		t.Fatalf("%s: the Mac was asked anyway: %+v", why, r)
	default:
	}
}

func (f *fakeReserveMac) one(t *testing.T, port uint16) {
	t.Helper()
	select {
	case r := <-f.reqs:
		if r.Port != port || r.Op != "reserve" {
			t.Fatalf("Mac got %+v, want a reserve for :%d", r, port)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Mac never asked to reserve :%d", port)
	}
}

type captured struct {
	mu    sync.Mutex
	lines []string
}

func captureAgentLog(a *Agent) *captured {
	c := &captured{}
	a.logf = func(format string, args ...any) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.lines = append(c.lines, fmt.Sprintf(format, args...))
	}
	return c
}

func (c *captured) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

func agentWithMacPorts(ids ...portID) *Agent {
	a := &Agent{mac: map[portID]*macEntry{}, syncOwned: map[portID]struct{}{}}
	for _, id := range ids {
		a.mac[id] = &macEntry{}
		a.syncOwned[id] = struct{}{}
	}
	return a
}

// Audit H1 / NEW-A1: a bind on a port the Mac already holds (and has synced)
// is EADDRINUSE from the guest's own view, for every mirrorable address, and
// the Mac is never asked: no round trip, so no reservation holding Mac
// 127.0.0.1 for ReserveTTL behind a bind that then fails natively.
func TestReservePortAnswersSyncedMacPortLocally(t *testing.T) {
	const synced = uint16(5000)
	a := agentWithMacPorts(portID{bpf.ProtoTCP, synced})
	logs := captureAgentLog(a)
	mac := parkFakeMac(t, a)

	for _, addr := range []string{"127.0.0.1", "0.0.0.0", "::", "::1"} {
		if got := a.ReservePort("tcp", synced, addr); got != "inuse" {
			t.Fatalf("bind %s on synced Mac port :%d = %q, want inuse", net.JoinHostPort(addr, "5000"), synced, got)
		}
		mac.none(t, "synced port "+addr)
	}
	if !strings.Contains(logs.String(), "tcp 127.0.0.1:5000 is a synced Mac port") ||
		!strings.Contains(logs.String(), "tcp [::]:5000 is a synced Mac port") {
		t.Fatalf("short-circuit not logged with its address:\n%s", logs)
	}

	// A port the Mac never synced (skip-list, or not held) still goes to the
	// Mac, whose answer stands.
	const unsynced = uint16(5001)
	if got := a.ReservePort("tcp", unsynced, "127.0.0.1"); got != "ok" {
		t.Fatalf("unsynced :%d = %q, want the Mac's ok", unsynced, got)
	}
	mac.one(t, unsynced)
}

// The set is keyed per protocol: a Mac UDP service (-udp) on the port says
// nothing about a TCP bind there, which is the Mac's to decide.
func TestReservePortShortCircuitIsPerProto(t *testing.T) {
	const port = uint16(5353)
	a := agentWithMacPorts(portID{bpf.ProtoUDP, port})
	captureAgentLog(a)
	mac := parkFakeMac(t, a)

	if got := a.ReservePort("tcp", port, "0.0.0.0"); got != "ok" {
		t.Fatalf("tcp bind beside a synced udp :%d = %q, want the Mac's ok", port, got)
	}
	mac.one(t, port)
	if got := a.ReservePort("udp", port, "0.0.0.0"); got != "inuse" {
		t.Fatalf("udp bind on synced udp :%d = %q, want inuse", port, got)
	}
	mac.none(t, "synced udp port")
}

// No 'R' session at all (Mac down, or between reconnects) used to degrade
// every bind to CONTINUE. A port still in the mac set is still the Mac's:
// the answer needs nothing from the Mac, so it stays inuse.
func TestReservePortSyncedPortNeedsNoMacSession(t *testing.T) {
	const port = uint16(6000)
	a := agentWithMacPorts(portID{bpf.ProtoTCP, port})
	captureAgentLog(a)
	if got := a.ReservePort("tcp", port, "127.0.0.1"); got != "inuse" {
		t.Fatalf("synced :%d with no 'R' conn = %q, want inuse", port, got)
	}
	if got := a.ReservePort("tcp", port+1, "127.0.0.1"); got != "unknown" {
		t.Fatalf("unsynced :%d with no 'R' conn = %q, want unknown (degrade)", port+1, got)
	}
}

// The supervisor must always answer, and never block between receiving a
// notification and answering it. a.mu can be held for seconds (a UDP stream
// proxy closing under RemoveMacPort), so a contended mac set is skipped, not
// waited on: the bind goes to the Mac, whose own listener read backstops it.
func TestReservePortNeverWaitsOnTheMacSet(t *testing.T) {
	const port = uint16(7000)
	a := agentWithMacPorts(portID{bpf.ProtoTCP, port})
	captureAgentLog(a)
	mac := parkFakeMac(t, a)

	a.mu.Lock()
	defer a.mu.Unlock()
	done := make(chan string, 1)
	go func() { done <- a.ReservePort("tcp", port, "127.0.0.1") }()
	select {
	case got := <-done:
		if got != "ok" {
			t.Fatalf("contended set: got %q, want the Mac's answer (ok)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReservePort blocked on a.mu")
	}
	mac.one(t, port)
}
