package mirror

import (
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
)

// Audit H1: the Mac-side backstop. On XNU a mirror's 127.0.0.1:P bind
// succeeds beside a native 0.0.0.0:P or dual-stack [::]:P holder and then
// takes its loopback traffic, so the bind result alone cannot refuse; the
// MacHolder hook (macsync.HolderCheck in drawbridged) can. These tests inject
// the hook, so they hold on any OS; macsync's live tests prove the real read.

// fakeHolder answers MacHolder for one port and counts its calls.
type fakeHolder struct {
	port   uint16
	holder string
	known  bool
	calls  atomic.Int32
}

func (f *fakeHolder) check(proto string, port uint16) (string, bool) {
	f.calls.Add(1)
	if port != f.port {
		return "", f.known
	}
	return f.holder, f.known
}

func holderClient(f *fakeHolder) *Client {
	c := &Client{MirrorIP: "127.0.0.1", mirrors: map[mirrorKey]*mirrorEntry{}, ReserveTTL: time.Minute}
	if f != nil {
		c.MacHolder = f.check
	}
	return c
}

// listenHolder stands up a real Mac-side holder for the shape under test.
func listenHolder(t *testing.T, network, addr string) uint16 {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen %s %s here: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("MAC"))
			c.Close()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// The native service must still answer 127.0.0.1 after the decision: no
// mirror of ours sits in front of it.
func requireMacAnswers(t *testing.T, port uint16) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("127.0.0.1:%d: %v", port, err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 3)
	if _, err := c.Read(b); err != nil || string(b) != "MAC" {
		t.Fatalf("127.0.0.1:%d answered %q (%v), want the Mac holder", port, b, err)
	}
}

func reserve(c *Client, port uint16) reserveResp {
	return c.handleReserve(reserveReq{Op: "reserve", Proto: "tcp", Port: port, Addr: "127.0.0.1"})
}

// A wildcard holder (dual-stack [::] or tcp4 0.0.0.0) makes the reservation
// answer inuse before anything is bound: no pending mirror holds Mac
// 127.0.0.1 for ReserveTTL, which is NEW-A1 on the Mac side.
func TestReserveRefusesMacWildcardHolder(t *testing.T) {
	for _, h := range []struct{ name, network, addr, desc string }{
		{"dual-stack", "tcp", ":0", "[::]:%d (dual-stack)"},
		{"tcp4 wildcard", "tcp4", "0.0.0.0:0", "0.0.0.0:%d"},
	} {
		t.Run(h.name, func(t *testing.T) {
			sink := captureLog(t)
			port := listenHolder(t, h.network, h.addr)
			f := &fakeHolder{port: port, holder: fmt.Sprintf(h.desc, port), known: true}
			c := holderClient(f)
			defer c.closeAll()

			if r := reserve(c, port); r.OK || r.Reason != "inuse" {
				t.Fatalf("reserve :%d beside a %s holder = %+v, want inuse", port, h.name, r)
			}
			if c.Mirrors("tcp", port) {
				t.Fatalf("a reservation for :%d exists after inuse", port)
			}
			requireMacAnswers(t, port)
			want := fmt.Sprintf("refusing guest bind :%d (inuse): Mac %s", port, f.holder)
			if !strings.Contains(sink.String(), want) {
				t.Fatalf("log lacks %q:\n%s", want, sink.String())
			}
		})
	}
}

// A v6-only [::] holder never answers 127.0.0.1, so a reservation beside it
// takes nothing from anyone (and a Linux host would allow the bind too).
func TestReserveAllowsBesideV6OnlyHolder(t *testing.T) {
	port := listenHolder(t, "tcp6", "[::]:0")
	c := holderClient(&fakeHolder{port: port, known: true})
	defer c.closeAll()
	if r := reserve(c, port); !r.OK {
		t.Fatalf("reserve :%d beside a v6-only holder = %+v, want ok", port, r)
	}
	if !c.Mirrors("tcp", port) {
		t.Fatalf("no pending reservation for :%d", port)
	}
}

// An unknown read (empty/filtered enumeration, poll error) is neither free
// nor taken: the reservation decides from its own bind exactly as before the
// hook existed. A nil hook is the same.
func TestReserveUnknownFallsBackToBindResult(t *testing.T) {
	for _, name := range []string{"unknown", "nil hook"} {
		t.Run(name, func(t *testing.T) {
			var f *fakeHolder
			if name == "unknown" {
				f = &fakeHolder{known: false}
			}
			exact := listenHolder(t, "tcp4", "127.0.0.1:0")
			if f != nil {
				f.port = exact
				f.holder = "should never be read"
			}
			c := holderClient(f)
			defer c.closeAll()
			if r := reserve(c, exact); r.Reason != "inuse" {
				t.Fatalf("exact 127.0.0.1 holder: %+v, want inuse from the bind", r)
			}
			free := freeTCPPort(t)
			if r := reserve(c, free); !r.OK {
				t.Fatalf("free port :%d: %+v, want ok (unknown is not taken)", free, r)
			}
		})
	}
}

// The hook is not consulted where the answer never depended on the Mac:
// a skip-listed port (no interest, bind nothing) and a port already ours.
func TestReserveSkipsHookForSkipListAndOwnPorts(t *testing.T) {
	f := &fakeHolder{known: true}
	c := holderClient(f)
	defer c.closeAll()
	const skipped = uint16(61112)
	c.Skip = map[uint16]bool{skipped: true}
	captureLog(t)

	if r := reserve(c, skipped); !r.OK || f.calls.Load() != 0 {
		t.Fatalf("skip-listed :%d = %+v after %d hook calls, want ok with none", skipped, r, f.calls.Load())
	}
	own := freeTCPPort(t)
	if r := reserve(c, own); !r.OK {
		t.Fatalf("free :%d = %+v", own, r)
	}
	before := f.calls.Load()
	// Now ours: even a hook that would say "taken" is not asked.
	f.port, f.holder = own, "0.0.0.0:1 (must not be consulted)"
	if r := reserve(c, own); !r.OK || f.calls.Load() != before {
		t.Fatalf("own :%d = %+v, hook calls %d→%d", own, r, before, f.calls.Load())
	}
}

// The async mirror (no --oci): a guest listener on a port a Mac wildcard
// holder serves is not mirrored, and the refusal is recorded as bind-failed
// with a line naming the holder — the same shape as a colliding bind.
func TestAsyncMirrorRefusesMacWildcardHolder(t *testing.T) {
	sink := captureLog(t)
	port := listenHolder(t, "tcp", ":0")
	f := &fakeHolder{port: port, holder: fmt.Sprintf("[::]:%d (dual-stack)", port), known: true}
	c := holderClient(f)
	defer c.closeAll()

	c.add(listenerInfo{Proto: "tcp", Port: port, Addr: "127.0.0.1"})
	if c.Mirrors("tcp", port) {
		t.Fatalf("guest :%d mirrored over the Mac's wildcard holder", port)
	}
	requireMacAnswers(t, port)
	var state string
	for _, e := range c.Snapshot().Entries {
		if e.Proto == "tcp" && e.Port == port {
			state = e.State
		}
	}
	if state != introspect.EntryBindFailed {
		t.Fatalf("introspection state for :%d = %q, want %q", port, state, introspect.EntryBindFailed)
	}
	if want := fmt.Sprintf("Mac %s already serves it", f.holder); !strings.Contains(sink.String(), want) {
		t.Fatalf("log lacks %q:\n%s", want, sink.String())
	}

	// The snapshot path goes through the same open.
	c2 := holderClient(f)
	defer c2.closeAll()
	c2.reconcile([]listenerInfo{{Proto: "tcp", Port: port, Addr: "0.0.0.0"}})
	if c2.Mirrors("tcp", port) {
		t.Fatalf("snapshot mirrored guest :%d over the Mac's wildcard holder", port)
	}
}

// Known-free (v6-only holder, or nothing) and unknown both open the mirror
// as before.
func TestAsyncMirrorOpensWhenNotHeldOrUnknown(t *testing.T) {
	v6only := listenHolder(t, "tcp6", "[::]:0")
	free := freeTCPPort(t)
	cases := []struct {
		name string
		port uint16
		f    *fakeHolder
	}{
		{"v6-only holder", v6only, &fakeHolder{port: v6only, known: true}},
		{"unknown read", free, &fakeHolder{port: free, holder: "ignored", known: false}},
	}
	for _, tc := range cases {
		c := holderClient(tc.f)
		c.add(listenerInfo{Proto: "tcp", Port: tc.port, Addr: "0.0.0.0"})
		if !c.Mirrors("tcp", tc.port) {
			t.Errorf("%s: guest :%d not mirrored", tc.name, tc.port)
		}
		c.closeAll()
	}
}
