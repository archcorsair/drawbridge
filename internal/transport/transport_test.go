package transport

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	ok := []struct {
		in     string
		want   string
		scheme string
		port   uint16
	}{
		{"192.168.64.5:4777", "tcp://192.168.64.5:4777", SchemeTCP, 4777},
		{"tcp://192.168.64.5:4777", "tcp://192.168.64.5:4777", SchemeTCP, 4777},
		{"127.0.0.1:0", "tcp://127.0.0.1:0", SchemeTCP, 0},
		// Host-less: the wildcard bind stays wildcard. Rewriting "" to
		// 0.0.0.0 would silently drop the v6 half of today's `-transport
		// :4777` default.
		{":4777", "tcp://:4777", SchemeTCP, 4777},
		{"tcp://:4777", "tcp://:4777", SchemeTCP, 4777},
		{"localhost:4777", "tcp://localhost:4777", SchemeTCP, 4777},
		{"[::1]:4777", "tcp://[::1]:4777", SchemeTCP, 4777},
		{"tcp://[::]:4777", "tcp://[::]:4777", SchemeTCP, 4777},
		{"unix:///run/drawbridge.sock", "unix:///run/drawbridge.sock", SchemeUnix, 0},
		{"vsock://3:4777", "vsock://3:4777", SchemeVsock, 4777},
	}
	for _, tc := range ok {
		e, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", tc.in, err)
			continue
		}
		if got := e.String(); got != tc.want {
			t.Errorf("Parse(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
		if e.Scheme != tc.scheme {
			t.Errorf("Parse(%q).Scheme = %q, want %q", tc.in, e.Scheme, tc.scheme)
		}
		if got := e.Port(); got != tc.port {
			t.Errorf("Parse(%q).Port() = %d, want %d", tc.in, got, tc.port)
		}
	}

	bad := []string{
		"",
		"192.168.64.5",         // no port
		"192.168.64.5:http",    // non-numeric port
		"192.168.64.5:70000",   // out of range
		"udp://127.0.0.1:4777", // unknown scheme
		"unix://relative.sock", // not absolute
		"vsock://3",            // no port
		"vsock://host:4777",    // non-numeric cid
		"tcp://192.168.64.5",   // scheme form, no port
		"tcp://1.2.3.4:1:2",    // not host:port
	}
	for _, in := range bad {
		if e, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %v, want error", in, e)
		}
	}
}

// endpoints returns a listener and its dial endpoint for each supported
// scheme, plus the bare spelling for tcp (the harness passes
// ln.Addr().String() straight through).
func listeners(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}

	tln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	t.Cleanup(func() { tln.Close() })
	out["tcp-bare"] = tln.Addr().String()
	out["tcp-canonical"] = "tcp://" + tln.Addr().String()
	go acceptEcho(tln)

	sock := filepath.Join(t.TempDir(), "t.sock")
	uln, err := Listen("unix://" + sock)
	if err != nil {
		t.Fatalf("Listen unix: %v", err)
	}
	t.Cleanup(func() { uln.Close(); os.Remove(sock) })
	out["unix"] = "unix://" + sock
	go acceptEcho(uln)

	return out
}

func acceptEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() { io.Copy(c, c); c.Close() }()
	}
}

func TestRoundTrip(t *testing.T) {
	for name, ep := range listeners(t) {
		c, err := Dial(ep)
		if err != nil {
			t.Fatalf("%s: Dial(%q): %v", name, ep, err)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatalf("%s: write: %v", name, err)
		}
		buf := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("%s: read: %v", name, err)
		}
		if string(buf) != "ping" {
			t.Fatalf("%s: echo = %q", name, buf)
		}
		c.Close()
	}
}

// TestHostlessListen pins that the agent's ":4777"-shaped default binds
// through the seam exactly as net.Listen("tcp", ":4777") did.
func TestHostlessListen(t *testing.T) {
	ln, err := Listen(":0")
	if err != nil {
		t.Fatalf("Listen(\":0\"): %v", err)
	}
	defer ln.Close()
	go acceptEcho(ln)

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := Dial(net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("dial wildcard listener: %v", err)
	}
	c.Close()
}

// TestCloseWritePropagates is the property Lima's gRPC tunnel lacks: a
// half-close on one side must surface as EOF on the other while the reverse
// direction stays open.
func TestCloseWritePropagates(t *testing.T) {
	cases := map[string]func(*testing.T) (net.Listener, string){
		"tcp": func(t *testing.T) (net.Listener, string) {
			ln, err := Listen("127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			return ln, ln.Addr().String()
		},
		"unix": func(t *testing.T) (net.Listener, string) {
			sock := filepath.Join(t.TempDir(), "hc.sock")
			ln, err := Listen("unix://" + sock)
			if err != nil {
				t.Fatal(err)
			}
			return ln, "unix://" + sock
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			ln, ep := mk(t)
			defer ln.Close()

			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := ln.Accept()
				if err == nil {
					accepted <- c
				}
			}()

			c, err := Dial(ep)
			if err != nil {
				t.Fatalf("Dial(%q): %v", ep, err)
			}
			defer c.Close()

			cw, ok := c.(interface{ CloseWrite() error })
			if !ok {
				t.Fatalf("%T does not implement CloseWrite", c)
			}
			if _, err := c.Write([]byte("half")); err != nil {
				t.Fatal(err)
			}
			if err := cw.CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}

			var srv net.Conn
			select {
			case srv = <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("no accept")
			}
			defer srv.Close()

			srv.SetReadDeadline(time.Now().Add(5 * time.Second))
			b, err := io.ReadAll(srv)
			if err != nil {
				t.Fatalf("server read: %v", err)
			}
			if string(b) != "half" {
				t.Fatalf("server saw %q, want %q", b, "half")
			}
			// Reverse direction still open after the peer's half-close.
			if _, err := srv.Write([]byte("back")); err != nil {
				t.Fatalf("server write after peer CloseWrite: %v", err)
			}
			buf := make([]byte, 4)
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Fatalf("client read after own CloseWrite: %v", err)
			}
			if string(buf) != "back" {
				t.Fatalf("client saw %q", buf)
			}
		})
	}
}

// TestDialWritesNothing pins the transport-layer contract: no banner, no
// handshake. A parked 'D' conn is byte-silent until the application writes.
func TestDialWritesNothing(t *testing.T) {
	for _, ep := range []string{"tcp", "unix"} {
		t.Run(ep, func(t *testing.T) {
			var ln net.Listener
			var dialEP string
			if ep == "tcp" {
				l, err := Listen("127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				ln, dialEP = l, l.Addr().String()
			} else {
				sock := filepath.Join(t.TempDir(), "q.sock")
				l, err := Listen("unix://" + sock)
				if err != nil {
					t.Fatal(err)
				}
				ln, dialEP = l, "unix://"+sock
			}
			defer ln.Close()

			accepted := make(chan net.Conn, 1)
			go func() {
				c, err := ln.Accept()
				if err == nil {
					accepted <- c
				}
			}()

			c, err := Dial(dialEP)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()

			var srv net.Conn
			select {
			case srv = <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("no accept")
			}
			defer srv.Close()

			buf := make([]byte, 8)
			srv.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, err := srv.Read(buf)
			if n != 0 {
				t.Fatalf("transport wrote %d bytes on dial: %q", n, buf[:n])
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("want read timeout with zero bytes, got %v", err)
			}

			// The application's first write is the first byte on the wire.
			if _, err := c.Write([]byte{'D', 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			srv.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(srv, buf[:4]); err != nil {
				t.Fatalf("read type frame: %v", err)
			}
			if string(buf[:4]) != "D\x00\x00\x00" {
				t.Fatalf("first bytes on the wire = % x", buf[:4])
			}
		})
	}
}

func TestVsockUnsupported(t *testing.T) {
	e, err := Parse("vsock://3:4777")
	if err != nil {
		t.Fatalf("vsock must parse: %v", err)
	}
	if e.Port() != 4777 {
		t.Fatalf("vsock Port() = %d", e.Port())
	}
	if _, err := Dial("vsock://3:4777"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial vsock err = %v, want ErrUnsupported", err)
	}
	if _, err := DialTimeout("vsock://3:4777", time.Second); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DialTimeout vsock err = %v, want ErrUnsupported", err)
	}
	if _, err := Listen("vsock://3:4777"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Listen vsock err = %v, want ErrUnsupported", err)
	}
}
