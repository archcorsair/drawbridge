package podmanaddr

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
)

func ref(t *testing.T, spec string) vmprovider.Ref {
	t.Helper()
	r, err := vmprovider.ParseRef(spec)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", spec, err)
	}
	return r
}

// No record is a refusal with the one command that creates one, never a
// plausible-looking default endpoint: dialing a port nobody chose is how a
// daemon ends up authenticating against the wrong peer.
func TestNoRecordRefusesWithTheRemedy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	got := Resolve(ref(t, "podman:spike"))
	if got.Endpoint != "" {
		t.Fatalf("Endpoint = %q with no record, want empty", got.Endpoint)
	}
	if got.Source != Source {
		t.Fatalf("Source = %q, want %q", got.Source, Source)
	}
	if !strings.Contains(got.Note, "drawbridge up podman:spike") {
		t.Fatalf("Note %q does not name the remedy", got.Note)
	}
}

// A live endpoint resolves clean: no note, because for podman the loopback
// publish IS the direct path and there is nothing to warn about.
func TestLiveEndpointResolvesWithoutANote(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	write(t, r, "tcp://"+ln.Addr().String())
	got := Resolve(r)
	if got.Endpoint != "tcp://"+ln.Addr().String() {
		t.Fatalf("Endpoint = %q, want the recorded one", got.Endpoint)
	}
	if got.Source != Source {
		t.Fatalf("Source = %q, want %q", got.Source, Source)
	}
	if got.Note != "" {
		t.Fatalf("Note = %q, want none for a reachable endpoint", got.Note)
	}
}

// A machine that is stopped (or a user session that ended, which is
// indistinguishable from it) still resolves to its endpoint: the daemon's
// reconnect backoff is the right response, and the note says where to look.
func TestRefusedEndpointKeepsTheAddressAndExplains(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing holds it now

	write(t, r, "tcp://"+addr)
	got := Resolve(r)
	if got.Endpoint != "tcp://"+addr {
		t.Fatalf("Endpoint = %q, want the recorded one even when refused", got.Endpoint)
	}
	for _, want := range []string{"has not published", "podman machine ssh spike", "journalctl -u drawbridge-agent"} {
		if !strings.Contains(got.Note, want) {
			t.Fatalf("Note %q does not mention %q", got.Note, want)
		}
	}
}

// Branch A publishes a loopback TCP port and nothing else. A record naming
// another scheme was written by a build that knows something this one does
// not.
func TestNonTCPRecordIsRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")
	write(t, r, "unix:///tmp/drawbridge-podman.sock")
	got := Resolve(r)
	if got.Endpoint != "" {
		t.Fatalf("Endpoint = %q, want a refusal", got.Endpoint)
	}
	if !strings.Contains(got.Note, "not a tcp endpoint") {
		t.Fatalf("Note = %q", got.Note)
	}
}

// A record we cannot parse must not read as "absent" and must not read as
// "fine": both would send the caller somewhere.
func TestBrokenRecordIsRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")
	p, err := vmrecord.Path(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Resolve(r)
	if got.Endpoint != "" || got.Note == "" {
		t.Fatalf("Resolve on a broken record = %+v, want an empty endpoint and a note", got)
	}
}

func write(t *testing.T, r vmprovider.Ref, endpoint string) {
	t.Helper()
	if err := vmrecord.Write(r, vmrecord.Record{
		Transport: vmrecord.TransportGvproxyPublish,
		Endpoint:  endpoint,
		VMType:    "libkrun",
		SSH:       vmrecord.SSH{Port: 57446, Identity: "/Users/u/.local/share/containers/podman/machine/machine", User: "core"},
	}); err != nil {
		t.Fatal(err)
	}
}
