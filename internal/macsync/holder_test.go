package macsync

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func ml(port uint16, addr string, v6only bool) Listener {
	return Listener{Proto: "tcp", Port: port, Addr: netip.MustParseAddr(addr), V6Only: v6only}
}

// Which Mac holders a mirror bound at mirrorIP:port would shadow (audit H1).
func TestWildcardHolder(t *testing.T) {
	const p = 5000
	v4 := netip.MustParseAddr("127.0.0.1")
	v6 := netip.MustParseAddr("::1")
	cases := []struct {
		name   string
		ls     []Listener
		mirror netip.Addr
		taken  bool
	}{
		{"dual-stack :: serves 127.0.0.1", []Listener{ml(p, "::", false)}, v4, true},
		{"0.0.0.0 serves 127.0.0.1", []Listener{ml(p, "0.0.0.0", false)}, v4, true},
		{"v6-only :: does not serve 127.0.0.1", []Listener{ml(p, "::", true)}, v4, false},
		{"::1 does not serve 127.0.0.1", []Listener{ml(p, "::1", true)}, v4, false},
		{"exact 127.0.0.1 is the bind's job", []Listener{ml(p, "127.0.0.1", false)}, v4, false},
		{"LAN address does not serve loopback", []Listener{ml(p, "192.168.1.5", false)}, v4, false},
		{"other port", []Listener{ml(p+1, "::", false), ml(p+1, "0.0.0.0", false)}, v4, false},
		{"udp is not a tcp holder", []Listener{{Proto: "udp", Port: p, Addr: netip.MustParseAddr("0.0.0.0")}}, v4, false},
		{"v6-only and v4 twin: the twin counts", []Listener{ml(p, "::", true), ml(p, "0.0.0.0", false)}, v4, true},
		{"::1 mirror: 0.0.0.0 does not serve it", []Listener{ml(p, "0.0.0.0", false)}, v6, false},
		{"::1 mirror: v6-only :: serves it", []Listener{ml(p, "::", true)}, v6, true},
		{"::1 mirror: dual-stack :: serves it", []Listener{ml(p, "::", false)}, v6, true},
	}
	for _, c := range cases {
		_, got := WildcardHolder(c.ls, p, c.mirror)
		if got != c.taken {
			t.Errorf("%s: taken = %v, want %v", c.name, got, c.taken)
		}
	}
}

func TestHolderCheckNamesTheHolder(t *testing.T) {
	poll := func() ([]Listener, error) {
		return []Listener{ml(5000, "::", false), ml(5001, "0.0.0.0", false), ml(5002, "::", true)}, nil
	}
	check := HolderCheck("127.0.0.1", poll)
	if h, known := check("tcp", 5000); !known || !strings.Contains(h, "[::]:5000") || !strings.Contains(h, "dual-stack") {
		t.Fatalf("dual-stack holder = %q known=%v", h, known)
	}
	if h, known := check("tcp", 5001); !known || h != "0.0.0.0:5001" {
		t.Fatalf("v4 wildcard holder = %q known=%v", h, known)
	}
	if h, known := check("tcp", 5002); !known || h != "" {
		t.Fatalf("v6-only holder = %q known=%v, want known and free", h, known)
	}
	if h, known := check("tcp", 5003); !known || h != "" {
		t.Fatalf("unheld port = %q known=%v, want known and free", h, known)
	}
}

// Every way the read cannot be trusted is "unknown", and unknown is neither
// free nor taken: the mirror falls back to its own bind result. Empty above
// all — the macOS 27.0b4 per-app filter returns exactly that, with no error.
func TestHolderCheckUnknowns(t *testing.T) {
	full := func() ([]Listener, error) { return []Listener{ml(5000, "::", false)}, nil }
	cases := []struct {
		name     string
		mirrorIP string
		poll     func() ([]Listener, error)
		proto    string
	}{
		{"empty enumeration", "127.0.0.1", func() ([]Listener, error) { return nil, nil }, "tcp"},
		{"poll error", "127.0.0.1", func() ([]Listener, error) { return nil, errors.New("torn") }, "tcp"},
		{"udp", "127.0.0.1", full, "udp"},
		{"non-literal mirror ip", "localhost", full, "tcp"},
	}
	for _, c := range cases {
		h, known := HolderCheck(c.mirrorIP, c.poll)(c.proto, 5000)
		if known || h != "" {
			t.Errorf("%s: holder=%q known=%v, want unknown", c.name, h, known)
		}
	}
}

// One fresh read per call: a holder that appeared since the last call is
// seen, which is the property the syncer's 75 ms-stale, post-Exclude set
// cannot give the mirror.
func TestHolderCheckReadsFreshEachCall(t *testing.T) {
	var ls []Listener
	calls := 0
	check := HolderCheck("127.0.0.1", func() ([]Listener, error) { calls++; return ls, nil })
	ls = []Listener{ml(9, "127.0.0.1", false)}
	if h, _ := check("tcp", 5000); h != "" {
		t.Fatalf("free port reported held by %q", h)
	}
	ls = append(ls, ml(5000, "0.0.0.0", false))
	if h, _ := check("tcp", 5000); h == "" {
		t.Fatal("holder that appeared since the last call was missed")
	}
	if calls != 2 {
		t.Fatalf("polled %d times for 2 checks", calls)
	}
}
