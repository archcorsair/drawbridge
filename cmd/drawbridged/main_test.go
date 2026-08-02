package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/macsync"
)

// The root path must never widen the mirror bind address. This is the whole
// enforcement — there is no override flag — so the table is the contract.
func TestCheckMirrorIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		euid    int
		ip      string
		wantErr bool
	}{
		{"root loopback v4", 0, "127.0.0.1", false},
		{"root loopback v4 alias", 0, "127.0.0.2", false},
		{"root loopback v6", 0, "::1", false},
		{"root wildcard", 0, "0.0.0.0", true},
		{"root wildcard v6", 0, "::", true},
		{"root empty means wildcard", 0, "", true},
		{"root lan address", 0, "192.168.64.1", true},
		{"root hostname is not decidable", 0, "localhost", true},
		{"unprivileged wildcard is the operator's own foot", 501, "0.0.0.0", false},
		{"unprivileged lan", 501, "192.168.64.1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMirrorIP(tc.euid, tc.ip)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkMirrorIP(%d, %q) = %v, wantErr=%v", tc.euid, tc.ip, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("error %q does not say why", err)
			}
		})
	}
}

// One parser serves -udp and -skip, and `-skip ""` has to survive it as an
// empty list rather than an error — that spelling is the documented way to
// turn the skip-list off.
func TestParsePorts(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []uint16
	}{
		{"", nil},
		{"   ", nil},
		{"22", []uint16{22}},
		{" 22 , 5353 ", []uint16{22, 5353}},
		{"22,22", []uint16{22, 22}}, // duplicates collapse in the set, not here
		{"65535", []uint16{65535}},
	} {
		got, err := parsePorts(tc.in)
		if err != nil {
			t.Fatalf("parsePorts(%q) = %v", tc.in, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("parsePorts(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("parsePorts(%q) = %v, want %v", tc.in, got, tc.want)
			}
		}
	}
	for _, bad := range []string{"0", "22,0", "70000", "-1", "abc", "22,", ",22", "2 2"} {
		if _, err := parsePorts(bad); err == nil {
			t.Fatalf("parsePorts(%q) accepted", bad)
		}
	}
	// The shipped default has to be parseable by the code that consumes it,
	// and it stays exactly {22}: a longer default list is not cheaply
	// reversible once users depend on its entries.
	def, err := parsePorts(defaultSkip)
	if err != nil || len(def) != 1 || def[0] != 22 {
		t.Fatalf("default skip-list %q = %v, %v; want [22]", defaultSkip, def, err)
	}
	if defaultSkip != install.DefaultSkip {
		t.Fatalf("daemon default %q != install default %q — an installed daemon would differ from an ad-hoc one", defaultSkip, install.DefaultSkip)
	}
}

// The sync direction's half of the skip-list rides the same Exclude seam as
// the agent port and the mirror self-ports.
func TestNewExclude(t *testing.T) {
	const agentPort = 4777
	mirrored := func(proto string, port uint16) bool { return proto == "tcp" && port == 9000 }
	ex := newExclude(agentPort, map[uint16]bool{22: true}, mirrored)

	l := func(proto string, port uint16) macsync.Listener {
		return macsync.Listener{Proto: proto, Port: port, Addr: netip.MustParseAddr("127.0.0.1")}
	}
	for _, tc := range []struct {
		l    macsync.Listener
		want bool
		why  string
	}{
		{l("tcp", 22), true, "skip-list"},
		{l("udp", 22), true, "skip-list covers the port, not one protocol"},
		{l("tcp", agentPort), true, "the transport's own port"},
		{l("tcp", 9000), true, "our own mirror, syncing it would bounce guest traffic through the Mac"},
		{l("tcp", 5432), false, "a real Mac service"},
		{l("udp", 9000), false, "not mirrored for udp"},
	} {
		if got := ex(tc.l); got != tc.want {
			t.Fatalf("exclude(%s :%d) = %v, want %v (%s)", tc.l.Proto, tc.l.Port, got, tc.want, tc.why)
		}
	}

	// An empty skip-list excludes only infrastructure.
	ex = newExclude(agentPort, map[uint16]bool{}, mirrored)
	if ex(l("tcp", 22)) {
		t.Fatal("-skip \"\" still excluded :22 from the sync")
	}
}
