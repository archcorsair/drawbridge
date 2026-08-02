package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
)

// The daemon section is additive (docs/doctor.md §D7): on a Mac where no
// socket answers, `status` prints exactly what it printed before the
// introspection substrate existed. Byte-identical, not merely similar —
// scripts read this output.
func TestStatusDaemonSectionIsSilentWithoutSockets(t *testing.T) {
	var buf bytes.Buffer
	renderDaemons(&buf, asciiStyles(), nil, nil)
	if buf.Len() != 0 {
		t.Fatalf("no daemon answered and status printed:\n%s", buf.String())
	}
}

func TestStatusDaemonSection(t *testing.T) {
	snap := &introspect.Snapshot{
		Path:   introspect.RootSocketPath,
		Usable: true,
		State: introspect.State{
			Schema: introspect.Schema, Version: "v0.1.0", PID: 4242, EUID: 0,
			VM:         introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
			Resolution: introspect.Resolution{Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct"},
			Auth:       introspect.Auth{Mode: introspect.AuthModeStaticHMACv1, SecretState: introspect.SecretOK},
			Mirror: introspect.Mirror{SessionUp: true, Entries: []introspect.MirrorEntry{
				{Proto: "tcp", Port: 8080, State: introspect.EntryBound},
				{Proto: "tcp", Port: 22, State: introspect.EntrySkipped},
			}},
			Sync: introspect.Sync{SessionUp: true, Advertised: []introspect.Advertised{{Proto: "tcp", Port: 5432}}, PoolParked: 4},
		},
	}
	var buf bytes.Buffer
	renderDaemons(&buf, asciiStyles(), []*introspect.Snapshot{snap}, nil)
	out := buf.String()
	for _, want := range []string{
		"daemon:  v0.1.0 (pid 4242, euid 0)",
		"vm:        colima:colima",
		"endpoint:  tcp://192.168.64.5:4777 (source=vznat-direct)",
		"auth:      static-hmac-v1 (secret ok)",
		"mirror:    session up, 1 bound of 2 entries",
		"sync:      session up, 1 advertised, 4 parked",
		"socket:    " + introspect.RootSocketPath,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status daemon section has no %q:\n%s", want, out)
		}
	}
}

// A payload this build cannot read is one warn line, never silence and never
// a pretense that its fields mean anything (D4, §3.3).
func TestStatusDaemonSectionSkewAndProblems(t *testing.T) {
	skewed := &introspect.Snapshot{Path: "/tmp/s.sock", State: introspect.State{Schema: 2, Version: "v9"}}
	var buf bytes.Buffer
	renderDaemons(&buf, asciiStyles(), []*introspect.Snapshot{skewed}, []error{errors.New("introspect: unreadable snapshot: /tmp/bad.sock")})
	out := buf.String()
	if !strings.Contains(out, "speaks introspection schema 2, this CLI knows 1") {
		t.Errorf("no schema-skew line:\n%s", out)
	}
	if !strings.Contains(out, "unreadable snapshot") {
		t.Errorf("an unreadable socket was swallowed:\n%s", out)
	}
	if strings.Contains(out, "endpoint:") {
		t.Errorf("a skewed payload's fields were rendered as if usable:\n%s", out)
	}
}

// The calm default: a live daemon's snapshot is the whole status — one
// compact block, no launchctl inference, no paths, no log tail. Skew and
// unreadable-socket lines print in both modes: truncating a health report
// is calm, truncating a problem is silence.
func TestRenderCalmStatus(t *testing.T) {
	snap := &introspect.Snapshot{
		Path:   introspect.RootSocketPath,
		Usable: true,
		State: introspect.State{
			Schema: introspect.Schema, Version: "v0.1.0", PID: 4242, EUID: 0,
			VM:         introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
			Resolution: introspect.Resolution{Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct"},
			Auth:       introspect.Auth{Mode: introspect.AuthModeStaticHMACv1, SecretState: introspect.SecretOK},
			Mirror:     introspect.Mirror{SessionUp: true, Entries: []introspect.MirrorEntry{{Proto: "tcp", Port: 8080, State: introspect.EntryBound}}},
			Sync:       introspect.Sync{SessionUp: true, Advertised: []introspect.Advertised{{Proto: "tcp", Port: 5432}}, PoolParked: 4},
		},
	}
	running := install.Status{PlistInstalled: true, BinaryInstalled: true, Loaded: true, State: "running", PID: 4242,
		LogTail: []string{"drawbridged: mirroring guest :8080 on 127.0.0.1:8080"}}

	var b bytes.Buffer
	if !renderCalmStatus(&b, asciiStyles(), running, []*introspect.Snapshot{snap}, nil) {
		t.Fatal("a usable snapshot did not render calm status")
	}
	out := b.String()
	for _, want := range []string{
		"drawbridged  running · pid 4242 · v0.1.0 · installed (launchd)",
		"endpoint:  tcp://192.168.64.5:4777 (vznat-direct)",
		"session up · 1 bound of 1 entries",
		"session up · 1 advertised · 4 parked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("calm status missing %q:\n%s", want, out)
		}
	}
	for name, absent := range map[string]string{
		"plist path": "plist:", "binary path": "binary:", "launchd line": "launchd:", "log tail": "| ",
	} {
		if strings.Contains(out, absent) {
			t.Errorf("calm status leaked %s:\n%s", name, out)
		}
	}

	// A foreground daemon (pid unmatched, euid 501) names its flavor.
	fg := snap
	fgState := snap.State
	fgState.PID, fgState.EUID = 7777, 501
	fg = &introspect.Snapshot{Path: "/tmp/u.sock", Usable: true, State: fgState}
	b.Reset()
	renderCalmStatus(&b, asciiStyles(), install.Status{}, []*introspect.Snapshot{fg}, nil)
	if !strings.Contains(b.String(), "foreground (euid 501)") {
		t.Errorf("foreground flavor missing:\n%s", b.String())
	}

	// No usable snapshot → not handled; the caller falls back to the full
	// form, where the launchctl half and the log tail are the diagnosis.
	b.Reset()
	if renderCalmStatus(&b, asciiStyles(), running, nil, nil) {
		t.Fatal("calm status claimed to handle an empty snapshot list")
	}

	// Skew still prints even in calm mode.
	b.Reset()
	skewed := &introspect.Snapshot{Path: "/tmp/s.sock", State: introspect.State{Schema: 2, Version: "v9"}}
	renderCalmStatus(&b, asciiStyles(), running, []*introspect.Snapshot{skewed}, nil)
	if !strings.Contains(b.String(), "speaks introspection schema 2") {
		t.Errorf("calm mode swallowed the skew line:\n%s", b.String())
	}
}
