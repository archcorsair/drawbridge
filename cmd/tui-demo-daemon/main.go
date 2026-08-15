// Command tui-demo-daemon serves storytelling-rich canned introspection
// snapshots so `drawbridge tui` can be exercised, screenshotted and recorded
// with zero VMs, zero containers and zero sudo.
//
// It binds the same per-VM user sockets a real foreground daemon would, under
// a fake home directory, so the unmodified TUI discovers them through its
// ordinary Discover path:
//
//	go run ./cmd/tui-demo-daemon -home /tmp/dbtui &
//	HOME=/tmp/dbtui DRAWBRIDGE_TUI_DEMO_DOCTOR=/tmp/dbtui/doctor drawbridge tui
//
// Build the CLI stamped with the fixture's version so the skew chip stays
// quiet for the healthy daemon and fires only for the deliberately stale one:
//
//	go build -ldflags "-X github.com/archcorsair/drawbridge/internal/buildinfo.Version=v0.1.0" -o /tmp/drawbridge ./cmd/drawbridge
//
// The snapshots are a scripted timeline keyed to seconds since the daemon
// started: a listener appears, a bound port flips to bind-failed, a refusal
// storm streams in, a degraded daemon's mirror session flaps. That makes
// recordings deterministic enough for demo gifs without any replay machinery:
// start the daemon, start recording, the same story plays.
//
// The scene, one socket per posture:
//
//   - colima:colima  healthy and busy: vznat-direct endpoint, auth ok, both
//     sessions up, mirrors in every state, the scripted flips above
//   - lima:dev       degraded: ssh-forwarder fallback with the resolver's
//     Note verbatim, version-skewed against the CLI, secret
//     absent with the refusal storm that posture causes, sync
//     session down, mirror session flapping
//   - lima:scratch   speaks introspection schema 2: the skew card and a
//     read-only switcher row
//   - broken         answers with bytes that are not a snapshot at all
//   - fight          optional (-sockets ...,fight): a fake ROOT daemon
//     claiming the same VM as colima, the D8 fighting-daemons
//     posture without sudo; point the consumer at it with
//     DRAWBRIDGE_INTROSPECT_ROOT
//
// The doctor view cannot be fed through a socket (a gather probes the machine
// in-process), so the fixture writes canned doctor.Report JSON into
// <home>/doctor and `drawbridge tui` substitutes it when
// DRAWBRIDGE_TUI_DEMO_DOCTOR names that directory: findings across all five
// statuses, and a probe run that upgrades the half-close finding so `p`
// visibly buys something.
//
// This is demo scaffolding only. It must never grow into a test double for
// daemon behavior: the introspect package's own tests do that against the
// real server. It links no charm code; the TUI half of every demo is the
// production `drawbridge tui` binary.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/archcorsair/drawbridge/internal/introspect"
)

// demoVersion is what the healthy daemons report. The demo runner builds the
// CLI with the same string so the skew chip stays quiet where it should and
// fires only for the deliberately stale daemon below.
const demoVersion = "v0.1.0"

// staleVersion is what lima:dev reports: one release behind, so the summary
// carries the skew chip with its remedy.
const staleVersion = "v0.0.9"

func main() {
	home := flag.String("home", "/tmp/dbtui", "fake HOME to bind sockets under (kept short: sun_path caps at 104 bytes); run the TUI with HOME set to the same path")
	sockets := flag.String("sockets", "colima,dev,skew,broken", "comma-separated subset of {colima,dev,skew,broken,fight} to serve")
	flag.Parse()

	runDir := filepath.Join(*home, "Library", "Application Support", "drawbridge", "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		log.Fatal(err)
	}

	want := map[string]bool{}
	for _, s := range strings.Split(*sockets, ",") {
		want[strings.TrimSpace(s)] = true
	}

	start := time.Now()
	serve := func(path string, snap func() introspect.State) {
		srv, err := introspect.Listen(path, os.Geteuid(), snap)
		if err != nil {
			log.Fatalf("%s: %v", path, err)
		}
		go srv.Serve()
		fmt.Println("serving", path)
	}

	if want["colima"] {
		serve(filepath.Join(runDir, "introspect-colima-colima.sock"),
			func() introspect.State { return colimaState(start) })
	}
	if want["dev"] {
		serve(filepath.Join(runDir, "introspect-lima-dev.sock"),
			func() introspect.State { return devState(start) })
	}
	if want["skew"] {
		// Schema 2 on the wire: the TUI must render the skew card from the two
		// frozen fields and nothing else.
		serve(filepath.Join(runDir, "introspect-lima-scratch.sock"),
			func() introspect.State { return introspect.State{Schema: 2, Version: "v0.2.0"} })
	}
	if want["broken"] {
		serveGarbage(filepath.Join(runDir, "introspect-lima-broken.sock"))
	}
	if want["fight"] {
		// A fake ROOT daemon claiming the same VM as the colima socket above:
		// the D8 fighting-daemons posture, demoable without sudo.
		path := filepath.Join(*home, "root.sock")
		serve(path, func() introspect.State { return rootState(start) })
		fmt.Println("fake root daemon: export " + introspect.EnvRootSocket + "=" + path)
	}

	doctorDir := filepath.Join(*home, "doctor")
	if err := writeCannedDoctor(doctorDir); err != nil {
		log.Fatal(err)
	}
	fmt.Println("canned doctor reports:", doctorDir)
	fmt.Println()
	fmt.Println("run the TUI against this fixture:")
	fmt.Printf("  HOME=%s DRAWBRIDGE_TUI_DEMO_DOCTOR=%s drawbridge tui\n", *home, doctorDir)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}

// serveGarbage answers with bytes that are not a snapshot, so the TUI's
// unreadable-socket posture (the `!` notice line, the read-only switcher row)
// has something real to chew on.
func serveGarbage(path string) {
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("drawbridged panic: this is not a snapshot\n"))
			conn.Close()
		}
	}()
	fmt.Println("serving", path, "(garbage)")
}

// colimaState is the healthy, busy daemon: the screen a happy user watches.
// Timeline: a dev server appears at t+6, a bind race is lost at t+10 (bound
// flips to bind-failed: the change a 1 Hz snapshot loop exists to catch), a
// debugger listener appears at t+16.
func colimaState(start time.Time) introspect.State {
	now := time.Now()
	t := now.Sub(start)
	up := 2*time.Hour + 14*time.Minute

	// Counter fakes (PerEntryCounters below): busy services with live
	// traffic, so the detail strip's traffic line has a story to tell.
	entries := []introspect.MirrorEntry{
		{Proto: "tcp", Port: 8080, State: introspect.EntryBound, Since: now.Add(-97 * time.Minute),
			Conns: 3, RxBytes: 48_213_902, TxBytes: 3_144_265, LastActiveAt: now.Add(-2 * time.Second)},
		{Proto: "tcp", Port: 3000, State: introspect.EntryBound, Since: now.Add(-52 * time.Minute),
			Conns: 1, RxBytes: 1_204_112, TxBytes: 226_540, LastActiveAt: now.Add(-45 * time.Second)},
		{Proto: "udp", Port: 5353, State: introspect.EntryBound, Since: now.Add(-61 * time.Minute),
			RxBytes: 88_204, TxBytes: 12_930, LastActiveAt: now.Add(-9 * time.Second)},
		{Proto: "tcp", Port: 22, State: introspect.EntrySkipped, Since: start.Add(-up)},
	}
	lastEvent := now.Add(-12 * time.Second)
	if t >= 6*time.Second {
		entries = append(entries, introspect.MirrorEntry{
			Proto: "tcp", Port: 5173, State: introspect.EntryBound, Since: start.Add(6 * time.Second),
			Conns: 2, RxBytes: 402_113, TxBytes: 1_929_004, LastActiveAt: now.Add(-1 * time.Second)})
		lastEvent = start.Add(6 * time.Second)
	}
	// tcp 5000 is bound for the first ten seconds, then loses its Mac port to
	// a forwarder and reports bind-failed: live evidence of the state doctor's
	// ring can only tell you about after the fact. Its counters vanish with
	// the binding, exactly as the real daemon's do.
	if t < 10*time.Second {
		entries = append(entries, introspect.MirrorEntry{
			Proto: "tcp", Port: 5000, State: introspect.EntryBound, Since: now.Add(-5 * time.Minute),
			RxBytes: 3_211, TxBytes: 954, LastActiveAt: now.Add(-4 * time.Minute)})
	} else {
		entries = append(entries, introspect.MirrorEntry{
			Proto: "tcp", Port: 5000, State: introspect.EntryBindFailed, Since: start.Add(10 * time.Second)})
		lastEvent = start.Add(10 * time.Second)
	}
	if t >= 16*time.Second {
		entries = append(entries, introspect.MirrorEntry{
			Proto: "tcp", Port: 9229, State: introspect.EntryBound, Since: start.Add(16 * time.Second),
			Conns: 1, RxBytes: 18_112, TxBytes: 7_430, LastActiveAt: now})
		lastEvent = start.Add(16 * time.Second)
	}

	refusals := ringAt(now, start, []scripted{
		{-40 * time.Minute, introspect.IDMirrorSkip, "guest tcp :22 not mirrored (skip list)"},
		{8 * time.Second, introspect.IDReverseDialRefused, "'D' activation named 127.0.0.1:9099: not advertised; refused"},
		{18 * time.Second, introspect.IDMirrorSkip, "guest tcp :22 not mirrored (skip list)"},
	})

	return introspect.State{
		Schema: introspect.Schema, Version: demoVersion, PID: 71234, EUID: 501,
		StartedAt: start.Add(-up),
		VM:        introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
		MirrorIP:  "127.0.0.1",
		Resolution: introspect.Resolution{
			Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct", ResolvedAt: start.Add(-up)},
		Auth: introspect.Auth{Mode: introspect.AuthModeStaticHMACv1, SecretState: introspect.SecretOK,
			SecretPath: "/Users/demo/Library/Application Support/drawbridge/transport-secret-colima-colima"},
		Mirror: introspect.Mirror{
			SessionUp: true, Since: start.Add(-up), LastEventAt: lastEvent,
			Entries: entries, Skip: []uint16{22},
			PerEntryCounters: true,
		},
		Sync: introspect.Sync{
			SessionUp: true, Since: start.Add(-up),
			Advertised: []introspect.Advertised{
				{Proto: "tcp", Port: 3306}, {Proto: "tcp", Port: 5432}, {Proto: "tcp", Port: 6379},
				{Proto: "tcp", Port: 8443},
				{Proto: "tcp", Port: 49410}, {Proto: "tcp", Port: 50122}, {Proto: "tcp", Port: 51873},
				{Proto: "tcp", Port: 53002}, {Proto: "tcp", Port: 54988}, {Proto: "tcp", Port: 56206},
			},
			UDPPorts: []uint16{5353}, PoolParked: 4,
		},
		RecentRefusals: refusals,
	}
}

// devState is the degraded daemon, every warn surface at once: version-skewed
// against the CLI, resolving through the ssh-forwarder fallback with the
// resolver's note verbatim, secret absent (so this side refuses to connect,
// which is the storm below), sync session down, and a mirror session that
// flaps: up for 14 s of every 20 s cycle, entries only while up, so the
// "session down, press d" wording shows the rest of the time. Its Mirror
// deliberately omits PerEntryCounters: a v0.0.9 daemon predates the
// accounting, which is the detail strip's honest-absence demo surface.
func devState(start time.Time) introspect.State {
	now := time.Now()
	up := 11 * time.Minute

	script := []scripted{
		{-3 * time.Minute, introspect.IDAdvertisedNone, "sync session established advertising nothing: Mac listener enumeration came back empty"},
		{-2 * time.Minute, "auth-mac-missing-secret", "guest requires auth and this side has no secret: refusing to connect"},
	}
	// One auth refusal every 2 s from t+4: a storm, not a flood. The ring
	// carries it whole, so the TUI's accumulated log is lossless and the
	// footer badge visibly climbs while you watch.
	for i := 0; i < 300; i++ {
		script = append(script, scripted{
			4*time.Second + time.Duration(i)*2*time.Second,
			"auth-mac-missing-secret",
			fmt.Sprintf("guest requires auth and this side has no secret: refusing to connect (attempt %d)", i+3),
		})
	}

	// The mirror-session flap is phase-locked to the timeline so SINCE reads
	// honestly: the flip time is the phase boundary, not the fetch time.
	const cycle, upFor = 20 * time.Second, 14 * time.Second
	cyc := now.Sub(start) % cycle
	sessionUp := cyc < upFor
	flip := now.Add(-cyc)
	if !sessionUp {
		flip = now.Add(-cyc + upFor)
	}

	mirror := introspect.Mirror{SessionUp: sessionUp, Since: flip, Skip: []uint16{22}}
	if sessionUp {
		mirror.LastEventAt = flip
		mirror.Entries = []introspect.MirrorEntry{
			{Proto: "tcp", Port: 8000, State: introspect.EntryBound, Since: flip},
			{Proto: "tcp", Port: 3000, State: introspect.EntryBindFailed, Since: flip},
			{Proto: "tcp", Port: 22, State: introspect.EntrySkipped, Since: start.Add(-up)},
		}
	}

	return introspect.State{
		Schema: introspect.Schema, Version: staleVersion, PID: 4242, EUID: 501,
		StartedAt: start.Add(-up),
		VM:        introspect.VM{Ref: "lima:dev", Provider: "lima", Instance: "dev"},
		MirrorIP:  "127.0.0.1",
		Resolution: introspect.Resolution{
			Endpoint: "tcp://127.0.0.1:52347", Source: "ssh-forwarder",
			Note:       "Local Network permission denied for this app; vznat-direct unreachable, using the SSH forwarder",
			ResolvedAt: start.Add(-up)},
		Auth: introspect.Auth{Mode: introspect.AuthModeStaticHMACv1, SecretState: introspect.SecretAbsent,
			SecretPath: "/Users/demo/Library/Application Support/drawbridge/transport-secret-lima-dev"},
		Mirror: mirror,
		Sync: introspect.Sync{
			SessionUp: false, Since: now.Add(-3 * time.Minute), PoolParked: 0,
		},
		RecentRefusals: ringAt(now, start, script),
	}
}

// rootState is the fake privileged daemon for the fighting-daemons demo: the
// same VM as colimaState, a different PID, and the mirror entries a daemon
// that keeps losing bind races to its rival would show.
func rootState(start time.Time) introspect.State {
	now := time.Now()
	up := 6 * time.Minute
	return introspect.State{
		Schema: introspect.Schema, Version: demoVersion, PID: 892, EUID: 0,
		StartedAt: start.Add(-up),
		VM:        introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
		MirrorIP:  "127.0.0.1",
		Resolution: introspect.Resolution{
			Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct", ResolvedAt: start.Add(-up)},
		Auth: introspect.Auth{Mode: introspect.AuthModeStaticHMACv1, SecretState: introspect.SecretOK},
		Mirror: introspect.Mirror{
			SessionUp: true, Since: start.Add(-up), LastEventAt: now.Add(-30 * time.Second),
			Entries: []introspect.MirrorEntry{
				{Proto: "tcp", Port: 8080, State: introspect.EntryBindFailed, Since: now.Add(-5 * time.Minute)},
				{Proto: "tcp", Port: 3000, State: introspect.EntryBindFailed, Since: now.Add(-5 * time.Minute)},
				{Proto: "tcp", Port: 22, State: introspect.EntrySkipped, Since: start.Add(-up)},
			},
			Skip:             []uint16{22},
			PerEntryCounters: true,
		},
		Sync: introspect.Sync{SessionUp: true, Since: start.Add(-up), PoolParked: 2},
	}
}

// scripted is one timeline refusal: when (relative to daemon start; negative
// means it predates the recording) and what.
type scripted struct {
	at   time.Duration
	id   string
	line string
}

// ringAt is the daemon-side ring semantics in miniature: everything that has
// happened by now, newest last, capped at RingSize. Timestamps anchor to the
// timeline, never to the fetch: refusal identity is the (At, ID, Line)
// triple, and a timestamp that moved with the fetch would make every fetch's
// ring look brand new to the TUI's accumulator.
func ringAt(now, start time.Time, script []scripted) []introspect.Refusal {
	var out []introspect.Refusal
	for _, s := range script {
		at := start.Add(s.at)
		if at.After(now) {
			continue
		}
		out = append(out, introspect.Refusal{At: at, ID: s.id, Line: s.line})
	}
	if len(out) > introspect.RingSize {
		out = out[len(out)-introspect.RingSize:]
	}
	return out
}

// writeCannedDoctor writes the two canned reports `drawbridge tui` substitutes
// when DRAWBRIDGE_TUI_DEMO_DOCTOR names dir: the plain gather, and the probe
// run that upgrades the half-close finding. The findings tell the same story
// the sockets do, so a viewer can cross-check the dashboard against the
// diagnosis on camera.
func writeCannedDoctor(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, probe := range map[string]bool{"doctor.json": false, "doctor-probe.json": true} {
		b, err := json.MarshalIndent(cannedReport(probe), "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func cannedReport(probe bool) doctor.Report {
	half := doctor.Finding{
		ID:     "half-close",
		Title:  "TCP half-close survives the transport",
		Status: doctor.StatusSkip,
		Remedy: "re-run with p to probe it (~20s+)",
	}
	if probe {
		half = doctor.Finding{
			ID:       "half-close",
			Title:    "TCP half-close survives the transport",
			Status:   doctor.StatusOK,
			Evidence: []string{"probe: FIN forwarded, peer half stayed open 21.3s, data drained after FIN"},
		}
	}
	return doctor.Report{
		CLIVersion: demoVersion,
		RanAt:      time.Now(),
		VM:         "colima:colima",
		Findings: []doctor.Finding{
			{ID: "provider", Title: "a supported VM provider is installed", Status: doctor.StatusOK,
				Evidence: []string{"colima 0.9.2 and lima 2.2.0 at /opt/homebrew/bin"}},
			{ID: "vm-address", Title: "the guest's vmnet address resolves", Status: doctor.StatusOK,
				Evidence: []string{"lease 192.168.64.5 (hw 52:55:55:a5:de:d2) inside 192.168.64.0/24"}},
			{ID: "agent-endpoint", Title: "the agent answers on its control port", Status: doctor.StatusOK},
			{ID: "endpoint-route", Title: "the transport dials the guest directly", Status: doctor.StatusWarn,
				Evidence: []string{
					"lima:dev resolves through the SSH forwarder, not vznat-direct",
					"resolver: Local Network permission denied for this app; vznat-direct unreachable, using the SSH forwarder",
				},
				Remedy: "System Settings > Privacy & Security > Local Network: allow your terminal, then restart drawbridged"},
			{ID: "transport-auth", Title: "both sides hold the same transport secret", Status: doctor.StatusFail,
				Evidence: []string{
					"lima:dev: guest secret configured, Mac secret absent",
					"ring: auth-mac-missing-secret repeating every few seconds",
				},
				Remedy: "drawbridge secret sync lima:dev"},
			{ID: "mirror-binds", Title: "mirrored ports bound without a fight", Status: doctor.StatusFail,
				Evidence: []string{
					"colima:colima tcp/5000 reports bind-failed",
					"lsof: node (pid 8123) holds 127.0.0.1:5000",
				},
				Remedy: "stop the Mac-side listener on 5000, or add 5000 to the skip list"},
			half,
			{ID: "version-skew", Title: "daemon and CLI versions agree", Status: doctor.StatusWarn,
				Evidence: []string{"lima:dev daemon " + staleVersion + " != CLI " + demoVersion},
				Remedy:   "sudo drawbridge install"},
			{ID: "skip-visibility", Title: "the skip list is visible, not silent", Status: doctor.StatusInfo,
				Evidence: []string{"colima:colima and lima:dev skip 22 (default exclusions)"}},
		},
	}
}
