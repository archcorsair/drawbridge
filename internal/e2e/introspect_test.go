package e2e

// The introspection leg (docs/doctor.md §3): a daemon pair assembled
// in-process exactly as the other legs assemble one — through the
// newMirror/`Auth: macAuth` seam — serving the read-only snapshot socket the
// CLI reads. Everything else in internal/introspect is unit-tested against
// fabricated state; this is the one place the payload is assembled from a
// live agent's events, which is the only way to catch a snapshot that is
// correct in isolation and empty in practice.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/macsync"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// introspectPort is this leg's own guest listener, in the same 479xx block
// as the other suites and outside the guest autobind range.
const introspectPort = 47996

// shortSockDir is a temp directory short enough for a unix socket path:
// t.TempDir() spends most of sun_path's 104 bytes on $TMPDIR plus the test's
// name, which is the very limit introspect.CheckPath exists to report.
func shortSockDir(t *testing.T) string {
	t.Helper()
	base := ""
	if fi, err := os.Stat("/tmp"); err == nil && fi.IsDir() {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "dbe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestIntrospectionSnapshotFromLiveDaemon(t *testing.T) {
	requireE2E(t)
	requireAttributableMirror(t, "0.0.0.0", introspectPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newMirror(agentAddr)
	s := &macsync.Syncer{
		AgentAddr: agentAddr,
		Auth:      macAuth,
		Exclude: func(l macsync.Listener) bool {
			return l.Port == agentPort || m.Mirrors(l.Proto, l.Port)
		},
	}
	go m.Run(ctx)
	go s.Run(ctx)

	// The daemon's own snapshot closure, assembled the way cmd/drawbridged
	// assembles it: the live mirror and syncer views, plus the auth posture
	// re-read per snapshot.
	snapshot := func() introspect.State {
		return introspect.State{
			Schema:    introspect.Schema,
			Version:   buildinfo.Version,
			PID:       os.Getpid(),
			EUID:      os.Geteuid(),
			StartedAt: time.Now(),
			VM:        introspect.VM{Ref: vmRef.Spec, Provider: vmRef.Provider, Instance: vmRef.Instance},
			MirrorIP:  "127.0.0.1",
			Auth:      snapshotAuth(macAuth.SecretFile),
			Mirror:    m.Snapshot(),
			Sync:      s.Snapshot(),
		}
	}
	path := filepath.Join(shortSockDir(t), "i.sock")
	srv, err := introspect.Listen(path, os.Geteuid(), snapshot)
	if err != nil {
		t.Fatalf("introspect.Listen(%s): %v", path, err)
	}
	defer srv.Close()
	go srv.Serve()

	// A guest listener, so the payload has to carry something the agent
	// reported rather than an empty table that would pass every assertion.
	unit := unitName + "-introspect"
	guest(t, fmt.Sprintf("systemctl stop %s 2>/dev/null; systemctl reset-failed %s 2>/dev/null; true", unit, unit))
	if out, err := guest(t, fmt.Sprintf(
		"systemd-run --unit=%s --collect python3 -m http.server %d --bind 0.0.0.0", unit, introspectPort)); err != nil {
		t.Fatalf("start guest http server: %v: %s", err, out)
	}
	t.Cleanup(func() { guest(t, fmt.Sprintf("systemctl stop %s", unit)) })

	deadline := time.Now().Add(20 * time.Second)
	for !m.Mirrors("tcp", introspectPort) {
		if time.Now().After(deadline) {
			t.Fatalf("guest tcp :%d never mirrored, so there is nothing to introspect", introspectPort)
		}
		time.Sleep(200 * time.Millisecond)
	}

	snap, err := introspect.Fetch(path, 2*time.Second)
	if err != nil {
		t.Fatalf("Fetch(%s): %v", path, err)
	}
	if !snap.Usable || snap.State.Schema != introspect.Schema {
		t.Fatalf("schema = %d (usable=%v), want %d", snap.State.Schema, snap.Usable, introspect.Schema)
	}
	if snap.State.Version != buildinfo.Version {
		t.Errorf("version = %q, want %q", snap.State.Version, buildinfo.Version)
	}
	if !snap.State.Mirror.SessionUp {
		t.Error("mirror session reported down while the 'E' stream is delivering events")
	}
	var found *introspect.MirrorEntry
	for i, e := range snap.State.Mirror.Entries {
		if e.Proto == "tcp" && e.Port == introspectPort {
			found = &snap.State.Mirror.Entries[i]
		}
	}
	if found == nil {
		t.Fatalf("no entry for the guest listener this leg created (tcp/%d); entries: %+v", introspectPort, snap.State.Mirror.Entries)
	}
	if found.State != introspect.EntryBound {
		t.Fatalf("tcp/%d is %q, want %q — the mirror holds the Mac-side port", introspectPort, found.State, introspect.EntryBound)
	}

	// The auth block reflects the harness's own posture: the seam every leg
	// runs through is the one the payload reports.
	wantMode := introspect.AuthModeNone
	if sec, err := macAuth.Secret(); err == nil && sec != nil {
		wantMode = introspect.AuthModeStaticHMACv1
	}
	if snap.State.Auth.Mode != wantMode {
		t.Errorf("auth mode = %q, want %q (secret file %q)", snap.State.Auth.Mode, wantMode, macAuth.SecretFile)
	}
	t.Logf("snapshot: schema %d, %s, mirror %d entries (session up), sync %d advertised, auth %s",
		snap.State.Schema, snap.State.Version, len(snap.State.Mirror.Entries), len(snap.State.Sync.Advertised), snap.State.Auth.Mode)
}

// snapshotAuth is cmd/drawbridged's authState: the mode and the file's
// usability, never bytes, proofs, or digests.
func snapshotAuth(path string) introspect.Auth {
	a := introspect.Auth{Mode: introspect.AuthModeNone, SecretPath: path, SecretState: introspect.SecretAbsent}
	switch sec, err := transportauth.LoadOptional(path); {
	case err != nil:
		a.Mode, a.SecretState = introspect.AuthModeStaticHMACv1, introspect.SecretMalformed
	case sec != nil:
		a.Mode, a.SecretState = introspect.AuthModeStaticHMACv1, introspect.SecretOK
	}
	return a
}
