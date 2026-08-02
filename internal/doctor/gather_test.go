package doctor

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// The whole guest script's answer, as a healthy dev VM produces it.
const guestOutputFixture = `kernel=6.8.0-51-generic
btf=yes
cgroup2=yes
systemd=yes
sudo=yes
oci=yes
runc=runc version 1.1.12
crun=
agent-active=active
agent-enabled=enabled
agent-transient=no
agent-version=v0.1.0
guest-ips=192.168.64.2 192.168.5.15
secret=present
secret-mode=600
secret-owner=root:root
secret-size=65
secret-digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
ss-begin
LISTEN 0      4096         0.0.0.0:8080       0.0.0.0:*
LISTEN 0      4096       127.0.0.1:4777       0.0.0.0:*
LISTEN 0      4096    192.168.64.2:4777       0.0.0.0:*
ss-end
`

func TestParseGuestProbe(t *testing.T) {
	g := ParseGuestProbe(guestOutputFixture)
	if !g.Ran || !g.BTF || !g.CGroup2 || !g.Systemd || !g.Sudo || !g.OCI {
		t.Fatalf("flags = %+v", g)
	}
	if g.Kernel != "6.8.0-51-generic" || g.Runc != "runc version 1.1.12" || g.Crun != "" {
		t.Fatalf("versions = %q %q %q", g.Kernel, g.Runc, g.Crun)
	}
	if g.AgentActive != "active" || g.AgentVersion != "v0.1.0" || g.AgentTransient {
		t.Fatalf("agent = %q %q %v", g.AgentActive, g.AgentVersion, g.AgentTransient)
	}
	if len(g.GuestIPs) != 2 || g.GuestIPs[0] != "192.168.64.2" {
		t.Fatalf("guest IPs = %v", g.GuestIPs)
	}
	if len(g.Listeners) != 3 {
		t.Fatalf("listeners = %v", g.Listeners)
	}
	if !g.Secret.Present || g.Secret.Mode != "600" || g.Secret.Owner != "root:root" || g.Secret.Size != 65 {
		t.Fatalf("secret = %+v", g.Secret)
	}
}

// An unknown key is a missing check, not a crash: a newer script against an
// older parse must still produce everything it does recognise.
func TestParseGuestProbeIgnoresUnknownKeys(t *testing.T) {
	g := ParseGuestProbe("kernel=6.8.0\nfuture-key=yes\nbtf=yes\n")
	if g.Kernel != "6.8.0" || !g.BTF {
		t.Fatalf("parse = %+v", g)
	}
}

// The `ss` block is fenced, so a key=value line inside it is not a key and a
// listener outside it is not a listener.
func TestParseGuestProbeSSFencing(t *testing.T) {
	g := ParseGuestProbe("LISTEN 0 1 0.0.0.0:4777 0.0.0.0:*\nss-begin\nkernel=nonsense\nss-end\nkernel=6.8.0\n")
	if len(g.Listeners) != 0 {
		t.Fatalf("listeners outside the fence: %v", g.Listeners)
	}
	if g.Kernel != "6.8.0" {
		t.Fatalf("kernel = %q", g.Kernel)
	}
}

// --- target selection (mirrors `up`'s step 1) ------------------------------

func TestSelectTarget(t *testing.T) {
	insts := []vmprovider.Instance{
		vz("lima", "drawbridge", true),
		vz("colima", "colima", false),
		qemu("lima", "old"),
	}

	t.Run("implicit picks the single running vz", func(t *testing.T) {
		got, skip, err := selectTarget("", insts)
		if err != nil || skip != "" {
			t.Fatalf("skip=%q err=%v", skip, err)
		}
		if got.Ref.Provider != "lima" || got.Ref.Instance != "drawbridge" {
			t.Fatalf("ref = %+v", got.Ref)
		}
	})

	t.Run("ambiguity skips with pass -vm", func(t *testing.T) {
		two := append([]vmprovider.Instance{}, insts...)
		two = append(two, vz("colima", "work", true))
		_, skip, err := selectTarget("", two)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(skip, "pass -vm") {
			t.Fatalf("skip = %q", skip)
		}
	})

	t.Run("nothing running", func(t *testing.T) {
		_, skip, err := selectTarget("", []vmprovider.Instance{vz("lima", "drawbridge", false)})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(skip, "no running vz VM") {
			t.Fatalf("skip = %q", skip)
		}
	})

	t.Run("explicit provider:name", func(t *testing.T) {
		got, skip, err := selectTarget("lima:drawbridge", insts)
		if err != nil || skip != "" {
			t.Fatalf("skip=%q err=%v", skip, err)
		}
		if got.Ref.Spec != "lima:drawbridge" {
			t.Fatalf("spec = %q", got.Ref.Spec)
		}
	})

	t.Run("explicit but stopped", func(t *testing.T) {
		_, skip, err := selectTarget("colima:default", insts)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(skip, "not running") {
			t.Fatalf("skip = %q", skip)
		}
	})

	t.Run("explicit but qemu", func(t *testing.T) {
		_, skip, err := selectTarget("lima:old", insts)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(skip, "no host-reachable guest IP") {
			t.Fatalf("skip = %q", skip)
		}
	})

	t.Run("explicit and absent is the gather error", func(t *testing.T) {
		_, _, err := selectTarget("lima:nope", insts)
		if err == nil {
			t.Fatal("a -vm that names nothing must be reportable as a gather failure")
		}
	})

	t.Run("a malformed -vm never reaches a probe", func(t *testing.T) {
		if _, _, err := selectTarget("lima:has space", insts); err == nil {
			t.Fatal("a malformed -vm was accepted")
		}
	})
}

// `colima:default` and `colima:colima` are the same VM — the canonical-ref
// rule, checked where doctor selects a target.
func TestSelectTargetColimaSpellings(t *testing.T) {
	insts := []vmprovider.Instance{vz("colima", "colima", true)}
	for _, spec := range []string{"colima:default", "colima:colima"} {
		got, skip, err := selectTarget(spec, insts)
		if err != nil || skip != "" {
			t.Fatalf("%s: skip=%q err=%v", spec, skip, err)
		}
		if got.Ref.Instance != "colima" {
			t.Fatalf("%s → instance %q", spec, got.Ref.Instance)
		}
	}
}

// The euid-0 selection cannot consult an instance list (limactl refuses
// root), so it mirrors the root daemon: -vm or the daemon's default, and the
// lease db does the rest. The skip string scopes the guest-shell checks only
// — resolution and the root probe run against the ref, which is the whole
// point of `sudo drawbridge doctor`.
func TestRootTarget(t *testing.T) {
	t.Run("default is the daemon's default VM", func(t *testing.T) {
		got, skip := rootTarget("")
		if got.Ref.Provider != "lima" || got.Ref.Instance != "drawbridge" {
			t.Fatalf("ref = %s:%s, want lima:drawbridge", got.Ref.Provider, got.Ref.Instance)
		}
		if !strings.Contains(skip, "root half of the discriminator") {
			t.Fatalf("skip does not say what the root run is for: %q", skip)
		}
		if !strings.Contains(skip, "-vm overrides") {
			t.Fatalf("skip does not say how to point at another VM: %q", skip)
		}
	})
	t.Run("explicit -vm wins", func(t *testing.T) {
		got, _ := rootTarget("colima:colima")
		if got.Ref.Provider != "colima" || got.Ref.Instance != "colima" {
			t.Fatalf("ref = %s:%s, want colima:colima", got.Ref.Provider, got.Ref.Instance)
		}
		if got.Ref.LeaseName != "colima" {
			t.Fatalf("lease name = %q, want the bare colima name", got.Ref.LeaseName)
		}
	})
}

// --- the vzNAT candidate ---------------------------------------------------

func TestVZNATCandidate(t *testing.T) {
	subnet := netip.MustParsePrefix("192.168.64.0/24")

	// Lima's usernet subnet is outbound-only and must never be the candidate.
	got := vznatCandidate([]string{"192.168.5.15", "192.168.64.2"}, limaaddr.Resolution{}, subnet)
	if got != "192.168.64.2" {
		t.Fatalf("candidate = %q", got)
	}

	// No guest answer: fall back to the resolver, but only when it took a
	// direct path — a forwarder endpoint is 127.0.0.1 and proves nothing.
	got = vznatCandidate(nil, limaaddr.Resolution{Endpoint: "tcp://192.168.64.7:4777", Source: limaaddr.SourceVZNATLeases}, subnet)
	if got != "192.168.64.7" {
		t.Fatalf("lease candidate = %q", got)
	}
	got = vznatCandidate(nil, limaaddr.Resolution{Endpoint: "tcp://127.0.0.1:4777", Source: limaaddr.SourceSSHForwarder}, subnet)
	if got != "" {
		t.Fatalf("forwarder endpoint became a candidate: %q", got)
	}
}

// --- the Mac half of the auth state comparison -----------------------------

func macSecretEnv(t *testing.T) (vmprovider.Ref, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	ref, err := vmprovider.ParseRef("lima:drawbridge")
	if err != nil {
		t.Fatal(err)
	}
	p, err := transportauth.PathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	return ref, p
}

func writeSecret(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestMacSecretState(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		_, path := macSecretEnv(t)
		s := macSecretState(path)
		if s.Present || s.Malformed {
			t.Fatalf("state = %+v", s)
		}
	})

	t.Run("healthy", func(t *testing.T) {
		_, path := macSecretEnv(t)
		sec, err := transportauth.Generate()
		if err != nil {
			t.Fatal(err)
		}
		writeSecret(t, path, sec.Format(), 0o600)
		s := macSecretState(path)
		if !s.Present || s.Malformed || s.Mode != "600" {
			t.Fatalf("state = %+v", s)
		}
		if s.Digest != sha256Of(sec.Format()) {
			t.Fatalf("digest = %q", s.Digest)
		}
	})

	// The digest is taken over the canonical rendering, so a Mac file whose
	// whitespace differs still compares equal to a correctly-written guest
	// file — the same normalisation `up`'s convergence step uses.
	t.Run("whitespace does not change the digest", func(t *testing.T) {
		_, path := macSecretEnv(t)
		sec, err := transportauth.Generate()
		if err != nil {
			t.Fatal(err)
		}
		writeSecret(t, path, strings.TrimSpace(sec.Format()), 0o600)
		if got := macSecretState(path).Digest; got != sha256Of(sec.Format()) {
			t.Fatalf("digest = %q, want the canonical one", got)
		}
	})

	t.Run("wrong mode", func(t *testing.T) {
		_, path := macSecretEnv(t)
		sec, err := transportauth.Generate()
		if err != nil {
			t.Fatal(err)
		}
		writeSecret(t, path, sec.Format(), 0o644)
		if got := macSecretState(path).Mode; got != "644" {
			t.Fatalf("mode = %q", got)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		_, path := macSecretEnv(t)
		writeSecret(t, path, "garbage\n", 0o600)
		s := macSecretState(path)
		if !s.Present || !s.Malformed || s.Digest != "" {
			t.Fatalf("state = %+v", s)
		}
	})
}

// authInput wires the guest stat into the format check: the bytes stay in the
// guest, so the size is the only format evidence available from the Mac.
func TestAuthInputGuestSizeIsTheFormatCheck(t *testing.T) {
	ref, _ := macSecretEnv(t)
	g := ParseGuestProbe(guestOutputFixture)
	in := authInput(target{Ref: ref}, "", g, nil, "vznat-direct")
	if in.Guest.Malformed {
		t.Fatalf("a 65-byte guest secret read as malformed: %+v", in.Guest)
	}

	g.Secret.Size = 40
	in = authInput(target{Ref: ref}, "", g, nil, "vznat-direct")
	if !in.Guest.Malformed || !strings.Contains(in.Guest.Why, "want 65") {
		t.Fatalf("guest = %+v", in.Guest)
	}
}

// A refused `sudo -n` in the guest is named, not guessed around.
func TestAuthInputGuestDigestRefused(t *testing.T) {
	ref, _ := macSecretEnv(t)
	g := ParseGuestProbe(strings.Replace(guestOutputFixture,
		"secret-digest=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "secret-digest=", 1))
	in := authInput(target{Ref: ref}, "", g, nil, "vznat-direct")
	if !strings.Contains(in.Guest.Why, "sudo -n") {
		t.Fatalf("why = %q", in.Guest.Why)
	}
}

// The VM is not running: the guest side is skipped, and the Mac side is
// still read.
func TestAuthInputGuestSkipped(t *testing.T) {
	ref, path := macSecretEnv(t)
	sec, err := transportauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	writeSecret(t, path, sec.Format(), 0o600)
	in := authInput(target{Ref: ref}, "colima:colima is not running", GuestProbe{}, nil, "")
	if in.GuestSkip == "" {
		t.Fatal("the guest side was not skipped")
	}
	if !in.Mac.Present {
		t.Fatal("the Mac side was not read")
	}
}

// A stopped-but-named VM keeps its Ref, so the Mac half of the auth
// comparison is still derivable and still reported.
func TestSelectTargetKeepsRefWhenSkipping(t *testing.T) {
	insts := []vmprovider.Instance{vz("colima", "colima", false)}
	got, skip, err := selectTarget("colima:default", insts)
	if err != nil || skip == "" {
		t.Fatalf("skip=%q err=%v", skip, err)
	}
	if got.Ref.Instance != "colima" {
		t.Fatalf("ref lost on skip: %+v", got.Ref)
	}
}

// With no VM selected at all, the Mac-side path is not derived from an empty
// ref — the auth block skips instead.
func TestAuthInputNoVMSelected(t *testing.T) {
	macSecretEnv(t)
	in := authInput(target{}, "several VMs are running — pass -vm", GuestProbe{}, nil, "")
	if in.MacSkip == "" {
		t.Fatal("MacSkip not set for an unselected VM")
	}
	if in.Mac.Path != "" {
		t.Fatalf("a path was derived from an empty ref: %q", in.Mac.Path)
	}
}

// --- the introspection enrichment tier -------------------------------------

func rootSnap(mutate func(*introspect.State)) *introspect.Snapshot {
	st := introspect.State{
		Schema: introspect.Schema, Version: "v0.1.0", PID: 4242, EUID: 0,
		VM:         introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
		Resolution: introspect.Resolution{Endpoint: "tcp://192.168.64.5:4777", Source: limaaddr.SourceVZNATDirect},
		Mirror:     introspect.Mirror{SessionUp: true},
	}
	if mutate != nil {
		mutate(&st)
	}
	return &introspect.Snapshot{Path: introspect.RootSocketPath, State: st, Usable: true}
}

// Tier 2 is the root daemon's passive vantage: root euid, vznat-direct, a
// live session. Anything less stays "unknown", which is the branch that
// prints the tier-1 instruction rather than concluding anything.
func TestTier2Evidence(t *testing.T) {
	ok := tier2Evidence(rootSnap(nil))
	if ok.Kind != "tier2" || ok.Probe != ProbeOK {
		t.Fatalf("healthy root daemon = %+v, want tier2/ok", ok)
	}
	if !strings.Contains(ok.Note, introspect.RootSocketPath) || !strings.Contains(ok.Note, "vznat-direct") {
		t.Fatalf("note does not name the vantage: %q", ok.Note)
	}

	// A real root daemon always reports vznat-leases — the lease db is its
	// only legal candidate source — and that is the same direct path
	// (pinned live 2026-08-01: the installed daemon's snapshot).
	leases := tier2Evidence(rootSnap(func(s *introspect.State) { s.Resolution.Source = limaaddr.SourceVZNATLeases }))
	if leases.Kind != "tier2" || leases.Probe != ProbeOK {
		t.Fatalf("root daemon on vznat-leases = %+v, want tier2/ok", leases)
	}

	// A daemon on the fallback path proves nothing about the direct one, and
	// a dead session proves nothing at all. Neither is a "tier2 fail": the
	// daemon re-resolves on its own cadence, so a stale failure read as a
	// verdict would misdiagnose.
	for name, snap := range map[string]*introspect.Snapshot{
		"fallback source": rootSnap(func(s *introspect.State) { s.Resolution.Source = limaaddr.SourceSSHForwarder }),
		"dead sessions":   rootSnap(func(s *introspect.State) { s.Mirror.SessionUp = false }),
		"user daemon":     rootSnap(func(s *introspect.State) { s.EUID = 501 }),
		"absent":          nil,
	} {
		if got := tier2Evidence(snap); got.Kind != "unknown" {
			t.Errorf("%s: kind = %q, want unknown", name, got.Kind)
		}
	}
	// A payload this build cannot read carries no evidence either.
	skewed := &introspect.Snapshot{Path: introspect.RootSocketPath, State: introspect.State{Schema: 2, Version: "v9"}}
	if got := tier2Evidence(skewed); got.Kind != "unknown" {
		t.Errorf("schema-skewed snapshot produced %q evidence", got.Kind)
	}
}

// A daemon attached to a different VM says nothing about this one, so it is
// never matched — the payload names its own VM precisely so this is a match
// and not a guess.
func TestMatchSnapshot(t *testing.T) {
	ref, err := vmprovider.ParseRef("colima:colima")
	if err != nil {
		t.Fatal(err)
	}
	other := rootSnap(func(s *introspect.State) {
		s.VM = introspect.VM{Ref: "lima:dev", Provider: "lima", Instance: "dev"}
	})
	if got := matchSnapshot([]*introspect.Snapshot{other}, ref); got != nil {
		t.Fatalf("matched a snapshot for %s against %s", got.State.VM.Ref, ref.Spec)
	}
	mine := rootSnap(nil)
	if got := matchSnapshot([]*introspect.Snapshot{other, mine}, ref); got != mine {
		t.Fatalf("matched %+v, want the colima:colima snapshot", got)
	}
	if got := matchSnapshot([]*introspect.Snapshot{mine}, vmprovider.Ref{}); got != nil {
		t.Fatal("matched a snapshot with no target VM selected")
	}
}

func TestEntriesInState(t *testing.T) {
	snap := rootSnap(func(s *introspect.State) {
		s.Mirror.Entries = []introspect.MirrorEntry{
			{Proto: "tcp", Port: 8080, State: introspect.EntryBound},
			{Proto: "tcp", Port: 22, State: introspect.EntrySkipped},
			{Proto: "tcp", Port: 5000, State: introspect.EntryBindFailed},
		}
	})
	if got := entriesInState(snap, introspect.EntryBindFailed); len(got) != 1 || got[0].Port != 5000 {
		t.Fatalf("bind-failed = %+v", got)
	}
	if got := entriesInState(nil, introspect.EntrySkipped); got != nil {
		t.Fatalf("absent snapshot yielded %+v", got)
	}
}
