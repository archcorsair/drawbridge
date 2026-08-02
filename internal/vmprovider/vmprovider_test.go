package vmprovider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ParseRef is the grammar drawbridged's -vm and the install plist both read,
// so it has to be exact in three directions at once: what a bare name means
// (today's Lima instance, unchanged — every installed plist depends on it),
// which Lima instance a colima profile is, and which DHCP record name the
// resolver will match.
func TestParseRef(t *testing.T) {
	for _, tc := range []struct {
		in         string
		provider   string
		instance   string
		leaseName  string
		colimaHome bool
	}{
		{"drawbridge", ProviderLima, "drawbridge", "lima-drawbridge", false},
		{"default", ProviderLima, "default", "lima-default", false},
		{"lima:myvm", ProviderLima, "myvm", "lima-myvm", false},
		{"lima:drawbridge", ProviderLima, "drawbridge", "lima-drawbridge", false},

		// The colima profile→instance mapping, in both spellings a user can
		// have in front of them.
		// colima's guest hostname is the instance name, so its lease record
		// carries no `lima-` prefix (see LeaseName).
		{"colima:default", ProviderColima, "colima", "colima", true},
		{"colima:colima", ProviderColima, "colima", "colima", true},
		{"colima:work", ProviderColima, "colima-work", "colima-work", true},
		{"colima:colima-work", ProviderColima, "colima-work", "colima-work", true},

		{"  drawbridge  ", ProviderLima, "drawbridge", "lima-drawbridge", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			r, err := ParseRef(tc.in)
			if err != nil {
				t.Fatalf("ParseRef(%q) = %v", tc.in, err)
			}
			if r.Provider != tc.provider || r.Instance != tc.instance || r.LeaseName != tc.leaseName {
				t.Fatalf("ParseRef(%q) = %+v; want provider=%s instance=%s lease=%s",
					tc.in, r, tc.provider, tc.instance, tc.leaseName)
			}
			if tc.colimaHome {
				// The exact directory is discovered (ColimaHome), so assert
				// the shape rather than a path this machine happens to have.
				if r.LimaHome == "" || filepath.Base(r.LimaHome) != limaSubdir {
					t.Fatalf("ParseRef(%q).LimaHome = %q, want colima's LIMA_HOME", tc.in, r.LimaHome)
				}
			} else if r.LimaHome != "" {
				t.Fatalf("ParseRef(%q).LimaHome = %q, want the ambient environment", tc.in, r.LimaHome)
			}
			// Spec round-trips verbatim: it is what `drawbridge install`
			// renders back into root's argv, so anything but the given text
			// would install a daemon the user did not ask for.
			if want := strings.TrimSpace(tc.in); r.Spec != want {
				t.Fatalf("ParseRef(%q).Spec = %q, want %q", tc.in, r.Spec, want)
			}
		})
	}
}

// The value reaches root's ProgramArguments through the install plist, so
// the parser is an allowlist and rejects rather than escapes.
func TestParseRefRejects(t *testing.T) {
	for _, bad := range []string{
		"",
		"   ",
		"podman:machine", // Phase 7, and until then not a silent lima
		"lima",           // bare "lima" is a Lima instance named lima — see below
		"colima:",        // an empty profile is not the default profile
		":drawbridge",    // empty provider
		"lima:my vm",
		"lima:-rf",
		"colima:../../etc/passwd",
		"vm</string><string>-mirror-ip</string><string>0.0.0.0",
		"lima:vm\n<key>Program</key>",
		"lima:a:b",
		strings.Repeat("a", 65),
		"lima:" + strings.Repeat("a", 65),
	} {
		t.Run(bad, func(t *testing.T) {
			if bad == "lima" {
				// Documenting the one ambiguity the grammar has: without a
				// colon this is a name, not a provider. That is deliberate —
				// bare names are the historical spelling and must not change
				// meaning — so it must parse, as an instance called "lima".
				r, err := ParseRef(bad)
				if err != nil || r.Instance != "lima" || r.LeaseName != "lima-lima" {
					t.Fatalf("ParseRef(%q) = %+v, %v; want the Lima instance named lima", bad, r, err)
				}
				return
			}
			if r, err := ParseRef(bad); err == nil {
				t.Fatalf("ParseRef(%q) = %+v, want an error", bad, r)
			}
		})
	}
}

func TestColimaInstance(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "colima"},
		{"default", "colima"},
		{"colima", "colima"},
		{"work", "colima-work"},
		{"colima-work", "colima-work"},
		{"colima-default", "colima-default"}, // a real profile literally named "colima-default"
	} {
		if got := ColimaInstance(tc.in); got != tc.want {
			t.Fatalf("ColimaInstance(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The lease name is a match key, never evidence — but it still has to be the
// right key, or a colima install resolves nothing at all.
//
// It is the guest's *hostname*, and the two providers set it differently:
// Lima defaults to `lima-<instance>`, colima's cloud-init sets it to the
// instance name. Confirmed against a live pair on 0.10.3/2.2.0 —
// /var/db/dhcpd_leases held `name=lima-drawbridge` and `name=colima`.
func TestLeaseName(t *testing.T) {
	for _, tc := range []struct{ provider, in, want string }{
		{ProviderLima, "drawbridge", "lima-drawbridge"},
		{ProviderLima, "default", "lima-default"},
		{ProviderColima, "colima", "colima"},
		{ProviderColima, "colima-work", "colima-work"},
	} {
		if got := LeaseName(tc.provider, tc.in); got != tc.want {
			t.Fatalf("LeaseName(%q, %q) = %q, want %q", tc.provider, tc.in, got, tc.want)
		}
	}
}

// The namespaces must not cross. A *Lima* instance literally named `colima`
// claims `lima-colima`; a colima default profile claims `colima`. Collapsing
// the two would let either one answer for the other — and since both would be
// vz guests on the same vmnet answering :4777 with the same protocol, the
// probe could not tell them apart.
func TestLeaseNameNamespacesDoNotCross(t *testing.T) {
	limaColima := mustRef(t, "lima:colima")
	colimaDefault := mustRef(t, "colima:default")
	if limaColima.LeaseName != "lima-colima" {
		t.Fatalf("lima:colima lease = %q, want lima-colima", limaColima.LeaseName)
	}
	if colimaDefault.LeaseName != "colima" {
		t.Fatalf("colima:default lease = %q, want colima", colimaDefault.LeaseName)
	}
	if limaColima.LeaseName == colimaDefault.LeaseName {
		t.Fatal("a Lima instance named colima and colima's default profile resolve to one lease record")
	}
	// Same instance name, so everything else about them *does* coincide —
	// which is exactly why the lease name has to carry the distinction.
	if limaColima.Instance != colimaDefault.Instance {
		t.Fatalf("instances differ (%q vs %q); the test no longer covers the collision it was written for",
			limaColima.Instance, colimaDefault.Instance)
	}
}

// ColimaHome must not inherit $LIMA_HOME: colima sets that variable itself
// when it drives limactl, and honouring a user's value would point the
// colima driver at the user's own Lima instances.
func TestColimaHomeIgnoresLimaHomeEnv(t *testing.T) {
	t.Setenv("LIMA_HOME", "/tmp/somewhere-else")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("COLIMA_HOME", "")
	if got := ColimaHome(); strings.HasPrefix(got, "/tmp/somewhere-else") {
		t.Fatalf("ColimaHome() = %q, want colima's own home", got)
	}
	if got := LimaHome(); got != "/tmp/somewhere-else" {
		t.Fatalf("LimaHome() = %q, want the $LIMA_HOME override", got)
	}
}

// Colima's state directory moved (v0.9: ~/.colima → $XDG_CONFIG_HOME/colima),
// so this is discovery, not a constant — and getting it wrong is silent: the
// driver finds no instances and resolution quietly degrades to the lease db,
// which is the failure the LIMA_HOME parameter exists to prevent.
//
// The precedence asserted here is colima 0.10's own. Its binary carries
// "found ~/.colima, ignoring $XDG_CONFIG_HOME...", so when both layouts are
// on disk the legacy one wins — an upgraded install must keep working.
func TestColimaHomeDiscovery(t *testing.T) {
	mk := func(t *testing.T, parts ...string) string {
		t.Helper()
		p := filepath.Join(parts...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}

	for _, tc := range []struct {
		name string
		// build lays out a fake $HOME (and anything outside it) and returns
		// the directory ColimaHome must pick.
		build func(t *testing.T, home, outside string) string
		// env applied after build, so a case can point COLIMA_HOME at
		// something build created.
		colimaHomeEnv func(outside string) string
		xdgEnv        func(outside string) string
	}{
		{
			name: "current layout: XDG default",
			build: func(t *testing.T, home, _ string) string {
				return mk(t, home, ".config", "colima", limaSubdir)
			},
		},
		{
			name: "legacy layout still works",
			build: func(t *testing.T, home, _ string) string {
				return mk(t, home, ".colima", limaSubdir)
			},
		},
		{
			name: "both present: legacy wins, as colima itself does",
			build: func(t *testing.T, home, _ string) string {
				mk(t, home, ".config", "colima", limaSubdir)
				return mk(t, home, ".colima", limaSubdir)
			},
		},
		{
			name: "explicit $XDG_CONFIG_HOME is honoured",
			build: func(t *testing.T, _, outside string) string {
				return mk(t, outside, "xdg", "colima", limaSubdir)
			},
			xdgEnv: func(outside string) string { return filepath.Join(outside, "xdg") },
		},
		{
			name: "$COLIMA_HOME outranks both when it really exists",
			build: func(t *testing.T, home, outside string) string {
				mk(t, home, ".colima", limaSubdir)
				mk(t, home, ".config", "colima", limaSubdir)
				return mk(t, outside, "explicit", limaSubdir)
			},
			colimaHomeEnv: func(outside string) string { return filepath.Join(outside, "explicit") },
		},
		{
			name: "a $COLIMA_HOME that holds nothing falls through rather than winning",
			build: func(t *testing.T, home, _ string) string {
				return mk(t, home, ".colima", limaSubdir)
			},
			colimaHomeEnv: func(outside string) string { return filepath.Join(outside, "empty") },
		},
		{
			name: "nothing on disk: the XDG default, which is what colima will create",
			build: func(t *testing.T, home, _ string) string {
				return filepath.Join(home, ".config", "colima", limaSubdir)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := mk(t, root, "home")
			outside := mk(t, root, "outside")
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("COLIMA_HOME", "")
			want := tc.build(t, home, outside)
			if tc.xdgEnv != nil {
				t.Setenv("XDG_CONFIG_HOME", tc.xdgEnv(outside))
			}
			if tc.colimaHomeEnv != nil {
				t.Setenv("COLIMA_HOME", tc.colimaHomeEnv(outside))
			}
			if got := colimaHome(home); got != want {
				t.Fatalf("colimaHome() = %q, want %q", got, want)
			}
		})
	}
}

// No home and no $XDG_CONFIG_HOME must stay empty rather than fatal. Empty is
// a meaningful answer — "use the ambient environment" — and this is the shape
// a root daemon can reach, where limactl is never run anyway.
func TestColimaHomeWithoutAHomeIsEmptyNotFatal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("COLIMA_HOME", "")
	if got := colimaHome(""); got != "" {
		t.Fatalf("colimaHome(\"\") = %q, want empty", got)
	}
	// With $XDG_CONFIG_HOME set there is still an answer without a home.
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	if got, want := colimaHome(""), filepath.Join("/tmp/xdg", "colima", limaSubdir); got != want {
		t.Fatalf("colimaHome(\"\") = %q, want %q", got, want)
	}
}

func TestForRef(t *testing.T) {
	r, err := ParseRef("colima:default")
	if err != nil {
		t.Fatal(err)
	}
	p := ForRef(r)
	if p.Provider() != ProviderColima || p.Home() != r.LimaHome {
		t.Fatalf("ForRef = provider %q home %q, want %q %q", p.Provider(), p.Home(), ProviderColima, r.LimaHome)
	}
	// The Lima driver deliberately keeps the ambient LIMA_HOME rather than
	// resolving it: a user who sets the variable per shell must keep working.
	if p := ForRef(mustRef(t, "drawbridge")); p.Home() != "" {
		t.Fatalf("ForRef(lima).Home() = %q, want ambient", p.Home())
	}
}

func mustRef(t *testing.T, s string) Ref {
	t.Helper()
	r, err := ParseRef(s)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", s, err)
	}
	return r
}
