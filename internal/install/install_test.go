package install

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden plist files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// The plist is executed as root at every boot, so its exact bytes are the
// contract — a golden test, not a "contains" test. A silent change to
// KeepAlive, ProcessType, or the log paths is the kind of thing that only
// shows up as "the daemon didn't come back after a reboot".
func TestRenderPlistGolden(t *testing.T) {
	p, err := RenderPlist(Config{VM: DefaultVM})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-default.golden", p)

	p, err = RenderPlist(Config{VM: "othervm", UDP: []uint16{5353, 51820}})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-udp.golden", p)

	p, err = RenderPlist(Config{VM: DefaultVM, MAC: "52:55:55:a5:de:d2", Subnet: "192.168.64.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-pinned.golden", p)

	// The provider passthrough: `drawbridge install -vm colima:default`
	// installs a daemon whose -vm says exactly that. Rendering the resolved
	// instance name instead would be a plist that does not read back as what
	// was installed — and, since the daemon re-does the mapping at boot, it
	// would also pin a translation the CLI happened to make on install day.
	p, err = RenderPlist(Config{VM: "colima:default", MAC: "52:55:55:0a:de:02"})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-colima.golden", p)

	// The skip-list, overridden and disabled. The disabled form renders an
	// empty <string> — launchd hands the daemon an empty -skip value, which
	// is the documented "skip nothing" spelling — so its bytes are pinned
	// too, not left to a reader's assumption.
	over := Config{VM: DefaultVM}
	if err := over.SetSkip("22,5353"); err != nil {
		t.Fatal(err)
	}
	if p, err = RenderPlist(over); err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-skip.golden", p)

	off := Config{VM: DefaultVM}
	if err := off.SetSkip(""); err != nil {
		t.Fatal(err)
	}
	if p, err = RenderPlist(off); err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-skip-off.golden", p)
}

// -agent auto is load-bearing: pinning an endpoint at install time disables
// drawbridged's re-resolve hook, so a recreated VM (new MAC → new vzNAT IP)
// would leave the daemon dialing a dead address forever. And -mirror-ip must
// never appear: the installed daemon has no way to express a non-loopback
// mirror bind, which is the root-side half of the "mirrors bind 127.0.0.1
// only" invariant.
func TestArgs(t *testing.T) {
	args := Config{VM: "drawbridge"}.Args()
	want := []string{BinaryPath, "-agent", "auto", "-vm", "drawbridge"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("Args() = %v, want %v", args, want)
	}
	joined := strings.Join(Config{VM: "drawbridge", UDP: []uint16{53, 5353}}.Args(), " ")
	if !strings.Contains(joined, "-udp 53,5353") {
		t.Fatalf("Args() = %q, want a -udp 53,5353", joined)
	}
	for _, bad := range []string{"-mirror-ip", "0.0.0.0", "tcp://"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("Args() = %q, must not contain %q", joined, bad)
		}
	}

	// -vm-mac and -vm-subnet appear only when set. A placeholder would make
	// an unpinned install read as pinned in `drawbridge status` and in the
	// plist — the daemon's own default is "no pin, and say so".
	if strings.Contains(joined, "-vm-mac") || strings.Contains(joined, "-vm-subnet") {
		t.Fatalf("Args() = %q, must not mention the pins when unset", joined)
	}
	pinned := strings.Join(Config{VM: "drawbridge", MAC: "52:55:55:a5:de:d2", Subnet: "192.168.64.0/24"}.Args(), " ")
	for _, want := range []string{"-vm-mac 52:55:55:a5:de:d2", "-vm-subnet 192.168.64.0/24"} {
		if !strings.Contains(pinned, want) {
			t.Fatalf("Args() = %q, want %q", pinned, want)
		}
	}
}

// Config fields become literal text inside an XML document that launchd
// runs as root. Reject rather than escape — an argument that needs escaping
// is not a VM name.
func TestValidateRejectsInjection(t *testing.T) {
	for _, vm := range []string{
		"",
		"-rf",
		"vm name",
		"vm</string><string>-mirror-ip</string><string>0.0.0.0",
		"vm&amp;",
		"../../etc/passwd",
		"vm\n<key>Program</key>",
		strings.Repeat("a", 65),
	} {
		t.Run(vm, func(t *testing.T) {
			if err := (Config{VM: vm}).Validate(); err == nil {
				t.Fatalf("Validate() accepted %q", vm)
			}
			if _, err := RenderPlist(Config{VM: vm}); err == nil {
				t.Fatalf("RenderPlist() accepted %q", vm)
			}
		})
	}
	if err := (Config{VM: "drawbridge", UDP: []uint16{0}}).Validate(); err == nil {
		t.Fatal("Validate() accepted UDP port 0")
	}
	for _, vm := range []string{"drawbridge", "lima-vm_2", "a.b-c_1", "X"} {
		if err := (Config{VM: vm}).Validate(); err != nil {
			t.Fatalf("Validate(%q) = %v, want ok", vm, err)
		}
	}
}

// The provider grammar widened what -vm accepts, and a widened allowlist is
// where an injection gets back in. The accepted set is exactly two tokens
// separated by one colon, each an instance-name allowlist; a colon is not a
// licence to carry anything else.
func TestValidateProviderRefs(t *testing.T) {
	for _, vm := range []string{
		"lima:drawbridge",
		"colima:default",
		"colima:colima",
		"colima:work",
		"colima:colima-work",
	} {
		if err := (Config{VM: vm}).Validate(); err != nil {
			t.Fatalf("Validate(%q) = %v, want ok", vm, err)
		}
		p, err := RenderPlist(Config{VM: vm})
		if err != nil {
			t.Fatalf("RenderPlist(%q) = %v", vm, err)
		}
		// Rendered verbatim — the daemon re-parses it at boot.
		if !strings.Contains(p, "<string>"+vm+"</string>") {
			t.Fatalf("RenderPlist(%q) did not render the -vm value verbatim:\n%s", vm, p)
		}
	}
	for _, vm := range []string{
		"podman:machine", // Phase 7; until then it must not install as a lima
		"docker:desktop",
		"colima:",
		":drawbridge",
		"colima:a:b",
		"colima:my vm",
		"lima:vm</string><string>-mirror-ip</string><string>0.0.0.0",
		"colima:" + strings.Repeat("a", 65),
	} {
		if err := (Config{VM: vm}).Validate(); err == nil {
			t.Fatalf("Validate() accepted %q", vm)
		}
		if _, err := RenderPlist(Config{VM: vm}); err == nil {
			t.Fatalf("RenderPlist() accepted %q", vm)
		}
	}
}

// The pins reach root's ProgramArguments too, so they get the same
// allowlist-not-escaping treatment as the VM name.
func TestValidatePins(t *testing.T) {
	for _, bad := range []string{
		"52:55:55:a5:de",
		"52:55:55:a5:de:d2:99",
		"52-55-55-a5-de-d2",
		"52:55:55:a5:de:zz",
		"52:55:55:a5:de:d2</string><string>-mirror-ip",
		"52:55:55:a5:de:d2 -mirror-ip 0.0.0.0",
		"1,52:55:55:a5:de:d2", // the lease-db spelling is canonicalised before it gets here
	} {
		if err := (Config{VM: DefaultVM, MAC: bad}).Validate(); err == nil {
			t.Fatalf("Validate() accepted MAC %q", bad)
		}
		if _, err := RenderPlist(Config{VM: DefaultVM, MAC: bad}); err == nil {
			t.Fatalf("RenderPlist() accepted MAC %q", bad)
		}
	}
	for _, bad := range []string{
		"192.168.64.0",
		"192.168.64.0/24 -mirror-ip 0.0.0.0",
		"fd00::/8",
		"192.168.64.0/24</string><string>x",
		"not-a-subnet",
	} {
		if err := (Config{VM: DefaultVM, Subnet: bad}).Validate(); err == nil {
			t.Fatalf("Validate() accepted subnet %q", bad)
		}
	}
	for _, ok := range []Config{
		{VM: DefaultVM},
		{VM: DefaultVM, MAC: "52:55:55:a5:de:d2"},
		{VM: DefaultVM, MAC: "52:55:55:0a:de:02", Subnet: "10.211.55.0/24"},
	} {
		if err := ok.Validate(); err != nil {
			t.Fatalf("Validate(%+v) = %v, want ok", ok, err)
		}
	}
}

func TestParseUDPPorts(t *testing.T) {
	got, err := ParseUDPPorts(" 53, 5353 ")
	if err != nil || len(got) != 2 || got[0] != 53 || got[1] != 5353 {
		t.Fatalf("ParseUDPPorts = %v, %v", got, err)
	}
	if got, err := ParseUDPPorts(""); err != nil || got != nil {
		t.Fatalf("ParseUDPPorts(\"\") = %v, %v", got, err)
	}
	for _, bad := range []string{"0", "70000", "abc", "53,"} {
		if _, err := ParseUDPPorts(bad); err == nil {
			t.Fatalf("ParseUDPPorts(%q) accepted", bad)
		}
	}
}

// The rotation entry must never fall back to newsyslog's default signal
// target, which is syslogd — a daemon we have nothing to do with.
func TestNewsyslogConf(t *testing.T) {
	conf := NewsyslogConf()
	var entry string
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "/") {
			entry = l
		}
	}
	if entry == "" {
		t.Fatalf("no entry line in:\n%s", conf)
	}
	f := strings.Fields(entry)
	if len(f) != 7 {
		t.Fatalf("entry %q has %d fields, want 7 (path owner mode count size when flags)", entry, len(f))
	}
	if f[0] != LogPath {
		t.Fatalf("entry path = %q, want %q", f[0], LogPath)
	}
	if f[3] != "5" || f[4] != "1024" {
		t.Fatalf("entry = %q, want count=5 size=1024 (1 MB)", entry)
	}
	if !strings.Contains(f[6], "N") {
		t.Fatalf("entry flags = %q, want the N flag (else newsyslog HUPs syslogd)", f[6])
	}
}

// Identity strings are the uninstall contract: an older CLI looking for a
// renamed label leaves a bootstrapped daemon behind with no way to reach it.
func TestIdentityPaths(t *testing.T) {
	for _, tc := range []struct{ name, got, want string }{
		{"Label", Label, "com.archcorsair.drawbridged"},
		{"ServiceTarget", ServiceTarget, "system/com.archcorsair.drawbridged"},
		{"PlistPath", PlistPath, "/Library/LaunchDaemons/com.archcorsair.drawbridged.plist"},
		{"BinaryPath", BinaryPath, "/usr/local/libexec/drawbridged"},
		{"LogDir", LogDir, "/Library/Logs/drawbridge"},
		{"LogPath", LogPath, "/Library/Logs/drawbridge/drawbridged.log"},
		{"NewsyslogPath", NewsyslogPath, "/etc/newsyslog.d/drawbridge.conf"},
	} {
		if tc.got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	// The binary must live outside any user-writable build tree.
	if strings.HasPrefix(BinaryPath, os.Getenv("HOME")) {
		t.Fatalf("BinaryPath %q is under $HOME", BinaryPath)
	}
}

// Status must be honest about the three independent observations it makes.
// Rendering lives in cmd/drawbridge (render_test.go pins the wording); the
// predicates the exit code hangs off are pinned here.
func TestStatusPredicates(t *testing.T) {
	st := Status{
		PlistInstalled: true, BinaryInstalled: true,
		Loaded: true, State: "running", PID: 4242,
	}
	if !st.Running() || !st.Installed() {
		t.Fatal("Running()/Installed() disagree with the fields")
	}

	// Plist on disk but launchd doesn't know it: someone booted it out by
	// hand. That must not read as "running".
	st = Status{PlistInstalled: true, BinaryInstalled: true}
	if st.Running() {
		t.Fatal("Running() true with launchd unaware of the job")
	}
	if !st.Installed() {
		t.Fatal("Installed() false with both artifacts on disk")
	}
	if (Status{}).Installed() || (Status{}).Running() {
		t.Fatal("the zero Status claims an install")
	}

	// A nil Step must be callable: the library never requires a presenter.
	Step(nil).emit("discarded %d", 1)
}

// The skip-list passthrough. The rules that matter: the default renders
// nothing (so a future change to the default reaches installs that never
// asked for the old value), an override renders, and the disable spelling
// `-skip ""` survives as a rendered empty argument rather than collapsing
// back into the default.
func TestSetSkipAndArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		want string // "" ⇒ no -skip argument at all
	}{
		{"default renders nothing", DefaultSkip, ""},
		{"whitespace default renders nothing", " 22 ", ""},
		{"override", "22,5353", "-skip 22,5353"},
		{"replacing the default entirely", "8022", "-skip 8022"},
		{"disable", "", `-skip `},
		{"whitespace disable", "  ", `-skip `},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{VM: DefaultVM}
			if err := cfg.SetSkip(tc.spec); err != nil {
				t.Fatalf("SetSkip(%q) = %v", tc.spec, err)
			}
			args := cfg.Args()
			idx := -1
			for i, a := range args {
				if a == "-skip" {
					idx = i
				}
			}
			if tc.want == "" {
				if idx >= 0 {
					t.Fatalf("Args() = %v, must not render -skip for %q", args, tc.spec)
				}
				return
			}
			if idx < 0 || idx+1 >= len(args) {
				t.Fatalf("Args() = %v, want %q", args, tc.want)
			}
			if got := args[idx] + " " + args[idx+1]; got != tc.want {
				t.Fatalf("Args() rendered %q, want %q", got, tc.want)
			}
			if _, err := RenderPlist(cfg); err != nil {
				t.Fatalf("RenderPlist: %v", err)
			}
		})
	}

	// Disable is not the same configuration as unset — the whole point of
	// the nil/empty distinction on Config.Skip.
	var unset, disabled Config
	unset.VM, disabled.VM = DefaultVM, DefaultVM
	if err := unset.SetSkip(DefaultSkip); err != nil {
		t.Fatal(err)
	}
	if err := disabled.SetSkip(""); err != nil {
		t.Fatal(err)
	}
	if unset.Skip != nil || disabled.Skip == nil {
		t.Fatalf("unset.Skip = %v, disabled.Skip = %v; want nil and non-nil empty", unset.Skip, disabled.Skip)
	}

	for _, bad := range []string{"0", "22,0", "abc", "70000", "22,"} {
		var c Config
		if err := c.SetSkip(bad); err == nil {
			t.Fatalf("SetSkip(%q) accepted", bad)
		}
	}
	// Nothing unvalidated reaches root's argv: port 0 is the one value the
	// type still permits and the flag does not.
	if err := (Config{VM: DefaultVM, Skip: []uint16{0}}).Validate(); err == nil {
		t.Fatal("Validate accepted skip port 0")
	}
	if ports := DefaultSkipPorts(); len(ports) != 1 || ports[0] != 22 {
		t.Fatalf("DefaultSkipPorts() = %v, want [22]", ports)
	}
}

// --- Phase 4.5: the transport secret path (docs/transport-auth.md §5)

// The path is rendered, the secret never is. The golden pins the bytes
// because this argument is what makes a root daemon authenticate as the user
// who provisioned the guest — and because the space in "Application Support"
// is exactly the character a naive escaping scheme would mangle.
func TestRenderPlistWithSecretFile(t *testing.T) {
	p, err := RenderPlist(Config{
		VM:         DefaultVM,
		SecretFile: "/Users/dev/Library/Application Support/drawbridge/transport-secret-lima-drawbridge",
	})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "plist-secret.golden", p)
}

func TestArgsSecretFile(t *testing.T) {
	// Absent unless set: an unprovisioned install must not claim a file.
	if joined := strings.Join(Config{VM: DefaultVM}.Args(), " "); strings.Contains(joined, "-secret-file") {
		t.Fatalf("Args() = %q, must not mention -secret-file when unset", joined)
	}
	path := "/Users/dev/Library/Application Support/drawbridge/transport-secret-colima-colima"
	args := Config{VM: "colima:default", SecretFile: path}.Args()
	found := false
	for i, a := range args {
		if a == "-secret-file" {
			if i+1 >= len(args) || args[i+1] != path {
				t.Fatalf("Args() = %v, want %q after -secret-file", args, path)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("Args() = %v, want a -secret-file", args)
	}
	// The path is one argv element, spaces and all. launchd hands
	// ProgramArguments to execve as a vector, so a space is data — but only
	// as long as nobody joins them.
	if len(args) != 7 {
		t.Fatalf("Args() = %v, want seven elements (the path is not split)", args)
	}
}

// Validate-never-escape, applied to a path: a space is legal (Application
// Support has one), XML metacharacters and control characters are not, and a
// relative path is refused outright — root would resolve it against a working
// directory nobody chose.
func TestValidateSecretFile(t *testing.T) {
	for _, ok := range []string{
		"",
		"/etc/drawbridge/transport-secret",
		"/Users/dev/Library/Application Support/drawbridge/transport-secret-lima-drawbridge",
	} {
		if err := (Config{VM: DefaultVM, SecretFile: ok}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"relative/path",
		"~/Library/Application Support/drawbridge/x",
		"/tmp/a&b",
		"/tmp/<script>",
		"/tmp/a\"b",
		"/tmp/a'b",
		"/tmp/a\nb",
		"/tmp/a\x00b",
		"/tmp/a\x7fb",
	} {
		if err := (Config{VM: DefaultVM, SecretFile: bad}).Validate(); err == nil {
			t.Errorf("Validate(%q) = nil, want a rejection", bad)
		}
		if _, err := RenderPlist(Config{VM: DefaultVM, SecretFile: bad}); err == nil {
			t.Errorf("RenderPlist(%q) rendered a plist, want a rejection", bad)
		}
	}
}

// InstalledVersion reads what the installed daemon prints. The parse is
// shared, and portable, so the shape is pinned here rather than only on a
// Mac with a daemon on it.
func TestParseVersionOutput(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"drawbridged v0.1.0\n", "v0.1.0", true},
		{"drawbridged dev\n", "dev", true},
		{"v0.1.0\n", "v0.1.0", true},
		{"", "", false},
		{"   \n", "", false},
	}
	for _, tc := range tests {
		got, err := parseVersionOutput(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parseVersionOutput(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if got != tc.want {
			t.Errorf("parseVersionOutput(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
