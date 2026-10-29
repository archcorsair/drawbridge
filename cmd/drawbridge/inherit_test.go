package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/install"
)

// Decision E3 (audit 2026-10-28 H3, M15, M11, I6): `drawbridge install`
// defaults every flag not given from the installed plist, prints what it
// kept, and never carries a per-VM value across a change of VM.
//
// Every test here replaces readInstalledArgs: the machine running the suite
// may have a real daemon installed (this one does), and a test must neither
// read nor depend on it. Every runInstall call goes through -print, which
// writes nothing.

const (
	oldSecret = "/Users/someone/Library/Application Support/drawbridge/transport-secret-colima-colima"
	oldMAC    = "52:55:55:a5:de:d2"
)

// fullPins is an installed daemon carrying every value install renders.
func fullPins(t *testing.T, vm string) (install.Config, string) {
	t.Helper()
	cfg := install.Config{
		VM:         vm,
		UDP:        []uint16{53},
		MAC:        oldMAC,
		Subnet:     "192.168.105.0/24",
		SecretFile: oldSecret,
	}
	if err := cfg.SetSkip("22,8080"); err != nil {
		t.Fatal(err)
	}
	p, err := install.RenderPlist(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, p
}

func notesContain(t *testing.T, h inherited, want string) {
	t.Helper()
	for _, n := range h.notes {
		if strings.Contains(n, want) {
			return
		}
	}
	t.Fatalf("no note mentions %q:\n%s", want, strings.Join(h.notes, "\n"))
}

func TestInheritInstall(t *testing.T) {
	defaults := installFlags{vm: install.DefaultVM, skip: install.DefaultSkip}
	_, plist := fullPins(t, "colima:default")
	prev := install.ArgsFromPlist(plist)

	t.Run("no installed plist: today's behavior", func(t *testing.T) {
		h := inheritInstall(defaults, map[string]bool{}, nil, false)
		if h.flags != defaults || len(h.notes) != 0 || h.installed {
			t.Fatalf("inherited from nothing: %+v", h)
		}
	})

	t.Run("bare install keeps everything", func(t *testing.T) {
		h := inheritInstall(defaults, map[string]bool{}, prev, true)
		want := installFlags{vm: "colima:default", mac: oldMAC, subnet: "192.168.105.0/24", udp: "53", skip: "22,8080", secretFile: oldSecret}
		if h.flags != want {
			t.Fatalf("flags = %+v\nwant    %+v", h.flags, want)
		}
		if !h.sameVM {
			t.Fatal("an inherited -vm is not the same VM")
		}
		for _, n := range []string{"keeping -vm colima:default", "keeping -vm-mac " + oldMAC, "keeping -udp 53",
			"keeping -skip 22,8080", "keeping -vm-subnet 192.168.105.0/24", `keeping -secret-file "` + oldSecret + `"`} {
			notesContain(t, h, n)
		}
	})

	t.Run("a different -vm re-derives the per-VM values", func(t *testing.T) {
		f := defaults
		f.vm = "lima:dev"
		h := inheritInstall(f, map[string]bool{"vm": true}, prev, true)
		if h.sameVM {
			t.Fatal("lima:dev read as the same VM as colima:default")
		}
		if h.flags.mac != "" || h.flags.secretFile != "" {
			t.Fatalf("a per-VM value crossed the VM change: mac=%q secret=%q", h.flags.mac, h.flags.secretFile)
		}
		// Mac-wide values survive.
		if h.flags.udp != "53" || h.flags.skip != "22,8080" || h.flags.subnet != "192.168.105.0/24" {
			t.Fatalf("a Mac-wide value was dropped: %+v", h.flags)
		}
		notesContain(t, h, "not keeping -vm-mac "+oldMAC+": it pins the hardware address of colima:default, not lima:dev")
		notesContain(t, h, "not keeping -secret-file")
		notesContain(t, h, "derived for lima:dev as a fresh install would")
	})

	t.Run("a different spelling of the same VM keeps the per-VM values", func(t *testing.T) {
		f := defaults
		f.vm = "colima:colima"
		h := inheritInstall(f, map[string]bool{"vm": true}, prev, true)
		if !h.sameVM || h.flags.mac != oldMAC || h.flags.secretFile != oldSecret {
			t.Fatalf("colima:colima is colima:default: %+v sameVM=%v", h.flags, h.sameVM)
		}
		if h.flags.vm != "colima:colima" {
			t.Fatalf("the explicit spelling was replaced: %q", h.flags.vm)
		}
	})

	t.Run("an explicit empty value overrides", func(t *testing.T) {
		f := defaults
		f.mac, f.udp, f.subnet, f.skip = "", "", "", ""
		set := map[string]bool{"vm-mac": true, "udp": true, "vm-subnet": true, "skip": true}
		h := inheritInstall(f, set, prev, true)
		if h.flags.mac != "" || h.flags.udp != "" || h.flags.subnet != "" || h.flags.skip != "" {
			t.Fatalf("an explicit \"\" did not clear: %+v", h.flags)
		}
		if h.flags.secretFile != oldSecret || h.flags.vm != "colima:default" {
			t.Fatalf("the flags left out stopped inheriting: %+v", h.flags)
		}
		notesContain(t, h, `dropping -vm-mac `+oldMAC+` from the installed daemon (-vm-mac "" given)`)
		notesContain(t, h, `dropping -udp 53`)
	})

	t.Run("an installed -skip \"\" is kept as skip-nothing", func(t *testing.T) {
		cfg := install.Config{VM: "lima:dev"}
		if err := cfg.SetSkip(""); err != nil {
			t.Fatal(err)
		}
		p, err := install.RenderPlist(cfg)
		if err != nil {
			t.Fatal(err)
		}
		h := inheritInstall(defaults, map[string]bool{}, install.ArgsFromPlist(p), true)
		if h.flags.skip != "" {
			t.Fatalf("skip = %q, want the installed skip-nothing", h.flags.skip)
		}
		notesContain(t, h, `keeping -skip ""`)
	})
}

// The -agent pin is never a flag: re-derived per VM, and a change is said.
func TestInheritAgentNote(t *testing.T) {
	podman := install.ArgsFromPlist(mustPlist(t, install.Config{VM: "podman:spike", Agent: "tcp://127.0.0.1:4778"}))

	same := inheritInstall(installFlags{vm: install.DefaultVM}, map[string]bool{}, podman, true)
	if n := same.agentNote("tcp://127.0.0.1:4778"); n != "" {
		t.Fatalf("an unchanged pin produced a note: %q", n)
	}
	if n := same.agentNote("tcp://127.0.0.1:4779"); !strings.Contains(n, "now says tcp://127.0.0.1:4779") {
		t.Fatalf("a re-recorded endpoint is not said: %q", n)
	}
	moved := inheritInstall(installFlags{vm: "lima:dev"}, map[string]bool{"vm": true}, podman, true)
	if n := moved.agentNote(""); !strings.Contains(n, "not keeping -agent tcp://127.0.0.1:4778: it is the endpoint of podman:spike") {
		t.Fatalf("a dropped pin on a VM change is not said: %q", n)
	}
	auto := inheritInstall(installFlags{vm: "lima:dev"}, map[string]bool{"vm": true}, install.ArgsFromPlist(mustPlist(t, install.Config{VM: "lima:dev"})), true)
	if n := auto.agentNote(""); n != "" {
		t.Fatalf("-agent auto produced a note: %q", n)
	}
}

func mustPlist(t *testing.T, cfg install.Config) string {
	t.Helper()
	p, err := install.RenderPlist(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// I6: the replacing notice compares canonical refs, not spellings.
func TestSameVM(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"colima:default", "colima:colima", true},
		{"drawbridge", "lima:drawbridge", true},
		{"colima", "colima:colima", false}, // a bare name is Lima
		{"podman:spike", "lima:spike", false},
		{"lima:has/slash", "lima:has/slash", false},
	} {
		if got := sameVM(tc.a, tc.b); got != tc.want {
			t.Errorf("sameVM(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// printInstall runs `drawbridge install ARGS` with the installed plist faked
// and both streams captured. It refuses to run without -print: nothing here
// may ever reach install.Install.
func printInstall(t *testing.T, installed string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	hasPrint := false
	for _, a := range args {
		hasPrint = hasPrint || a == "-print"
	}
	if !hasPrint {
		t.Fatal("printInstall without -print would attempt a real install")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_USER", "")
	// $HOME in the fake plist is this run's temp home, so a test can install
	// a secret path that is exactly the per-VM default.
	installed = strings.ReplaceAll(installed, "$HOME", home)
	old := readInstalledArgs
	readInstalledArgs = func() (install.InstalledArgs, bool) {
		if installed == "" {
			return nil, false
		}
		return install.ArgsFromPlist(installed), true
	}
	t.Cleanup(func() { readInstalledArgs = old })

	oldOut, oldErr := os.Stdout, os.Stderr
	ro, wo, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	re, we, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wo, we
	outC, errC := make(chan string), make(chan string)
	go func() { b, _ := io.ReadAll(ro); outC <- string(b) }()
	go func() { b, _ := io.ReadAll(re); errC <- string(b) }()
	code = runInstall(args)
	_ = wo.Close()
	_ = we.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return code, <-outC, <-errC
}

// renderedPlist is the plist half of -print's stdout.
func renderedPlist(t *testing.T, stdout string) string {
	t.Helper()
	head := "# " + install.PlistPath + "\n"
	if !strings.HasPrefix(stdout, head) {
		t.Fatalf("-print stdout does not start with the plist:\n%s", stdout)
	}
	body := strings.TrimPrefix(stdout, head)
	i := strings.Index(body, "\n# "+install.NewsyslogPath)
	if i < 0 {
		t.Fatalf("-print stdout has no newsyslog section:\n%s", stdout)
	}
	return body[:i]
}

// The upgrade path itself: a bare install on a fully pinned daemon renders
// the identical plist, for a Lima and a colima install alike.
func TestBareInstallReproducesTheInstalledPlist(t *testing.T) {
	for _, vm := range []string{"colima:default", "lima:dev"} {
		t.Run(vm, func(t *testing.T) {
			_, want := fullPins(t, vm)
			code, out, errOut := printInstall(t, want, "-print")
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, errOut)
			}
			if got := renderedPlist(t, out); got != want {
				t.Fatalf("bare install changed the plist:\n--- installed ---\n%s\n--- rendered ---\n%s", want, got)
			}
			if !strings.Contains(errOut, "keeping -vm "+vm+" from the installed daemon") {
				t.Fatalf("the kept -vm is not printed:\n%s", errOut)
			}
			if strings.Contains(errOut, "replace") {
				t.Fatalf("a same-VM upgrade talks about replacing:\n%s", errOut)
			}
		})
	}
}

// With nothing installed, a bare install is what it always was.
func TestBareInstallWithNothingInstalled(t *testing.T) {
	code, out, errOut := printInstall(t, "", "-print")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, errOut)
	}
	p := renderedPlist(t, out)
	if !strings.Contains(p, "<string>-vm</string>\n\t\t<string>"+install.DefaultVM+"</string>") {
		t.Fatalf("the default VM changed:\n%s", p)
	}
	if strings.Contains(errOut, "keeping") {
		t.Fatalf("inherited from nothing:\n%s", errOut)
	}
}

// M11: a positional VM is accepted like `up` takes it, flags after it still
// parse, and -print after it is still a preview. A changed VM re-derives the
// secret path for the new VM and drops the old pin (M15's per-VM rule).
func TestInstallPositionalVMPrint(t *testing.T) {
	_, installed := fullPins(t, "colima:default")
	code, out, errOut := printInstall(t, installed, "lima:dev", "-print")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, errOut)
	}
	p := renderedPlist(t, out)
	home := os.Getenv("HOME")
	for _, want := range []string{
		"<string>lima:dev</string>",
		filepath.Join(home, "Library", "Application Support", "drawbridge", "transport-secret-lima-dev"),
		"<string>192.168.105.0/24</string>", // Mac-wide: kept
		"<string>53</string>",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("plist missing %q:\n%s", want, p)
		}
	}
	for _, unwanted := range []string{oldMAC, oldSecret, "colima"} {
		if strings.Contains(p, unwanted) {
			t.Fatalf("plist for lima:dev still carries %q:\n%s", unwanted, p)
		}
	}
	for _, want := range []string{"not keeping -vm-mac", "not keeping -secret-file", "would replace the installed daemon for colima:default with lima:dev"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("stderr missing %q:\n%s", want, errOut)
		}
	}
}

// I6: the same VM in another spelling replaces nothing; a bare name that
// ParseRef reads as Lima does, even though it looks like the colima one.
func TestInstallReplacingNoticeIsCanonical(t *testing.T) {
	_, installed := fullPins(t, "colima:colima")
	_, _, errOut := printInstall(t, installed, "-vm", "colima:default", "-print")
	if strings.Contains(errOut, "replace") {
		t.Fatalf("colima:default replacing colima:colima:\n%s", errOut)
	}
	_, _, errOut = printInstall(t, installed, "-vm", "colima", "-print")
	if !strings.Contains(errOut, "would replace the installed daemon for colima:colima with colima") {
		t.Fatalf("bare colima (lima:colima) is not reported as a replacement:\n%s", errOut)
	}
}

// An inherited secret path that is the per-VM default is still the file `up`
// writes, so the missing-secret warning must say so, not "create this one
// yourself" (P0-1's wording keyed on whether -secret-file was typed, which
// inheritance now answers for the user).
func TestInheritedDefaultSecretKeepsTheUpRemedy(t *testing.T) {
	installed := mustPlist(t, install.Config{
		VM:         "colima:default",
		SecretFile: "/HOMEDIR/Library/Application Support/drawbridge/transport-secret-colima-colima",
	})
	installed = strings.ReplaceAll(installed, "/HOMEDIR", "$HOME")
	code, _, errOut := printInstall(t, installed, "-print")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "keeping -secret-file") {
		t.Fatalf("the secret path was not inherited:\n%s", errOut)
	}
	if !strings.Contains(errOut, "writes that file") || strings.Contains(errOut, "create this one yourself") {
		t.Fatalf("an inherited default path got the custom-path remedy:\n%s", errOut)
	}
}

// M11: leftovers are usage errors (exit 2) before anything runs.
func TestInstallRejectsBadPositionals(t *testing.T) {
	for _, args := range [][]string{
		{"lima:a", "lima:b", "-print"},
		{"lima:a", "-vm", "lima:b", "-print"},
	} {
		if code, _, errOut := printInstall(t, "", args...); code != 2 {
			t.Fatalf("install %v = %d, want 2:\n%s", args, code, errOut)
		}
	}
}

func TestVerbsRejectLeftoverArguments(t *testing.T) {
	if got := runUninstall([]string{"colima"}); got != 2 {
		t.Fatalf("uninstall colima = %d, want 2", got)
	}
	if got := runStatus([]string{"colima", "-v"}); got != 2 {
		t.Fatalf("status colima -v = %d, want 2", got)
	}
	if _, _, err := doctorFlags([]string{"podman:spike", "-json"}); err == nil || !strings.Contains(err.Error(), "-vm NAME") {
		t.Fatalf("doctor podman:spike -json: err = %v, want a usage error naming -vm", err)
	}
	if got := runDoctor([]string{"podman:spike", "-json"}); got != 2 {
		t.Fatalf("runDoctor podman:spike -json = %d, want 2", got)
	}
	if _, err := tuiFlags([]string{"colima:default", "-timeout", "5s"}); err == nil {
		t.Fatal("tui colima:default: no usage error")
	}
	if got := runTUI([]string{"colima:default"}); got != 2 {
		t.Fatalf("runTUI colima:default = %d, want 2", got)
	}
}
