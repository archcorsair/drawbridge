//go:build darwin

package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The escalation boundary in one test: a root-executed binary must never sit
// under a directory a non-root user could swap out. checkSecurePath is what
// refuses the Homebrew-on-Intel /usr/local layout, where /usr/local is owned
// by the admin user — dropping drawbridged there would hand that account
// root at the next boot.
func TestCheckSecurePath(t *testing.T) {
	// The real target dirs on a healthy machine.
	for _, dir := range []string{"/usr/local", "/Library/LaunchDaemons", "/etc"} {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if err := checkSecurePath(dir); err != nil {
			t.Logf("NOTE: %s fails the install security check on this machine: %v", dir, err)
		}
	}
	// A user-owned, user-writable directory must be refused, and the reason
	// must be in the message — this is the one error the user has to act on.
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "libexec")
	if err := os.Mkdir(sub, 0o777); err != nil {
		t.Fatal(err)
	}
	err := checkSecurePath(sub)
	if err == nil {
		t.Fatalf("checkSecurePath(%s) accepted a world-writable user-owned dir", sub)
	}
	if !strings.Contains(err.Error(), "root") && !strings.Contains(err.Error(), "writable") {
		t.Fatalf("refusal %q does not say why", err)
	}
}

// A golden test pins the bytes but says nothing about whether launchd can
// read them. plutil is the same parser launchd uses, so ask it.
func TestRenderedPlistIsValid(t *testing.T) {
	for _, cfg := range []Config{
		{VM: DefaultVM},
		{VM: "other-vm_1", UDP: []uint16{53, 5353, 51820}},
		{VM: DefaultVM, MAC: "52:55:55:a5:de:d2", Subnet: "192.168.64.0/24"},
	} {
		p, err := RenderPlist(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "d.plist")
		if err := os.WriteFile(path, []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("plutil", "-lint", path).CombinedOutput()
		if err != nil {
			t.Fatalf("plutil -lint rejected the rendered plist: %v\n%s\n%s", err, out, p)
		}
	}
}

// Same idea for the rotation entry: newsyslog itself is the parser, and it
// exits non-zero on a config it cannot read (a malformed entry would
// otherwise sit silently in /etc/newsyslog.d until the log filled a disk).
// -n = don't actually trim, -r = don't require root.
func TestNewsyslogConfParses(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "drawbridged.log")
	if err := os.WriteFile(log, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "drawbridge.conf")
	// Same entry, pointed at a file this test may look at.
	if err := os.WriteFile(conf, []byte(strings.ReplaceAll(NewsyslogConf(), LogPath, log)), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("newsyslog", "-n", "-r", "-v", "-f", conf).CombinedOutput()
	if err != nil {
		t.Fatalf("newsyslog rejected the rotation entry: %v\n%s", err, out)
	}
	// -v echoes the thresholds it parsed; 1024 KB is the size we asked for.
	if !strings.Contains(string(out), "[1024]") {
		t.Fatalf("newsyslog did not read the 1 MB threshold:\n%s", out)
	}
}

// launchctl print's shape is the only thing status depends on; pin the parse
// against a realistic sample rather than the live system, which may have no
// job loaded.
func TestParseLaunchctlPrint(t *testing.T) {
	// Shape taken verbatim from launchctl print on macOS 27, including the
	// nested endpoint blocks whose own `state = active` lines must not be
	// mistaken for the job's.
	sample := "system/com.archcorsair.drawbridged = {\n" +
		"\tactive count = 1\n" +
		"\tpath = /Library/LaunchDaemons/com.archcorsair.drawbridged.plist\n" +
		"\tstate = running\n\n" +
		"\tprogram = /usr/local/libexec/drawbridged\n" +
		"\tpid = 4242\n" +
		"\tendpoints = {\n\t\t\"x\" = {\n\t\t\tstate = active\n\t\t\tpid = 9\n\t\t}\n\t}\n}"
	if got := parseState(sample); got != "running" {
		t.Fatalf("parseState = %q, want running", got)
	}
	if got := parsePID(sample); got != 4242 {
		t.Fatalf("parsePID = %d, want 4242 (not a nested endpoint's)", got)
	}
	// launchd's stopped state is two words — a \S+ capture would report
	// "not", which reads as a live state in the status output.
	stopped := "system/x = {\n\tactive count = 0\n\tstate = not running\n}"
	if got, pid := parseState(stopped), parsePID(stopped); got != "not running" || pid != 0 {
		t.Fatalf("parse(stopped) = %q/%d, want \"not running\"/0", got, pid)
	}
	if got := parseState("nonsense"); got != "unknown" {
		t.Fatalf("parseState(nonsense) = %q, want unknown", got)
	}

	// And against the live system: a real, always-running Apple daemon, so
	// the parse is pinned to what launchctl actually prints here.
	if out, err := exec.Command("launchctl", "print", "system/com.apple.opendirectoryd").CombinedOutput(); err == nil {
		if got := parseState(string(out)); got != "running" {
			t.Fatalf("live parseState(opendirectoryd) = %q, want running", got)
		}
		if parsePID(string(out)) <= 0 {
			t.Fatalf("live parsePID(opendirectoryd) = 0, want a pid:\n%s", out)
		}
	}
}

// A label launchd has never heard of must read as "not loaded", not as an
// error the user has to interpret.
func TestPrintJobUnknownLabel(t *testing.T) {
	loaded, state, pid := printJob()
	if os.Geteuid() != 0 && loaded {
		t.Logf("note: %s is currently loaded on this machine (state=%q pid=%d)", ServiceTarget, state, pid)
		return
	}
	if loaded || state != "" || pid != 0 {
		t.Fatalf("printJob() = %v/%q/%d for an unbootstrapped label, want false/\"\"/0", loaded, state, pid)
	}
}

// The `agent … (source=…)` line is the observable transport state — the only
// way, without a control socket, to see whether the root path resolved the
// guest via the lease db.
func TestTailLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drawbridged.log")
	body := strings.Join([]string{
		"2026/07/30 11:59:00 drawbridged: agent 127.0.0.1:4777 (source=ssh-forwarder); mirroring…",
		"2026/07/30 12:00:00 drawbridged: agent transport 127.0.0.1:4777 (source=ssh-forwarder) → 192.168.64.2:4777 (source=vznat-leases)",
		"2026/07/30 12:00:01 drawbridged: mirroring guest :80 on 127.0.0.1:80",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, agent, err := tailLog(path, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 || !strings.Contains(tail[1], "mirroring guest :80") {
		t.Fatalf("tail = %v", tail)
	}
	if !strings.Contains(agent, "source=vznat-leases") {
		t.Fatalf("agent line = %q, want the most recent one", agent)
	}
	if _, _, err := tailLog(filepath.Join(t.TempDir(), "absent"), 0, 2); !os.IsNotExist(err) {
		t.Fatalf("missing log err = %v, want not-exist", err)
	}
}

// The log persists across installs, so Install cuts its read at the
// pre-bootstrap size: a previous daemon's lines — including its agent line —
// must never surface as the new daemon's account of itself.
func TestTailLogSince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drawbridged.log")
	oldRun := "2026/07/25 09:00:00 drawbridged: agent 127.0.0.1:4777 (source=ssh-forwarder); mirroring…\n" +
		"2026/07/25 09:00:01 drawbridged: mirroring guest :3000 on 127.0.0.1:3000\n"
	if err := os.WriteFile(path, []byte(oldRun), 0o644); err != nil {
		t.Fatal(err)
	}
	mark := logSize(path)

	// Nothing written past the mark yet: an empty tail and no agent line,
	// never the previous run's.
	tail, agent, err := tailLog(path, mark, 8)
	if err != nil || len(tail) != 0 || agent != "" {
		t.Fatalf("tail past a fresh mark = %v/%q/%v, want empty", tail, agent, err)
	}

	newRun := "2026/08/01 12:00:00 drawbridged: agent 192.168.64.2:4777 (source=vznat-leases); mirroring…\n" +
		"2026/08/01 12:00:01 drawbridged: mirroring guest :80 on 127.0.0.1:80\n"
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(newRun); err != nil {
		t.Fatal(err)
	}
	f.Close()

	tail, agent, err = tailLog(path, mark, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(tail) != 2 || strings.Contains(strings.Join(tail, "\n"), "guest :3000") {
		t.Fatalf("tail past the mark leaked previous-run lines: %v", tail)
	}
	if !strings.Contains(agent, "source=vznat-leases") || strings.Contains(agent, "ssh-forwarder") {
		t.Fatalf("agent line past the mark = %q, want only the new run's", agent)
	}

	// A file smaller than the mark was rotated: the mark means nothing, and
	// everything present is newer than it — read it all rather than nothing.
	if err := os.WriteFile(path, []byte(newRun), 0o644); err != nil {
		t.Fatal(err)
	}
	tail, agent, err = tailLog(path, mark+1<<20, 8)
	if err != nil || len(tail) != 2 || !strings.Contains(agent, "source=vznat-leases") {
		t.Fatalf("tail after rotation = %v/%q/%v, want the whole rotated file", tail, agent, err)
	}
}

// The mutating verbs must refuse unprivileged rather than half-succeed.
// (The test suite never runs as root; if it somehow does, skip.)
func TestMutatingVerbsNeedRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	// A dev Mac may carry a live install (root-owned artifacts), so the
	// no-write assertion below is "unchanged", not "absent".
	before := map[string]os.FileInfo{}
	for _, p := range []string{PlistPath, NewsyslogPath} {
		if fi, err := os.Stat(p); err == nil {
			before[p] = fi
		}
	}
	if _, err := Install(Config{VM: DefaultVM}, "", nil); !errors.Is(err, ErrNeedRoot) {
		t.Fatalf("Install unprivileged = %v, want ErrNeedRoot", err)
	}
	if err := Uninstall(nil); !errors.Is(err, ErrNeedRoot) {
		t.Fatalf("Uninstall unprivileged = %v, want ErrNeedRoot", err)
	}
	// Nothing may have been written (or removed) on the refused path.
	for _, p := range []string{PlistPath, NewsyslogPath} {
		fi, err := os.Stat(p)
		was, existed := before[p]
		switch {
		case err == nil && !existed:
			t.Fatalf("%s exists after a refused unprivileged install", p)
		case err != nil && existed:
			t.Fatalf("%s vanished across a refused unprivileged uninstall: %v", p, err)
		case err == nil && existed && (fi.Size() != was.Size() || !fi.ModTime().Equal(was.ModTime())):
			t.Fatalf("%s changed across a refused unprivileged install", p)
		}
	}
	// Query must work without root — that is the whole point of status.
	_ = Query()
}

// InstalledVersion's two answers are distinguishable, which is what lets
// doctor report "not installed" as a state rather than as a failure. The
// assertion adapts to whichever this machine is.
func TestInstalledVersionContract(t *testing.T) {
	got, err := InstalledVersion()
	switch {
	case errors.Is(err, ErrNotInstalled):
		if fileExists(BinaryPath) {
			t.Fatalf("%s exists but InstalledVersion reported ErrNotInstalled", BinaryPath)
		}
	case err != nil:
		t.Fatalf("InstalledVersion: %v", err)
	default:
		if got == "" {
			t.Fatal("InstalledVersion returned an empty version and no error")
		}
	}
}
