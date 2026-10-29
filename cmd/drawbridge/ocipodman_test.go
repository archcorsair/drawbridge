package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runRestartScript executes a rendered restart script under /bin/sh with a
// stub systemctl first on PATH. The stub appends its argv, one bracketed word
// per argument, to a log, and exits `exit` for the verbs listed in failVerbs
// and 0 otherwise. The fake guest answers the marker without running the
// script, which is how M9's shell-parse bug went unseen, so this is the test
// that actually parses it.
func runRestartScript(t *testing.T, script string, failVerbs ...string) (marker string, calls []string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "calls.log")
	stub := `#!/bin/sh
for a in "$@"; do printf '[%s]' "$a" >> "` + logPath + `"; done
printf '\n' >> "` + logPath + `"
for a in "$@"; do
  case " ` + strings.Join(failVerbs, " ") + ` " in *" $a "*) exit 1;; esac
done
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin"}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script failed: %v\nstderr: %s\nscript:%s", err, stderr.String(), script)
	}
	if stderr.Len() != 0 {
		t.Fatalf("script wrote to stderr (a shell parse error looks like this):\n%s", stderr.String())
	}
	raw, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if s := strings.TrimSpace(string(raw)); s != "" {
		calls = strings.Split(s, "\n")
	}
	return strings.TrimSpace(string(out)), calls
}

// The restart script must hand systemctl the manager's words in order, for
// both the rootful and the rootless manager (audit M9, NEW-E3).
func TestRestartPodmanAPIScriptExecutes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rootful bool
		user    string
		prefix  string // the words before the verb, as the stub logs them
	}{
		{"rootful", true, "", ""},
		{"rootless", false, "core", "[--user][-M][core@.host]"},
		{"rootless dotted name", false, "first.last-1", "[--user][-M][first.last-1@.host]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc, ok := podmanManager(tc.rootful, tc.user)
			if !ok {
				t.Fatalf("no manager for rootful=%v user=%q", tc.rootful, tc.user)
			}
			marker, calls := runRestartScript(t, renderRestartPodmanAPIScript(sc))
			if marker != "drawbridge-podman=restarted" {
				t.Fatalf("marker = %q, want restarted (the stub reports the unit active)", marker)
			}
			want := []string{
				tc.prefix + "[cat][podman.service]",
				tc.prefix + "[is-active][--quiet][podman.service]",
				tc.prefix + "[reset-failed][podman.service]",
				tc.prefix + "[restart][podman.service]",
				tc.prefix + "[is-active][--quiet][podman.service]",
			}
			if strings.Join(calls, "\n") != strings.Join(want, "\n") {
				t.Fatalf("systemctl argv:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// Idle and failed outcomes still go through the real manager words.
func TestRestartPodmanAPIScriptOutcomes(t *testing.T) {
	sc, _ := podmanManager(false, "core")
	script := renderRestartPodmanAPIScript(sc)

	marker, calls := runRestartScript(t, script, "is-active")
	if marker != "drawbridge-podman=idle" || len(calls) != 2 {
		t.Fatalf("inactive unit: marker=%q calls=%q, want idle after cat and is-active", marker, calls)
	}
	marker, _ = runRestartScript(t, script, "cat")
	if marker != "drawbridge-podman=absent" {
		t.Fatalf("no unit: marker=%q, want absent", marker)
	}
	marker, _ = runRestartScript(t, script, "restart")
	if marker != "drawbridge-podman=failed" {
		t.Fatalf("restart refused: marker=%q, want failed", marker)
	}
}

// A login name outside the conservative set is refused, not escaped, and the
// rendered line cannot be broken out of even if it were not.
func TestPodmanManagerRefusesUnsafeUsers(t *testing.T) {
	for _, u := range []string{"", "-core", "co re", "core;id", "core'x", "co$re", "a\nb", "core@host", "ünï"} {
		if sc, ok := podmanManager(false, u); ok {
			t.Errorf("podmanManager(rootless, %q) = %q, want refusal", u, sc)
		}
	}
	if sc, ok := podmanManager(true, "ignored;rm"); !ok || sc != "systemctl" {
		t.Errorf("rootful must ignore the user name, got %q ok=%v", sc, ok)
	}
	if got := renderRestartPodmanAPIScript("systemctl --user -M a'b@.host"); !strings.Contains(got, `SC='systemctl --user -M a'\''b@.host'`) {
		t.Errorf("shquote not applied to SC:\n%s", got)
	}
}

// L40: the remedy names the manager that was targeted.
func TestPodmanRemedyMatchesTargetedManager(t *testing.T) {
	if got := podmanRemedy(true); !strings.Contains(got, "sudo systemctl restart podman.service") || strings.Contains(got, "--user") {
		t.Errorf("rootful remedy = %q", got)
	}
	if got := podmanRemedy(false); !strings.Contains(got, "systemctl --user restart podman.service") || strings.Contains(got, "sudo") {
		t.Errorf("rootless remedy = %q", got)
	}
}

// The warning a person actually sees carries the manager-specific remedy.
func TestReportPodmanRestartFailureNamesTheRightManager(t *testing.T) {
	for _, tc := range []struct {
		rootful bool
		want    string
		notWant string
	}{
		{true, "sudo systemctl restart podman.service", "--user"},
		{false, "systemctl --user restart podman.service", "sudo"},
	} {
		var buf strings.Builder
		reportPodmanRestart(&guest{out: &buf}, podmanFailed, "--oci", tc.rootful)
		got := buf.String()
		if !strings.Contains(got, tc.want) || strings.Contains(got, tc.notWant) {
			t.Errorf("rootful=%v warning:\n%s", tc.rootful, got)
		}
	}
}
