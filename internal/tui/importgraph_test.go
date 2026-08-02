package tui

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// charmPrefix covers bubbletea, lipgloss and their charm-ecosystem tree — and
// transitively internal/tui itself, since this package imports charm code. One
// substring therefore pins the boundary in both directions.
const charmPrefix = "github.com/charmbracelet/"

// docs/tui.md §6: charm code may link into cmd/drawbridge only. The root
// daemon, the guest agent and the runc wrapper must never grow a terminal UI
// dependency — the daemon runs under launchd with no terminal at all, and the
// two guest binaries are cross-compiled artifacts embedded in the CLI.
//
// This is a test rather than a convention because it fails at the exact commit
// that introduces the leak, with the offending package named.
func TestDaemonBinariesDoNotLinkCharm(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH; the import-graph boundary is unchecked in this harness")
	}
	for _, tc := range []struct {
		goos string
		pkg  string
	}{
		{"darwin", "./cmd/drawbridged"},
		{"linux", "./cmd/drawbridge-agent"},
		{"linux", "./cmd/drawbridge-runc"},
	} {
		t.Run(tc.goos+tc.pkg, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", tc.pkg)
			cmd.Dir = "../.." // repo root: -deps is resolved against the module
			cmd.Env = append(os.Environ(), "GOOS="+tc.goos)
			out, err := cmd.Output()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					t.Fatalf("go list -deps %s (GOOS=%s): %v\n%s", tc.pkg, tc.goos, err, ee.Stderr)
				}
				t.Fatalf("go list -deps %s (GOOS=%s): %v", tc.pkg, tc.goos, err)
			}
			for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.Contains(dep, charmPrefix) {
					t.Errorf("%s (GOOS=%s) imports %s — charm code belongs to cmd/drawbridge and internal/tui only", tc.pkg, tc.goos, dep)
				}
			}
		})
	}
}
