// Package tui is `drawbridge tui`: a read-only bubbletea front end over the
// daemon introspection socket (docs/tui.md).
//
// Read-only by construction, not by policy. The introspection socket has no
// request grammar — the daemon writes one snapshot and closes, never reading a
// byte — so there is nothing here that could command a daemon even if it
// wanted to. Everything on screen is `introspect.State` as fetched, at 1 Hz,
// from every answering socket on this Mac.
//
// Nothing charm-flavored may leave this package and cmd/drawbridge:
// importgraph_test.go pins that the root daemon, the guest agent and the runc
// wrapper never link bubbletea or lipgloss.
package tui

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/archcorsair/drawbridge/internal/introspect"
	tea "github.com/charmbracelet/bubbletea"
)

// Run draws the TUI until the user quits. The alt screen means the shell the
// user came from is untouched; bubbletea restores the terminal on quit, on
// ctrl+c and on panic, and Run's error is what the caller turns into a
// non-zero exit — after the restore, so the message is readable.
func Run(opts Options) error {
	defer silenceLog()()
	p := tea.NewProgram(newModel(opts), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// silenceLog mutes the stdlib logger for the TUI's lifetime and returns the
// restore. The doctor view runs gathers in-process, and packages under them
// (limaaddr's name-only lease warning, live 2026-08-01) log straight to
// stderr — which bypasses bubbletea's renderer and tears the alt screen.
// Nothing is lost: the same facts reach the user through doctor's own
// findings here, and through every plain CLI path once the TUI exits.
func silenceLog() func() {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	return func() { log.SetOutput(prev) }
}

// userRunDirDisplay is the user socket directory as the no-daemon card names
// it — abbreviated to `~/…` when it really is under this user's home, and the
// literal path when it is not (sudo, a moved HOME), because a tilde that lies
// about which directory was checked is worse than a long line.
func userRunDirDisplay() string {
	dir, err := introspect.UserRunDir()
	if err != nil {
		return "(this user has no home directory to hold one)"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" && strings.HasPrefix(dir, home+string(os.PathSeparator)) {
		dir = "~" + strings.TrimPrefix(dir, home)
	}
	return dir + "/"
}
