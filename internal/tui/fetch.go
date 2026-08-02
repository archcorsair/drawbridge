package tui

import (
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	tea "github.com/charmbracelet/bubbletea"
)

// refreshInterval is fixed at 1 Hz and deliberately not a flag (§4.3): one
// cadence is one less thing the quickstart has to explain, and a flag is cheap
// to add if anyone asks for it.
const refreshInterval = time.Second

type tickMsg time.Time

// snapshotsMsg is one FetchAll result. It carries its own timestamp because
// "refreshed Ns ago" is the client's fetch time, not a daemon-reported one.
type snapshotsMsg struct {
	snaps    []*introspect.Snapshot
	problems []error
	at       time.Time
}

func tickCmd() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// fetchCmd is the only I/O the dashboard does. D4: there is no separate
// Discover cadence — FetchAll globs and stats on every call for microseconds,
// so sockets appearing, vanishing and going stale are all caught within one
// tick by the same code path doctor and status already exercise.
//
// It is itself a tea.Cmd: bubbletea runs it on its own goroutine and the model
// only ever sees the message.
func fetchCmd() tea.Msg {
	snaps, problems := introspect.FetchAll(introspect.DialTimeout)
	return snapshotsMsg{snaps: snaps, problems: problems, at: time.Now()}
}
