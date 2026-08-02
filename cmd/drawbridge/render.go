package main

// Presentation for the install/uninstall/status verbs. lipgloss is
// sanctioned for the CLI (docs/HANDOFF.md: lipgloss-not-gum) and confined to
// cmd/drawbridge + internal/tui by TestDaemonBinariesDoNotLinkCharm — which
// is why internal/install reports data and this file owns the rendering.
//
// Styling is emphasis only: every state is carried by a word, so NO_COLOR,
// TERM=dumb and piped output print the same text uncolored. lipgloss
// resolves the color profile per stream, hence one styles value per file.

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
)

// styles maps the semantic classes this CLI prints — the same ANSI-16
// adaptive pairs as internal/tui/styles.go, so `status` and the TUI agree on
// what ok/warn/error look like.
type styles struct {
	key  lipgloss.Style // field names
	dim  lipgloss.Style // gutters, notes, the drawbridge: prefix
	ok   lipgloss.Style
	warn lipgloss.Style
	err  lipgloss.Style
}

func newStyles(r *lipgloss.Renderer) styles {
	return styles{
		key:  r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "4", Dark: "12"}),
		dim:  r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "7", Dark: "8"}),
		ok:   r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "2", Dark: "10"}),
		warn: r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "3", Dark: "11"}),
		err:  r.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "1", Dark: "9"}),
	}
}

var (
	stdoutStyles = newStyles(lipgloss.NewRenderer(os.Stdout))
	stderrStyles = newStyles(lipgloss.NewRenderer(os.Stderr))
)

// stepLine adapts a stream to install.Step in the house progress format —
// the same `drawbridge: ` prefix `up` prints, so a plain terminal sees the
// format these verbs have always used.
func stepLine(w io.Writer, sty styles) install.Step {
	return func(format string, args ...any) {
		fmt.Fprintf(w, "%s %s\n", sty.dim.Render("drawbridge:"), fmt.Sprintf(format, args...))
	}
}

// statusKeyWidth aligns the value column on the widest key, `transport:`.
const statusKeyWidth = len("transport:")

func kv(w io.Writer, sty styles, key, val string) {
	k := key + ":"
	fmt.Fprintf(w, "%s%s%s\n", sty.key.Render(k), strings.Repeat(" ", statusKeyWidth-len(k)+2), val)
}

// renderStatus is the single human renderer for install.Status: `status` and
// the tail of a successful `install` print through it, so the wording is
// testable in one place and identical on both paths. The transport line is
// promoted out of the tail — a tail line equal to it is skipped, never
// printed twice.
func renderStatus(w io.Writer, sty styles, st install.Status) {
	if !st.Installed() && !st.Loaded {
		// Pinned low-noise: a Mac with nothing installed gains no decoration
		// (render_test.go holds these bytes).
		fmt.Fprintf(w, "drawbridged: not installed\n")
		fmt.Fprintf(w, "  install with: sudo drawbridge install\n")
		return
	}
	kv(w, sty, "label", install.Label)
	kv(w, sty, "plist", install.PlistPath+" "+presence(sty, st.PlistInstalled))
	kv(w, sty, "binary", install.BinaryPath+" "+presence(sty, st.BinaryInstalled))
	switch {
	case !st.Loaded:
		kv(w, sty, "launchd", sty.warn.Render("not loaded")+" — `sudo drawbridge install` to (re)bootstrap")
	case st.PID > 0:
		kv(w, sty, "launchd", "state="+stateStyle(sty, st.State).Render(st.State)+fmt.Sprintf(" pid=%d", st.PID))
	default:
		kv(w, sty, "launchd", "state="+stateStyle(sty, st.State).Render(st.State)+" (no pid)")
	}
	switch {
	case st.AgentLine != "":
		kv(w, sty, "transport", strings.TrimSpace(st.AgentLine))
	case st.Running():
		// Running with no agent line in the (possibly cut) log: resolution
		// has not landed yet. The daemon retries on its own.
		kv(w, sty, "transport", sty.warn.Render("not resolved yet")+" — the daemon retries; watch the log")
	}
	kv(w, sty, "log", install.LogPath)
	if st.LogNote != "" {
		fmt.Fprintf(w, "  %s\n", sty.dim.Render("("+st.LogNote+")"))
	}
	for _, l := range st.LogTail {
		if l == st.AgentLine {
			continue // promoted to the transport: line above
		}
		fmt.Fprintf(w, "  %s %s\n", sty.dim.Render("|"), l)
	}
}

// renderCalmStatus is the default `status` form (the full renderStatus +
// renderDaemons pair is `-v`): when a live daemon answers its introspection
// socket, the snapshot IS the status — one compact block per daemon, no
// launchctl inference, no paths, no log tail. When nothing answers, it
// reports false and the caller falls back to the full form: there the
// launchctl half and the log tail are the only evidence, and detail is the
// diagnosis. Unreadable and schema-skewed sockets print in both modes —
// truncating a health report is calm, truncating a problem is silence.
func renderCalmStatus(w io.Writer, sty styles, st install.Status, snaps []*introspect.Snapshot, problems []error) bool {
	renderSnapshotIssues(w, sty, snaps, problems)
	rendered := false
	for _, s := range snaps {
		if s == nil || !s.Usable {
			continue
		}
		rendered = true
		d := s.State
		flavor := "foreground"
		if st.Running() && st.PID == d.PID {
			flavor = "installed (launchd)"
		} else if d.EUID != 0 {
			flavor = fmt.Sprintf("foreground (euid %d)", d.EUID)
		}
		fmt.Fprintf(w, "%s  %s · pid %d · %s · %s\n",
			sty.key.Render("drawbridged"), sty.ok.Render("running"), d.PID, orUnknown(d.Version), flavor)
		fmt.Fprintf(w, "%s%s\n", dk(sty, "vm"), orUnknown(d.VM.Ref))
		fmt.Fprintf(w, "%s%s (%s)\n", dk(sty, "endpoint"), orUnknown(d.Resolution.Endpoint), orUnknown(d.Resolution.Source))
		if d.Resolution.Note != "" {
			fmt.Fprintf(w, "%s%s\n", dk(sty, "note"), d.Resolution.Note)
		}
		fmt.Fprintf(w, "%s%s (secret %s)\n", dk(sty, "auth"), orUnknown(d.Auth.Mode), orUnknown(d.Auth.SecretState))
		fmt.Fprintf(w, "%ssession %s · %d bound of %d entries\n",
			dk(sty, "mirror"), upDown(d.Mirror.SessionUp), countState(d.Mirror.Entries, introspect.EntryBound), len(d.Mirror.Entries))
		fmt.Fprintf(w, "%ssession %s · %d advertised · %d parked\n",
			dk(sty, "sync"), upDown(d.Sync.SessionUp), len(d.Sync.Advertised), d.Sync.PoolParked)
	}
	return rendered
}

// renderSnapshotIssues prints the sockets that answered wrongly — unreadable
// payloads and schema skews — in the wording renderDaemons has always used.
func renderSnapshotIssues(w io.Writer, sty styles, snaps []*introspect.Snapshot, problems []error) {
	head := sty.key.Render("daemon:") + "  "
	for _, p := range problems {
		fmt.Fprintf(w, "%s%s a socket answered with something that is not a snapshot: %v\n", head, sty.warn.Render("warning:"), p)
	}
	for _, s := range snaps {
		if s == nil || s.Usable {
			continue
		}
		fmt.Fprintf(w, "%s%s speaks introspection schema %d, this CLI knows %d (version %s)\n",
			head, s.Path, s.State.Schema, introspect.Schema, orUnknown(s.State.Version))
	}
}

func presence(sty styles, ok bool) string {
	if ok {
		return sty.ok.Render("(present)")
	}
	return sty.err.Render("(missing)")
}

func stateStyle(sty styles, state string) lipgloss.Style {
	if state == "running" {
		return sty.ok
	}
	return sty.warn
}

// dk pads one daemon-section sub-key ("  vm:        ") to the column the
// section has always used; padding is computed on the plain text so ANSI
// sequences never shift the column.
func dk(sty styles, key string) string {
	k := key + ":"
	return "  " + sty.key.Render(k) + strings.Repeat(" ", len("endpoint:")-len(k)+2)
}

// warning is a deferred advisory. runInstall collects these while it parses
// flags and prints them after the install's status block — the last thing on
// screen — instead of as a wall of text the install output scrolls away.
type warning struct {
	title string   // one line, printed after "warning: "
	body  []string // indented detail; command lines carry their own deeper indent
}

func renderWarning(w io.Writer, sty styles, warn warning) {
	fmt.Fprintf(w, "%s %s\n", sty.warn.Render("warning:"), warn.title)
	for _, l := range warn.body {
		fmt.Fprintf(w, "  %s\n", l)
	}
}
