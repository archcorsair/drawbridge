package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// asciiStyles is the styles value every rendering test uses: the Ascii
// profile strips all sequences, so assertions read the same bytes a NO_COLOR
// or piped run prints — which is itself the contract (words, never color,
// carry the meaning).
func asciiStyles() styles {
	r := lipgloss.NewRenderer(io.Discard)
	r.SetColorProfile(termenv.Ascii)
	return newStyles(r)
}

// renderStatus must be honest about the three independent observations
// Status carries, and must never require the daemon to be reachable.
// (Moved from internal/install when rendering did — the wording contract is
// unchanged.)
func TestRenderStatus(t *testing.T) {
	sty := asciiStyles()
	var b bytes.Buffer
	renderStatus(&b, sty, install.Status{})
	// Pinned bytes, not merely contains: the no-daemon case must gain no new
	// noise, ever — scripts read this.
	if got, want := b.String(), "drawbridged: not installed\n  install with: sudo drawbridge install\n"; got != want {
		t.Fatalf("empty status = %q, want %q", got, want)
	}

	b.Reset()
	st := install.Status{
		PlistInstalled: true, BinaryInstalled: true,
		Loaded: true, State: "running", PID: 4242,
		AgentLine: "2026/07/30 12:00:00 drawbridged: agent 192.168.64.2:4777 (source=vznat-leases); mirroring…",
		LogTail:   []string{"line one", "line two"},
	}
	renderStatus(&b, sty, st)
	for _, want := range []string{"pid=4242", "state=running", "source=vznat-leases", "line two", install.PlistPath} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("report missing %q:\n%s", want, b.String())
		}
	}

	// Plist on disk but launchd doesn't know it: someone booted it out by
	// hand. That must not read as "running".
	b.Reset()
	renderStatus(&b, sty, install.Status{PlistInstalled: true, BinaryInstalled: true})
	if !strings.Contains(b.String(), "not loaded") {
		t.Fatalf("report does not flag the not-loaded state:\n%s", b.String())
	}
	if strings.Contains(b.String(), "not resolved yet") {
		t.Fatalf("a stopped daemon must not be told to watch for resolution:\n%s", b.String())
	}
}

// The agent line is promoted to the transport: field; when it is also among
// the tail lines (it usually is — it is a log line) it must not print twice.
func TestRenderStatusTransportNotDuplicated(t *testing.T) {
	agent := "2026/08/01 12:00:00 drawbridged: agent 192.168.64.2:4777 (source=vznat-leases); mirroring…"
	st := install.Status{
		PlistInstalled: true, BinaryInstalled: true,
		Loaded: true, State: "running", PID: 7,
		AgentLine: agent,
		LogTail:   []string{agent, "2026/08/01 12:00:01 drawbridged: mirroring guest :80 on 127.0.0.1:80"},
	}
	var b bytes.Buffer
	renderStatus(&b, asciiStyles(), st)
	if got := strings.Count(b.String(), "source=vznat-leases"); got != 1 {
		t.Fatalf("the transport line printed %d times, want once:\n%s", got, b.String())
	}
	if !strings.Contains(b.String(), "mirroring guest :80") {
		t.Fatalf("deduping the transport line dropped a real tail line:\n%s", b.String())
	}
}

// A running daemon with no agent line in the (install-cut) log is still
// resolving: say so instead of printing nothing.
func TestRenderStatusUnresolvedTransport(t *testing.T) {
	st := install.Status{
		PlistInstalled: true, BinaryInstalled: true,
		Loaded: true, State: "running", PID: 7, LogPresent: true,
	}
	var b bytes.Buffer
	renderStatus(&b, asciiStyles(), st)
	if !strings.Contains(b.String(), "not resolved yet") {
		t.Fatalf("running daemon without an agent line reported nothing:\n%s", b.String())
	}
}

// The status block's value column is aligned on the widest key: every key
// line starts its value at the same column, which is the whole point of the
// kv helper.
func TestRenderStatusAlignment(t *testing.T) {
	st := install.Status{
		PlistInstalled: true, BinaryInstalled: true,
		Loaded: true, State: "running", PID: 7,
		AgentLine: "drawbridged: agent 192.168.64.2:4777 (source=vznat-leases)",
	}
	var b bytes.Buffer
	renderStatus(&b, asciiStyles(), st)
	col := statusKeyWidth + 2
	for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
		if strings.HasPrefix(l, "  ") {
			continue // notes and tail gutters, not key lines
		}
		if len(l) <= col || l[col-1] != ' ' || l[col] == ' ' {
			t.Errorf("key line not aligned at column %d: %q", col, l)
		}
	}
}

func TestRenderWarning(t *testing.T) {
	var b bytes.Buffer
	renderWarning(&b, asciiStyles(), warning{
		title: "no -vm-mac given",
		body:  []string{"pin it:", "  sudo drawbridge install -vm x -vm-mac <addr>"},
	})
	want := "warning: no -vm-mac given\n  pin it:\n    sudo drawbridge install -vm x -vm-mac <addr>\n"
	if b.String() != want {
		t.Fatalf("warning = %q, want %q", b.String(), want)
	}
}
