package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
)

// The refusals pane (docs/tui.md §3.2) over D5's client-side accumulation.
//
// Each snapshot carries the daemon's fixed introspect.RingSize ring, and the
// TUI keeps a per-path append-only log of every entry it has seen. The loss
// bound is stated in the pane header rather than hidden: at 1 Hz the log is
// lossless up to a ring's worth of refusals per second, and past that the
// overflow is gone — that rate of refusals being itself the finding.
const (
	// refusalCap is D5's bound, oldest-first: a pane, not an audit log.
	refusalCap = 512

	// panePercent and minPaneLines are §3.2's split.
	panePercent  = 40
	minPaneLines = 6

	// refusalTimeW and refusalIDW are the two fixed columns, each including
	// its trailing gap. The ID column fits the longest contract ID
	// (`auth-mac-missing-secret`) whole.
	refusalTimeW = 10
	refusalIDW   = 25

	// refusalClock is the local wall-clock spelling. The timestamp is
	// formatted in its own location — the daemon that stamped it runs on this
	// Mac, so its zone is the reader's — never converted, which is also what
	// keeps View pure across machines.
	refusalClock = "15:04:05"
)

// refusalEmpty is §3.2's wording for a log with nothing in it yet: an empty
// pane is not a claim that the daemon has refused nothing ever.
const refusalEmpty = "(no refusals seen since attach — the ring starts with what the daemon remembers)"

// accumulate folds one fetch's ring into a path's log (D5). Identity is the
// full (At, ID, Line) triple; new entries append in ring order; the log keeps
// the newest refusalCap.
//
// The triple is compared through a key rather than by struct equality: two
// decodes of the same non-UTC timestamp carry distinct *time.Location
// pointers, so `==` on the Refusal would call every entry new and the log
// would fill with duplicates within a second.
func accumulate(log, ring []introspect.Refusal) []introspect.Refusal {
	if len(ring) == 0 {
		return log
	}
	seen := make(map[string]struct{}, len(log)+len(ring))
	for _, r := range log {
		seen[refusalKey(r)] = struct{}{}
	}
	var add []introspect.Refusal
	for _, r := range ring {
		k := refusalKey(r)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		add = append(add, r)
	}
	if len(add) == 0 {
		return log
	}
	// A fresh slice, always: the model is a value and an in-place append would
	// let one Update's log alias another's.
	out := make([]introspect.Refusal, 0, len(log)+len(add))
	out = append(append(out, log...), add...)
	if len(out) > refusalCap {
		out = out[len(out)-refusalCap:]
	}
	return out
}

func refusalKey(r introspect.Refusal) string {
	return strconv.FormatInt(r.At.UnixNano(), 10) + "\x00" + r.ID + "\x00" + r.Line
}

// The footer's unseen counter. The watermark is the newest refusal the pane
// has shown, keyed by identity rather than by a log length: the log trims from
// its front at refusalCap, and a length watermark would silently stop counting
// exactly when a daemon is refusing hard enough to matter.

// unseenRefusals is how many entries have landed in a path's log since its
// pane last had it on screen. An unwatermarked path counts its whole log —
// what accumulated before the pane was ever opened is precisely what the
// counter is there to advertise.
func (m Model) unseenRefusals(path string) int {
	log := m.refusals[path]
	mark, ok := m.refusalsSeen[path]
	if !ok {
		return len(log)
	}
	for i := len(log) - 1; i >= 0; i-- {
		if refusalKey(log[i]) == mark {
			return len(log) - 1 - i
		}
	}
	// The watermark aged out of the capped log: everything still in it is
	// newer than what was seen.
	return len(log)
}

// markRefusalsSeen watermarks the selected path when its log is on screen. A
// fresh map, like every other per-Update map: the model is a value and an
// in-place write would reach into the state a previous Update returned.
func (m Model) markRefusalsSeen() Model {
	log := m.refusals[m.selected]
	if m.pane != paneRefusals || len(log) == 0 {
		return m
	}
	seen := make(map[string]string, len(m.refusalsSeen)+1)
	for k, v := range m.refusalsSeen {
		seen[k] = v
	}
	seen[m.selected] = refusalKey(log[len(log)-1])
	m.refusalsSeen = seen
	return m
}

// pruneSeen drops the watermarks of paths D7 has retired, so a socket that
// comes and goes all day cannot grow the map without bound.
func (m Model) pruneSeen() map[string]string {
	out := make(map[string]string, len(m.refusalsSeen))
	for path, mark := range m.refusalsSeen {
		if _, ok := m.refusals[path]; ok {
			out[path] = mark
		}
	}
	return out
}

// paneLines is the pane's height in rows, header included: 40% of the window,
// never under six, and never so much of a short window that the dashboard
// above it has nowhere to render.
func (m Model) paneLines(lo layout) int {
	if m.pane != paneRefusals {
		return 0
	}
	return min(max(minPaneLines, lo.height*panePercent/100), max(1, lo.height-2))
}

// refusalPane renders the bottom split: the rule line with the count and the
// loss bound, then the selected daemon's log with the newest at the bottom.
func (m Model) refusalPane(lo layout) []string {
	h := m.paneLines(lo)
	if h <= 0 {
		return nil
	}
	w := lo.contentWidth() - lo.indent
	pad := strings.Repeat(" ", lo.indent)
	log := m.refusals[m.selected]

	body := make([]string, 0, max(len(log), 1))
	if len(log) == 0 {
		body = append(body, styleDim.Render(truncEnd(refusalEmpty, w)))
	}
	for _, r := range log {
		body = append(body, refusalLine(r, lo, w))
	}

	out := make([]string, 0, h)
	out = append(out, pad+refusalRule(len(log), w))
	// Rows start under the rule, oldest first, newest last — log-file order
	// (T2's bottom-float was reversed on user feedback 2026-08-01: rows
	// hovering above the footer with dead space over them read as upside
	// down). When the log outgrows the pane, the follow window still keeps
	// the newest line visible at the bottom edge.
	first, last := m.paneScroll().window(len(body), h-1)
	for _, l := range body[first:last] {
		out = append(out, pad+l)
	}
	for len(out) < h {
		out = append(out, "")
	}
	return out[:min(len(out), h)]
}

// paneScroll is the pane's window. It follows the bottom whenever the pane is
// not the region m.scroll drives — an overlay borrows the scroll keys, and a
// pane left at someone else's offset would be showing an arbitrary slice.
func (m Model) paneScroll() scrollState {
	if m.scrollRegion() == regionRefusals {
		return m.scroll
	}
	return scrollState{follow: true}
}

func refusalRule(n, width int) string {
	head := "─ " + refusalHeader(n, max(0, width-4)) + " "
	return styleDim.Render(head + strings.Repeat("─", max(0, width-visWidth(head))))
}

// refusalHeader states D5's loss bound in the pane's own header, in whichever
// spelling fits: a log that silently drops what the ring rotated past would
// read as an audit trail, which it is not.
func refusalHeader(n, width int) string {
	full := fmt.Sprintf("refusals · %d kept (ring carries last %d per refresh)", n, introspect.RingSize)
	if visWidth(full) <= width {
		return full
	}
	return truncEnd(fmt.Sprintf("refusals · %d kept · last %d/refresh", n, introspect.RingSize), width)
}

// refusalLine is one entry: wall clock, the stable ID, and the daemon's line
// verbatim. The ID is shown because it is the vocabulary doctor's findings use
// — the pane teaches it by printing it.
func refusalLine(r introspect.Refusal, lo layout, width int) string {
	var b strings.Builder
	rest := width
	// The clock column drops at the same width the mirror table's SINCE column
	// does: below it, the ID and the line are what is worth the columns.
	if lo.showSince {
		b.WriteString(padRight(r.At.Format(refusalClock), refusalTimeW))
		rest -= refusalTimeW
	}
	b.WriteString(padRight(refusalStyle(r.ID).Render(truncEnd(r.ID, refusalIDW-2)), refusalIDW))
	rest -= refusalIDW
	b.WriteString(truncEnd(oneLine(r.Line), rest))
	return b.String()
}

// refusalStyle colors one ID by class (§3.2). The auth causes are
// transport-auth §7's, matched by their shared prefix rather than by a list
// this package would have to chase; `mirror-skip` is dim for the same reason
// the skipped mirror rows are — the skip list is the default exclusion at
// work, not an error.
func refusalStyle(id string) lipgloss.Style {
	switch {
	case strings.HasPrefix(id, "auth-"):
		return styleErr
	case id == introspect.IDMirrorSkip:
		return styleDim
	default:
		return styleWarn
	}
}
