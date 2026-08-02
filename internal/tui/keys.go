package tui

import (
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// The keymap is the one source of truth for docs/tui.md §4: the Update loop
// dispatches through these bindings and the help overlay is rendered from the
// same values, so the two cannot drift (keys_test.go walks the struct and
// asserts every binding reaches the overlay).
//
// §4 is a Phase 6 contract — the quickstart cites these keys — so the whole
// map is laid down now. Bindings whose views land later (refusals in T2, the
// doctor view in T3, the switcher overlay in T2) are present here and in the
// help, and their dispatch arms are no-ops until then; a key that is
// documented and inert is honest, a key that is documented and absent is not.
type binding struct {
	// keys are the tea.KeyMsg strings this binding answers to.
	keys []string
	// label is how the key reads in the help overlay — the human spelling
	// (`j, ↓`), not the dispatch spelling.
	label string
	help  string
}

func (b binding) matches(msg tea.KeyMsg) bool {
	s := msg.String()
	for _, k := range b.keys {
		if k == s {
			return true
		}
	}
	return false
}

type keyMap struct {
	Quit         binding
	Help         binding
	Esc          binding
	NextDaemon   binding
	PrevDaemon   binding
	SelectDaemon binding
	Switcher     binding
	Refusals     binding
	Doctor       binding
	SyncExpand   binding

	LineDown binding
	LineUp   binding
	PageDown binding
	PageUp   binding
	Top      binding
	Bottom   binding

	Expand binding
	Rerun  binding
	Probe  binding

	SwitcherMove   binding
	SwitcherSelect binding
	SwitcherClose  binding
}

// No function keys, no alt/meta chords, and no ctrl beyond ctrl+c: the map has
// to survive small keyboards and SSH (§4).
func defaultKeys() keyMap {
	return keyMap{
		Quit:         binding{keys: []string{"q", "ctrl+c"}, label: "q, ctrl+c", help: "quit (terminal restored)"},
		Help:         binding{keys: []string{"?"}, label: "?", help: "toggle this help overlay"},
		Esc:          binding{keys: []string{"esc"}, label: "esc", help: "close the topmost overlay, else the refusals pane; doctor view: cancel a gather, else back"},
		NextDaemon:   binding{keys: []string{"tab", "l", "right"}, label: "tab, l, right", help: "next daemon"},
		PrevDaemon:   binding{keys: []string{"shift+tab", "h", "left"}, label: "shift+tab, h, left", help: "previous daemon"},
		SelectDaemon: binding{keys: []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}, label: "1-9", help: "select daemon N (switcher order)"},
		Switcher:     binding{keys: []string{"v"}, label: "v", help: "toggle the daemon switcher overlay"},
		Refusals:     binding{keys: []string{"r"}, label: "r", help: "toggle the refusals pane (the footer counts what it has not shown yet)"},
		Doctor:       binding{keys: []string{"d"}, label: "d", help: "open the doctor view (runs a gather on first entry)"},
		SyncExpand:   binding{keys: []string{"x"}, label: "x", help: "dashboard: expand / collapse the folded ephemeral SYNC rows"},

		LineDown: binding{keys: []string{"j", "down"}, label: "j, down", help: "line down (doctor view: move the cursor)"},
		LineUp:   binding{keys: []string{"k", "up"}, label: "k, up", help: "line up (doctor view: move the cursor)"},
		PageDown: binding{keys: []string{"pgdown", " "}, label: "pgdn, space", help: "page down"},
		PageUp:   binding{keys: []string{"pgup", "b"}, label: "pgup, b", help: "page up"},
		Top:      binding{keys: []string{"g"}, label: "g", help: "top"},
		Bottom:   binding{keys: []string{"G"}, label: "G", help: "bottom (re-engages follow in the refusals pane)"},

		Expand: binding{keys: []string{"enter"}, label: "enter", help: "expand / collapse the selected finding"},
		Rerun:  binding{keys: []string{"R"}, label: "R", help: "re-run the gather"},
		Probe:  binding{keys: []string{"p"}, label: "p", help: "re-run with the half-close probe (~20s+)"},

		SwitcherMove:   binding{keys: []string{"j", "k", "up", "down"}, label: "j/k, up/down", help: "move"},
		SwitcherSelect: binding{keys: []string{"enter"}, label: "enter", help: "select daemon and close"},
		SwitcherClose:  binding{keys: []string{"esc", "v"}, label: "esc, v", help: "close without changing selection"},
	}
}

type helpGroup struct {
	name string
	rows []binding
}

// groups is the §4.1 grouping, and the help overlay renders nothing else —
// adding a binding without listing it here fails the drift test.
func (k keyMap) groups() []helpGroup {
	return []helpGroup{
		{"Global", []binding{k.Quit, k.Help, k.Esc, k.NextDaemon, k.PrevDaemon, k.SelectDaemon, k.Switcher, k.Refusals, k.Doctor, k.SyncExpand}},
		{"Scrolling", []binding{k.LineDown, k.LineUp, k.PageDown, k.PageUp, k.Top, k.Bottom}},
		{"Doctor view", []binding{k.Expand, k.Rerun, k.Probe}},
		{"Switcher overlay", []binding{k.SwitcherMove, k.SwitcherSelect, k.SwitcherClose}},
	}
}

// shortHelpFull is §4.2's advertised surface, verbatim: exactly five entries,
// and the entire set a user who never presses `?` needs.
const shortHelpFull = "tab next daemon · r refusals · d doctor · ? help · q quit"

// shortHelpCompact and shortHelpTiny are the same five entries spelled for a
// terminal too narrow for the long form — down to the minimum window, where
// the keys keep their letters and the words they lose are one `?` away. Five
// entries is the contract; the spelling is not.
const (
	shortHelpCompact = "tab daemon · r refusals · d doctor · ? help · q quit"
	shortHelpTiny    = "tab · r · d · ? help · q quit"
)

// unseen is what the selected daemon has refused since its pane was last open
// (§3.2). It rides on the refusals entry rather than becoming a sixth one: the
// five are the contract, and a counter is a property of one of them.
func shortHelp(width, unseen int) string {
	badge := refusalBadge(unseen)
	for _, s := range []string{shortHelpFull, shortHelpCompact, shortHelpTiny} {
		if s = withBadge(s, badge); visWidth(s) <= width {
			return s
		}
	}
	return withBadge(shortHelpTiny, badge)
}

// refusalBadge caps its own width so a burst of refusals cannot push the
// footer into a narrower spelling one refresh and back the next.
func refusalBadge(unseen int) string {
	switch {
	case unseen <= 0:
		return ""
	case unseen > 99:
		return styleWarn.Render("(99+)")
	default:
		return styleWarn.Render("(" + strconv.Itoa(unseen) + ")")
	}
}

// withBadge attaches the counter to the refusals entry of a footer spelling.
// It works on the split entries rather than the rendered line so the five
// stay five by construction, whatever the spelling.
func withBadge(s, badge string) string {
	if badge == "" {
		return s
	}
	parts := strings.Split(s, " · ")
	for i, p := range parts {
		if p == "r" || strings.HasPrefix(p, "r ") {
			parts[i] = p + " " + badge
			break
		}
	}
	return strings.Join(parts, " · ")
}

// The doctor view's footer: §4.2's context-sensitive swap, five entries like
// every other spelling. `p` carries its price in the key line itself (§3.3) —
// the half-close probe outlasts the agent's liveness ping, and a key that
// costs twenty seconds has to say so before it is pressed, not after.
const (
	doctorHelpFull    = "enter expand · R re-run · p probe (~20s+) · esc back · ? help"
	doctorHelpCompact = "enter expand · R re-run · p probe · esc back · ? help"
	doctorHelpTiny    = "enter · R · p · esc back · ? help"

	// escBack/escCancel is esc's two-step (§4.1) spelled where the user is
	// looking. A footer that says `back` while esc would cancel is the one
	// place this key could surprise someone.
	escBack   = "esc back"
	escCancel = "esc cancel"
)

func doctorShortHelp(width int, running bool) string {
	for _, s := range []string{doctorHelpFull, doctorHelpCompact, doctorHelpTiny} {
		if running {
			s = strings.Replace(s, escBack, escCancel, 1)
		}
		if visWidth(s) <= width {
			return s
		}
	}
	if running {
		return strings.Replace(doctorHelpTiny, escBack, escCancel, 1)
	}
	return doctorHelpTiny
}

// helpBody renders the §4.1 tables as one line list. The label column is sized
// from the widest label so the four groups line up as a single table.
func helpBody(k keyMap) []string {
	labelw := 0
	for _, g := range k.groups() {
		for _, b := range g.rows {
			if w := visWidth(b.label); w > labelw {
				labelw = w
			}
		}
	}
	var body []string
	for i, g := range k.groups() {
		if i > 0 {
			body = append(body, "")
		}
		body = append(body, styleTitle.Render(g.name))
		for _, b := range g.rows {
			body = append(body, "  "+padRight(b.label, labelw)+"  "+b.help)
		}
	}
	return body
}

// dispatchedBindings names the bindings Update acts on in the dashboard scope.
// The drift test uses this list to pin that dispatch never reaches a key the
// help does not show, and that no two arms in one scope answer to the same key.
func (k keyMap) dispatchedBindings() []binding {
	return []binding{
		k.Quit, k.Help, k.Esc, k.NextDaemon, k.PrevDaemon, k.SelectDaemon,
		k.Switcher, k.Refusals, k.Doctor, k.SyncExpand,
		k.LineDown, k.LineUp, k.PageDown, k.PageUp, k.Top, k.Bottom,
	}
}

// doctorBindings is the same list for the doctor view: its own five claim
// esc/enter/R/p and the movement keys, and everything it does not claim falls
// through to the global map, so `tab`, `1`–`9`, `v` and `r` keep working from
// inside the view.
func (k keyMap) doctorBindings() []binding {
	return []binding{
		k.Quit, k.Help, k.Esc, k.Expand, k.Rerun, k.Probe,
		k.LineDown, k.LineUp, k.PageDown, k.PageUp, k.Top, k.Bottom,
		k.NextDaemon, k.PrevDaemon, k.SelectDaemon, k.Switcher, k.Refusals, k.Doctor,
	}
}

// switcherBindings is the same list for the switcher overlay, where j/k move a
// cursor and enter/esc mean what §4.1's switcher table says. One key meaning
// different things in different views is the design; two arms in one view
// sharing a key is the bug the drift test catches.
func (k keyMap) switcherBindings() []binding {
	return []binding{
		k.Quit, k.Help, k.NextDaemon, k.PrevDaemon, k.SelectDaemon,
		k.SwitcherMove, k.SwitcherSelect, k.SwitcherClose,
		k.PageDown, k.PageUp, k.Top, k.Bottom,
	}
}

func joinDot(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, " · ")
}
