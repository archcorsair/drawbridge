package tui

import (
	"reflect"
	"strings"
	"testing"
)

// §4.2's one-source-of-truth rule, mechanised: the help overlay is rendered
// from the same keymap the Update loop dispatches on, so a binding that exists
// but is not shown — or is shown with a stale label — fails here rather than
// silently outliving the docs that cite it.
func TestKeymapIsFullyDocumented(t *testing.T) {
	k := defaultKeys()
	help := strings.Join(helpBody(k), "\n")
	v := reflect.ValueOf(k)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		b, ok := v.Field(i).Interface().(binding)
		if !ok {
			t.Fatalf("keyMap.%s is not a binding — the drift test cannot see it", name)
		}
		if len(b.keys) == 0 || b.label == "" || b.help == "" {
			t.Errorf("keyMap.%s is incomplete: %+v", name, b)
			continue
		}
		if !strings.Contains(help, b.label) {
			t.Errorf("keyMap.%s label %q does not appear in the help overlay", name, b.label)
		}
		if !strings.Contains(help, b.help) {
			t.Errorf("keyMap.%s help %q does not appear in the help overlay", name, b.help)
		}
	}
}

// Every binding the Update loop acts on, in either scope, is one of the
// keymap's own fields, so there is no key that behaves without being
// documented.
func TestDispatchedBindingsAreKeymapFields(t *testing.T) {
	k := defaultKeys()
	fields := map[string]bool{}
	v := reflect.ValueOf(k)
	for i := 0; i < v.NumField(); i++ {
		fields[bindingID(v.Field(i).Interface().(binding))] = true
	}
	for _, scope := range [][]binding{k.dispatchedBindings(), k.switcherBindings(), k.doctorBindings()} {
		for _, b := range scope {
			if !fields[bindingID(b)] {
				t.Errorf("the Update loop dispatches %v, which is not a keyMap field", b.keys)
			}
		}
	}
}

// One key may mean different things in different views (esc, enter, j/k), but
// two bindings dispatched in the same view sharing a key is a bug the first
// arm would hide forever.
func TestDispatchedKeysAreUnambiguous(t *testing.T) {
	k := defaultKeys()
	for name, scope := range map[string][]binding{
		"dashboard": k.dispatchedBindings(),
		"switcher":  k.switcherBindings(),
		"doctor":    k.doctorBindings(),
	} {
		seen := map[string]string{}
		for _, b := range scope {
			for _, key := range b.keys {
				if prev, ok := seen[key]; ok {
					t.Errorf("%s: key %q is dispatched by both %q and %q", name, key, prev, b.label)
				}
				seen[key] = b.label
			}
		}
	}
}

// The footer is the entire advertised surface: exactly five entries, in both
// spellings, and the compact one has to fit a terminal at the minimum width.
func TestShortHelpIsFiveEntries(t *testing.T) {
	for _, s := range []string{shortHelpFull, shortHelpCompact, shortHelpTiny} {
		if got := len(strings.Split(s, " · ")); got != 5 {
			t.Errorf("%q has %d entries, want 5", s, got)
		}
		for _, want := range []string{"tab", "? help", "q quit"} {
			if !strings.Contains(s, want) {
				t.Errorf("%q is missing %q", s, want)
			}
		}
	}
	for _, want := range []string{"r refusals", "d doctor"} {
		if !strings.Contains(shortHelpFull, want) || !strings.Contains(shortHelpCompact, want) {
			t.Errorf("a footer spelling with room for %q dropped it", want)
		}
	}
	// The narrowest window the dashboard renders at must still show all five.
	if visWidth(shortHelpTiny) > minWidth-2 {
		t.Errorf("the tiny footer is %d columns, too wide for a %d-column window", visWidth(shortHelpTiny), minWidth)
	}
	if got := shortHelp(visWidth(shortHelpFull), 0); got != shortHelpFull {
		t.Errorf("a window exactly wide enough got a shorter footer")
	}
	if got := shortHelp(visWidth(shortHelpFull)-1, 0); got != shortHelpCompact {
		t.Errorf("a window one column short did not fall back to the compact footer")
	}
	if got := shortHelp(visWidth(shortHelpCompact)-1, 0); got != shortHelpTiny {
		t.Errorf("a narrow window did not fall back to the tiny footer")
	}
}

// The unseen-refusals counter rides on the refusals entry: still five entries,
// in every spelling and at every width, and only the refusals one grows.
func TestShortHelpCounterKeepsFiveEntries(t *testing.T) {
	for _, unseen := range []int{0, 1, 42, 100, 4096} {
		for w := minWidth - 2; w <= 200; w++ {
			got := shortHelp(w, unseen)
			parts := strings.Split(got, " · ")
			if len(parts) != 5 {
				t.Fatalf("%d unseen at %d columns: %d entries: %q", unseen, w, len(parts), got)
			}
			if unseen > 0 && !strings.Contains(parts[1], "(") {
				t.Fatalf("%d unseen at %d columns: no counter on the refusals entry: %q", unseen, w, got)
			}
			if unseen == 0 && strings.Contains(got, "(") {
				t.Fatalf("a daemon with nothing unseen got a counter: %q", got)
			}
		}
	}
	// The badge is capped so a refusal storm cannot resize the footer line
	// (and with it the chosen spelling) once per second.
	if got := refusalBadge(1000); got != "(99+)" {
		t.Errorf("refusalBadge(1000) = %q", got)
	}
	if got := shortHelp(visWidth(shortHelpFull), 3); !strings.Contains(got, "r refusals (3)") {
		t.Errorf("the full footer spelled the counter as %q", got)
	}
	if got := shortHelp(0, 3); !strings.Contains(got, "r (3)") {
		t.Errorf("the tiny footer spelled the counter as %q", got)
	}
}

// §4.2's context-sensitive swap is the same contract: five entries in every
// spelling, the cost of `p` shown wherever there is room for it, and a tiny
// spelling that still fits the narrowest window the view renders at.
func TestDoctorShortHelpIsFiveEntries(t *testing.T) {
	for _, s := range []string{doctorHelpFull, doctorHelpCompact, doctorHelpTiny} {
		if got := len(strings.Split(s, " · ")); got != 5 {
			t.Errorf("%q has %d entries, want 5", s, got)
		}
		for _, want := range []string{"enter", "R", "p", "esc back", "? help"} {
			if !strings.Contains(s, want) {
				t.Errorf("%q is missing %q", s, want)
			}
		}
	}
	if !strings.Contains(doctorHelpFull, "~20s+") {
		t.Error("the doctor footer does not price the probe key (§3.3)")
	}
	if visWidth(doctorHelpTiny) > minWidth-2 {
		t.Errorf("the tiny doctor footer is %d columns, too wide for a %d-column window",
			visWidth(doctorHelpTiny), minWidth)
	}
	if got := doctorShortHelp(visWidth(doctorHelpFull), false); got != doctorHelpFull {
		t.Error("a window exactly wide enough got a shorter doctor footer")
	}
	if got := doctorShortHelp(visWidth(doctorHelpFull)-1, false); got != doctorHelpCompact {
		t.Error("a window one column short did not fall back to the compact doctor footer")
	}
	if got := doctorShortHelp(visWidth(doctorHelpCompact)-1, false); got != doctorHelpTiny {
		t.Error("a narrow window did not fall back to the tiny doctor footer")
	}
	// While a gather is in flight esc cancels, and the footer must not still be
	// promising to go back — at every width, five entries throughout.
	for w := minWidth; w <= 200; w++ {
		got := doctorShortHelp(w, true)
		if !strings.Contains(got, escCancel) {
			t.Fatalf("the running footer at %d columns says %q", w, got)
		}
		if len(strings.Split(got, " · ")) != 5 {
			t.Fatalf("the running footer at %d columns has %d entries: %q", w, len(strings.Split(got, " · ")), got)
		}
		if visWidth(got) > w {
			t.Fatalf("the running footer at %d columns is %d wide: %q", w, visWidth(got), got)
		}
	}
}

func bindingID(b binding) string { return b.label + "\x00" + strings.Join(b.keys, ",") }
