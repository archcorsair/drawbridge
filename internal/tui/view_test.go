package tui

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

var updateGoldens = flag.Bool("update", false, "rewrite the view goldens in testdata/")

// The color profile is forced to ASCII for the whole package: goldens are
// byte-stable across terminals and CI that way, and every status word survives
// the loss of color — which is the §3.6 accessibility rule tested by the same
// stroke.
func TestMain(m *testing.M) {
	flag.Parse()
	lipgloss.SetColorProfile(termenv.Ascii)
	os.Exit(m.Run())
}

var fixtureNow = time.Date(2026, 8, 1, 18, 31, 2, 0, time.UTC)

const (
	userSock = "/Users/x/Library/Application Support/drawbridge/run/introspect-colima-colima.sock"
	devSock  = "/Users/x/Library/Application Support/drawbridge/run/introspect-lima-dev.sock"
	// scratchSock is the §3.4 fixture's schema-skewed socket: its name is the
	// only thing that says which VM it belongs to.
	scratchSock = "/Users/x/Library/Application Support/drawbridge/run/introspect-lima-scratch.sock"
	rootSock    = introspect.RootSocketPath
)

// healthySnap is §3.1's mockup as data: a bound/skipped/bind-failed mix, a
// skip list, both sessions up, and a pool with parked conns.
func healthySnap() *introspect.Snapshot {
	return &introspect.Snapshot{
		Path:   userSock,
		Usable: true,
		State: introspect.State{
			Schema:     introspect.Schema,
			Version:    "v0.1.0",
			PID:        71234,
			EUID:       501,
			StartedAt:  fixtureNow.Add(-2*time.Hour - 14*time.Minute),
			VM:         introspect.VM{Ref: "colima:colima", Provider: "colima", Instance: "colima"},
			MirrorIP:   "127.0.0.1",
			Resolution: introspect.Resolution{Endpoint: "tcp://192.168.64.5:4777", Source: "vznat-direct", ResolvedAt: fixtureNow.Add(-2*time.Hour - 14*time.Minute)},
			Auth: introspect.Auth{
				Mode:        introspect.AuthModeStaticHMACv1,
				SecretPath:  "/Users/x/Library/Application Support/drawbridge/transport-secret-colima-colima",
				SecretState: introspect.SecretOK,
			},
			Mirror: introspect.Mirror{
				SessionUp:   true,
				LastEventAt: fixtureNow.Add(-12 * time.Second),
				Entries: []introspect.MirrorEntry{
					{Proto: "tcp", Port: 8080, State: introspect.EntryBound, Since: fixtureNow.Add(-2 * time.Minute)},
					{Proto: "tcp", Port: 3000, State: introspect.EntryBound, Since: fixtureNow.Add(-2 * time.Minute)},
					{Proto: "udp", Port: 5353, State: introspect.EntryBound, Since: fixtureNow.Add(-1 * time.Minute)},
					{Proto: "tcp", Port: 22, State: introspect.EntrySkipped, Since: fixtureNow.Add(-2 * time.Hour)},
					{Proto: "tcp", Port: 5000, State: introspect.EntryBindFailed, Since: fixtureNow.Add(-40 * time.Second)},
				},
				Skip: []uint16{22},
			},
			Sync: introspect.Sync{
				SessionUp:  true,
				Advertised: []introspect.Advertised{{Proto: "tcp", Port: 5432}, {Proto: "tcp", Port: 6379}},
				UDPPorts:   []uint16{5353},
				PoolParked: 4,
			},
		},
	}
}

// rootSnap is a second answering daemon on the root socket — the flavor the
// box title names, and the path Discover always sorts first.
func rootSnap() *introspect.Snapshot {
	s := devSnap()
	s.Path = rootSock
	s.State.EUID = 0
	return s
}

// devSnap is a second *user* daemon, so the two-daemon goldens keep the
// mockup's colima instance selected as `daemon 1/2`.
func devSnap() *introspect.Snapshot {
	s := healthySnap()
	s.Path = devSock
	s.State.PID = 4242
	s.State.VM = introspect.VM{Ref: "lima:dev", Provider: "lima", Instance: "dev"}
	s.State.Mirror.Entries = s.State.Mirror.Entries[:2]
	return s
}

// fightingSnap is a root daemon serving the same VM healthySnap does: D8's
// pathology as data, which needs the canonical pair to match across two
// flavors, not merely two daemons to be running.
func fightingSnap() *introspect.Snapshot {
	s := healthySnap()
	s.Path = rootSock
	s.State.PID = 4242
	s.State.EUID = 0
	s.State.Mirror.Entries = s.State.Mirror.Entries[:2]
	return s
}

// skewedSnap is a daemon speaking a schema this build does not know: the two
// frozen fields and nothing else (D4 of the introspection contract).
func skewedSnap(path string) *introspect.Snapshot {
	return &introspect.Snapshot{Path: path, State: introspect.State{Schema: 2, Version: "v0.2.0"}}
}

// unreadableProblem is what FetchAll hands back for a socket that answered
// with something that is not a snapshot — an error whose string carries the
// path, which is all the TUI has to render.
func unreadableProblem() error {
	return fmt.Errorf("%w: %s: unexpected EOF", introspect.ErrMalformed, "/tmp/introspect-bad.sock")
}

// refusalRing is §3.2's mockup as data: an auth cause, a refused reverse dial
// and a skip, in ring order.
func refusalRing() []introspect.Refusal {
	at := func(h, m, s int) time.Time { return time.Date(2026, 8, 1, h, m, s, 0, time.UTC) }
	return []introspect.Refusal{
		{At: at(18, 22, 10), ID: "auth-mismatch",
			Line: "agent at tcp://192.168.64.5:4777 closed during transport authentication (wrong secret, or the agent has none)"},
		{At: at(18, 22, 41), ID: introspect.IDReverseDialRefused,
			Line: "'D' activation named 127.0.0.1:9099 — not advertised; refused"},
		{At: at(18, 23, 5), ID: introspect.IDMirrorSkip,
			Line: "guest tcp :22 not mirrored (skip list)"},
	}
}

// testModel is a model with every construction-time side effect already made
// deterministic: no HOME lookup, no clock, no linked version.
func testModel(width, height int, snaps ...*introspect.Snapshot) Model {
	m := Model{
		keys:        defaultKeys(),
		version:     "v0.1.0",
		userRunDir:  "~/Library/Application Support/drawbridge/run/",
		missedTicks: map[string]int{},
		refusals:    map[string][]introspect.Refusal{},
		width:       width,
		height:      height,
		now:         fixtureNow,
		fetchedAt:   fixtureNow.Add(-300 * time.Millisecond),
		snaps:       snaps,
	}
	sortSnaps(m.snaps) // the merge step's job in the real loop
	return m.resolveSelection()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".txt")
	if *updateGoldens {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/tui -update` to create it)", err)
	}
	if string(want) != got {
		t.Errorf("%s mismatch\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

// Every view a T1 model can reach, at the sizes and the exact breakpoint
// widths §3.1 fixes.
func TestViewGoldens(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Model
	}{
		{"healthy_120x40", testModel(120, 40, healthySnap(), devSnap())},
		{"healthy_80x24", testModel(80, 24, healthySnap(), devSnap())},
		// The wide/compact boundary: ≥100 keeps the box and the sync table.
		{"breakpoint_wide_100x24", testModel(100, 24, healthySnap())},
		{"breakpoint_compact_99x24", testModel(99, 24, healthySnap())},
		// The detail boundary: ≥70 keeps SINCE and the auth path.
		{"breakpoint_detail_70x24", testModel(70, 24, healthySnap())},
		{"breakpoint_nodetail_69x24", testModel(69, 24, healthySnap())},
		{"nodaemon_120x40", testModel(120, 40)},
		{"nodaemon_80x24", testModel(80, 24)},
		{"toosmall_43x40", testModel(43, 40, healthySnap())},
		{"toosmall_60x11", testModel(60, 11, healthySnap())},
		{"help_120x40", helpModel(testModel(120, 40, healthySnap(), devSnap()))},
		{"help_80x24", helpModel(testModel(80, 24, healthySnap()))},
		{"nomirrors_120x40", noMirrorsModel(120, 40)},
		{"nomirrors_sessiondown_80x24", sessionDownModel(80, 24)},
		{"stopped_120x40", stoppedModel(120, 40)},
		{"stopped_80x24", stoppedModel(80, 24)},
		{"skew_120x40", skewModel(120, 40)},
		// Height pressure: the mirror table is the elastic region and its
		// overflow ends in a `… +N more` tail.
		{"overflow_120x16", testModel(120, 16, manyEntries())},
		{"overflow_scrolled_120x16", scrolled(testModel(120, 16, manyEntries()), 3)},
		{"skew_chip_120x40", skewChipModel(120, 40)},
		{"note_120x40", noteModel(120, 40)},
		// T2: the refusals pane, the switcher overlay, and the D8 banner in
		// both the view it warns about and the overlay that makes it visible.
		{"refusals_120x40", refusalsModel(120, 40)},
		{"refusals_80x24", refusalsModel(80, 24)},
		// A log longer than the pane follows the newest line; scrolling up
		// disengages the follow and shows the older entries.
		{"refusals_follow_80x24", manyRefusalsModel(80, 24)},
		{"refusals_scrolled_80x24", press(manyRefusalsModel(80, 24), "k", "k")},
		{"refusals_empty_120x40", emptyRefusalsModel(120, 40)},
		{"refusals_empty_80x24", emptyRefusalsModel(80, 24)},
		{"switcher_120x40", switcherModel(120, 40)},
		{"switcher_80x24", switcherModel(80, 24)},
		{"fighting_120x40", fightingModel(120, 40)},
		{"fighting_80x24", fightingModel(80, 24)},
		{"fighting_switcher_120x40", openSwitcher(fightingModel(120, 40))},
		{"fighting_switcher_80x24", openSwitcher(fightingModel(80, 24))},
		{"skew_80x24", skewModel(80, 24)},
		// The ephemeral fold: tcp has enough dynamic-range advertisements to
		// bury its two real ones and folds; udp has two and does not. `x`
		// unfolds both without moving the header's count.
		{"sync_folded_120x40", testModel(120, 40, ephemeralSnap())},
		{"sync_expanded_120x40", press(testModel(120, 40, ephemeralSnap()), "x")},
		// The footer's unseen counter, with the pane still closed.
		{"counter_120x40", counterModel(120, 40)},
	} {
		t.Run(tc.name, func(t *testing.T) { golden(t, tc.name, tc.m.View()) })
	}
}

func helpModel(m Model) Model {
	m.overlay = overlayHelp
	return m
}

func scrolled(m Model, n int) Model {
	m.scroll = m.scroll.down(n, m.scrollTotal(), m.scrollVisible())
	return m
}

func noMirrorsModel(w, h int) Model {
	s := healthySnap()
	s.State.Mirror.Entries = nil
	s.State.Mirror.Skip = nil
	return testModel(w, h, s)
}

func sessionDownModel(w, h int) Model {
	s := healthySnap()
	s.State.Mirror.Entries = nil
	s.State.Mirror.Skip = nil
	s.State.Mirror.SessionUp = false
	s.State.Mirror.LastEventAt = time.Time{}
	return testModel(w, h, s)
}

func stoppedModel(w, h int) Model {
	m := testModel(w, h, healthySnap(), devSnap())
	m.missedTicks[userSock] = 7
	return m
}

func skewModel(w, h int) Model {
	m := testModel(w, h, healthySnap())
	m.skewed = []*introspect.Snapshot{skewedSnap(rootSock)}
	m.problems = []error{unreadableProblem()}
	return m
}

func refusalsModel(w, h int) Model {
	m := testModel(w, h, healthySnap(), devSnap())
	m.pane = paneRefusals
	m.refusals = map[string][]introspect.Refusal{userSock: refusalRing()}
	m.scroll = m.freshScroll()
	// An open pane has shown what it holds: the footer's counter cannot be
	// standing at 3 in a state the Update loop can actually reach.
	return m.markRefusalsSeen()
}

// manyRefusalsModel overflows the pane, which is the state the follow latch
// exists for.
func manyRefusalsModel(w, h int) Model {
	m := refusalsModel(w, h)
	log := m.refusals[userSock]
	for i := 0; i < 12; i++ {
		log = append(log, introspect.Refusal{
			At:   fixtureNow.Add(-time.Duration(12-i) * time.Second),
			ID:   introspect.IDMirrorSkip,
			Line: fmt.Sprintf("guest tcp :%d not mirrored (skip list)", 9000+i),
		})
	}
	m.refusals[userSock] = log
	return m.markRefusalsSeen()
}

// counterModel has a log the pane has never shown: the state the footer's
// counter exists for.
func counterModel(w, h int) Model {
	m := testModel(w, h, healthySnap(), devSnap())
	m.refusals = map[string][]introspect.Refusal{userSock: refusalRing()}
	return m
}

// ephemeralSnap advertises a dynamic-range run on tcp (enough to fold) and two
// on udp (not enough), so one fixture pins both sides of the threshold.
func ephemeralSnap() *introspect.Snapshot {
	s := healthySnap()
	for _, p := range []uint16{49410, 51002, 52233, 53817, 55110, 56206} {
		s.State.Sync.Advertised = append(s.State.Sync.Advertised, introspect.Advertised{Proto: "tcp", Port: p})
	}
	s.State.Sync.UDPPorts = append(s.State.Sync.UDPPorts, 49999, 50001)
	return s
}

func emptyRefusalsModel(w, h int) Model {
	m := testModel(w, h, healthySnap())
	m.pane = paneRefusals
	m.scroll = m.freshScroll()
	return m
}

// switcherModel is §3.4's fixture: an answering user daemon, an answering root
// daemon, a schema-skewed socket and an unreadable one.
func switcherModel(w, h int) Model {
	m := testModel(w, h, healthySnap(), rootSnap())
	m.skewed = []*introspect.Snapshot{skewedSnap(scratchSock)}
	m.problems = []error{unreadableProblem()}
	return openSwitcher(m)
}

func openSwitcher(m Model) Model {
	m.overlay = overlaySwitcher
	m.cursor = m.rowIndexOf(m.selected)
	return m
}

func fightingModel(w, h int) Model {
	return testModel(w, h, healthySnap(), fightingSnap())
}

func skewChipModel(w, h int) Model {
	s := healthySnap()
	s.State.Version = "v0.0.9"
	return testModel(w, h, s)
}

func noteModel(w, h int) Model {
	s := healthySnap()
	s.State.Resolution.Source = "ssh-forwarder"
	s.State.Resolution.Note = "vzNAT dial was refused (Local Network permission); fell back to the SSH forwarder"
	return testModel(w, h, s)
}

func manyEntries() *introspect.Snapshot {
	s := healthySnap()
	s.State.Mirror.Entries = nil
	s.State.Mirror.Skip = nil
	for i := 0; i < 20; i++ {
		s.State.Mirror.Entries = append(s.State.Mirror.Entries, introspect.MirrorEntry{
			Proto: "tcp", Port: uint16(9000 + i), State: introspect.EntryBound,
			Since: fixtureNow.Add(-time.Duration(i) * time.Minute),
		})
	}
	return s
}

// No rendered line may exceed the terminal's width, at any size, in any state:
// a line that overruns wraps and shears the layout below it.
func TestNoLineOverrunsWidth(t *testing.T) {
	models := map[string]func(w, h int) Model{
		"healthy":           func(w, h int) Model { return testModel(w, h, healthySnap(), devSnap()) },
		"nodaemon":          func(w, h int) Model { return testModel(w, h) },
		"stopped":           stoppedModel,
		"skew":              skewModel,
		"note":              noteModel,
		"overflow":          func(w, h int) Model { return testModel(w, h, manyEntries()) },
		"help":              func(w, h int) Model { return helpModel(testModel(w, h, healthySnap())) },
		"refusals":          manyRefusalsModel,
		"refusals_empty":    emptyRefusalsModel,
		"switcher":          switcherModel,
		"fighting":          fightingModel,
		"fighting_over":     func(w, h int) Model { return openSwitcher(fightingModel(w, h)) },
		"switcher_nodaemon": func(w, h int) Model { return openSwitcher(testModel(w, h)) },
		"sync_folded":       func(w, h int) Model { return testModel(w, h, ephemeralSnap()) },
		"sync_expanded":     func(w, h int) Model { return press(testModel(w, h, ephemeralSnap()), "x") },
		"counter":           counterModel,
	}
	for name, build := range models {
		for w := 20; w <= 200; w++ {
			for _, h := range []int{5, 12, 24, 40} {
				m := build(w, h)
				lines := strings.Split(m.View(), "\n")
				if len(lines) > h {
					t.Fatalf("%s at %dx%d: %d lines rendered", name, w, h, len(lines))
				}
				for i, l := range lines {
					if got := visWidth(l); got > w {
						t.Fatalf("%s at %dx%d: line %d is %d columns: %q", name, w, h, i, got, l)
					}
				}
			}
		}
	}
}

// §3.1's problems-first order: bind-failed, then anything unrecognised, then
// bound, then skipped — by port within proto inside each class.
func TestMirrorSortIsProblemsFirst(t *testing.T) {
	in := []introspect.MirrorEntry{
		{Proto: "tcp", Port: 8080, State: introspect.EntryBound},
		{Proto: "udp", Port: 5353, State: introspect.EntrySkipped},
		{Proto: "tcp", Port: 22, State: introspect.EntrySkipped},
		{Proto: "udp", Port: 9000, State: introspect.EntryBindFailed},
		{Proto: "tcp", Port: 3000, State: introspect.EntryBound},
		{Proto: "tcp", Port: 5000, State: introspect.EntryBindFailed},
		{Proto: "tcp", Port: 7000, State: "pending"},
	}
	want := []string{
		"tcp/5000/bind-failed", "udp/9000/bind-failed",
		"tcp/7000/pending",
		"tcp/3000/bound", "tcp/8080/bound",
		"tcp/22/skipped", "udp/5353/skipped",
	}
	order := func(in []introspect.MirrorEntry) []string {
		var out []string
		for _, e := range sortedEntries(in) {
			out = append(out, fmt.Sprintf("%s/%d/%s", e.Proto, e.Port, e.State))
		}
		return out
	}
	if got := order(in); !slices.Equal(got, want) {
		t.Fatalf("order = %v\nwant  %v", got, want)
	}
	// The order is total over the row's own fields, so the daemon's arrival
	// order cannot move a row between refreshes: only a state change can.
	shuffled := append([]introspect.MirrorEntry(nil), in...)
	slices.Reverse(shuffled)
	if got := order(shuffled); !slices.Equal(got, want) {
		t.Fatalf("a reordered fetch rendered %v", got)
	}
	if !slices.Equal(order(in), order(in)) {
		t.Fatal("two sorts of one fetch differ")
	}
}

// The wide layout is one grid: a rule down the gap between the two tables, for
// the full height of the taller one, and the skip list docked in the mirror
// header rather than floating under its rows.
func TestWideGridRuleAndDockedSkip(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	lines := strings.Split(m.View(), "\n")
	head := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "MIRROR —") {
			head = i
		}
	}
	if head < 0 {
		t.Fatalf("no mirror header:\n%s", m.View())
	}
	if want := "MIRROR — guest listeners on Mac localhost (5) · skip: 22"; !strings.Contains(lines[head], want) {
		t.Errorf("the header does not dock the skip list: %q", lines[head])
	}
	if strings.Contains(m.View(), "skip list:") {
		t.Error("the floating skip line survived")
	}
	// Every row of the grid — header rows included — carries the rule in the
	// same column; the last one is the taller region's last line.
	rule := 0
	for _, l := range lines[head:] {
		r := []rune(l)
		if len(r) <= syncCol-sepW || r[syncCol-sepW] != '│' {
			break
		}
		rule++
	}
	if want := 7; rule != want { // 2 header rows + 5 mirror entries
		t.Errorf("the rule runs %d rows, want %d:\n%s", rule, want, m.View())
	}
	// It is a wide-layout element: below the breakpoint there is no second
	// table for it to divide.
	if strings.Contains(testModel(99, 40, healthySnap()).View(), "│") {
		t.Error("the compact layout drew a table rule")
	}
}

// Errors reaching the notice line must never be able to smuggle a newline into
// the frame.
func TestNoticeLineIsSingleLine(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m.problems = []error{errors.New("first\nsecond\nthird")}
	for _, l := range m.noticeLines(m.layout()) {
		if strings.Contains(l, "\n") {
			t.Fatalf("notice line carries a newline: %q", l)
		}
	}
}
