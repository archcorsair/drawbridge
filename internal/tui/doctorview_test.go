package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/archcorsair/drawbridge/internal/doctor"
	"github.com/archcorsair/drawbridge/internal/introspect"
)

// doctorFixture is §3.3's complete screen as data: doctor's own catalog order,
// every status represented, and one warn finding carrying both evidence and a
// remedy — the finding the expansion golden opens.
func doctorFixture() doctor.Report {
	return doctor.Report{
		CLIVersion: "v0.1.0",
		RanAt:      fixtureNow.Add(-20 * time.Second),
		VM:         "colima:colima",
		Findings: []doctor.Finding{
			{ID: doctor.IDProviders, Title: "VM providers", Status: doctor.StatusOK,
				Evidence: []string{"colima v0.9.2", "1 vz instance running: colima"}},
			{ID: doctor.IDGuestPrereqs, Title: "guest prerequisites", Status: doctor.StatusOK,
				Evidence: []string{"kernel 6.8.0-45-generic, BTF present, cgroup v2"}},
			{ID: doctor.IDAgent, Title: "guest agent", Status: doctor.StatusOK,
				Evidence: []string{"drawbridge-agent v0.1.0 active, listening 127.0.0.1:4777 and 192.168.64.5:4777"}},
			{ID: doctor.IDResolution, Title: "endpoint resolution", Status: doctor.StatusWarn,
				Evidence: []string{
					"endpoint tcp://127.0.0.1:4777 (ssh-forwarder)",
					"vzNAT dial was refused (Local Network permission); fell back to the SSH forwarder",
				},
				Remedy: "grant Local Network permission to the app running drawbridge, then restart the daemon"},
			{ID: doctor.IDVZNATRoute, Title: "vzNAT route", Status: doctor.StatusOK,
				Evidence: []string{"192.168.64.0/24 via bridge100"}},
			{ID: doctor.IDLocalNetwork, Title: "Local Network permission", Status: doctor.StatusFail,
				Evidence: []string{"user probe to 192.168.64.5:4777 failed: connect: no route to host", "root evidence unknown"},
				Remedy:   "System Settings → Privacy & Security → Local Network → enable the terminal app"},
			{ID: doctor.IDNEFilter, Title: "network content filters", Status: doctor.StatusOK},
			{ID: doctor.IDHalfClose, Title: "half-close delivery", Status: doctor.StatusSkip,
				Remedy: "re-run with -probe to open one read-only session and measure it"},
			{ID: doctor.IDDaemon, Title: "Mac daemon", Status: doctor.StatusOK,
				Evidence: []string{"user daemon pid 71234, v0.1.0, 5 mirror entries"}},
			{ID: doctor.IDCoexistence, Title: "provider forwarder coexistence", Status: doctor.StatusOK},
			{ID: doctor.IDSkipVisible, Title: "default skip list", Status: doctor.StatusInfo,
				Evidence: []string{"tcp 22 is never mirrored (the guest's own sshd is Lima's)"}},
			{ID: doctor.IDAuth, Title: "transport authentication", Status: doctor.StatusOK,
				Evidence: []string{"static-hmac-v1, secret 3f9a1c2e (both sides)"}},
		},
	}
}

// doneModel is the doctor view showing a finished run, with the ages §3.3
// wants distinguishable: a 14 s gather that finished 20 s ago.
func doneModel(w, h int) Model {
	m := testModel(w, h, healthySnap())
	m.view = viewDoctor
	m.doctor = doctorState{
		phase:    doctorDone,
		gen:      1,
		report:   doctorFixture(),
		ranAt:    fixtureNow.Add(-20 * time.Second),
		elapsed:  14 * time.Second,
		expanded: map[string]bool{},
	}
	return m
}

func expandedModel(w, h int) Model {
	m := doneModel(w, h)
	m.doctor.cursor = 3 // the warn finding
	m.doctor.expanded = map[string]bool{doctor.IDResolution: true}
	return m
}

func runningModel(w, h int) Model {
	m := testModel(w, h, healthySnap())
	m.view = viewDoctor
	// A fixed start and a fixed frame: the spinner and the elapsed counter are
	// the two moving parts, and a golden pins both.
	m.doctor = doctorState{phase: doctorRunning, gen: 1, since: fixtureNow.Add(-7 * time.Second), frame: 3}
	return m
}

func probingModel(w, h int) Model {
	m := runningModel(w, h)
	m.doctor.probe = true
	return m
}

func failedModel(w, h int) Model {
	m := testModel(w, h, healthySnap())
	m.view = viewDoctor
	m.doctor = doctorState{
		phase:   doctorFailed,
		gen:     1,
		err:     errors.New("no running vz instance: lima reported 0 and colima reported 0 — start one, or name it with -vm"),
		ranAt:   fixtureNow.Add(-3 * time.Second),
		elapsed: 2 * time.Second,
	}
	return m
}

// persistedModel is the same report re-entered minutes later: §3.3's rule that
// results survive a view switch, with the age that keeps them honest.
func persistedModel(w, h int) Model {
	m := doneModel(w, h)
	m.doctor.ranAt = fixtureNow.Add(-4 * time.Minute)
	return m
}

func TestDoctorViewGoldens(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Model
	}{
		{"doctor_running_120x40", runningModel(120, 40)},
		{"doctor_running_80x24", runningModel(80, 24)},
		{"doctor_probing_120x40", probingModel(120, 40)},
		{"doctor_done_120x40", doneModel(120, 40)},
		{"doctor_done_80x24", doneModel(80, 24)},
		{"doctor_expanded_120x40", expandedModel(120, 40)},
		{"doctor_expanded_80x24", expandedModel(80, 24)},
		{"doctor_failed_120x40", failedModel(120, 40)},
		{"doctor_failed_80x24", failedModel(80, 24)},
		{"doctor_persisted_120x40", persistedModel(120, 40)},
		// The list is the elastic region: a short window scrolls to the cursor
		// rather than hiding the tail of the catalog.
		{"doctor_scrolled_120x14", press(doneModel(120, 14), "G")},
		// D8 renders above every view, the doctor view included.
		{"doctor_fighting_120x40", doctorFightingModel(120, 40)},
	} {
		t.Run(tc.name, func(t *testing.T) { golden(t, tc.name, tc.m.View()) })
	}
}

func doctorFightingModel(w, h int) Model {
	m := doneModel(w, h)
	m.snaps = append(m.snaps, fightingSnap())
	sortSnaps(m.snaps)
	return m
}

// §3.3: entering runs a plain gather immediately, but only once — a run is
// seconds, not a tick, and re-entering shows the last report with its age.
func TestDoctorAutoRunsOnFirstEntryOnly(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m, cmd := send(m, key("d"))
	if m.view != viewDoctor {
		t.Fatal("d did not open the doctor view")
	}
	if m.doctor.phase != doctorRunning {
		t.Fatalf("d left the view in phase %v, want running", m.doctor.phase)
	}
	if cmd == nil {
		t.Fatal("d started no gather")
	}
	if m.doctor.probe {
		t.Fatal("the first entry ran the priced probe")
	}
	if m.doctor.cancel == nil {
		t.Fatal("a running gather has no cancel — esc could not stop it")
	}

	gen := m.doctor.gen
	m, _ = send(m, doctorDoneMsg{gen: gen, report: doctorFixture(), ranAt: fixtureNow, elapsed: 14 * time.Second})
	if m.doctor.phase != doctorDone {
		t.Fatalf("the report landed in phase %v", m.doctor.phase)
	}
	if m.doctor.cancel != nil {
		t.Fatal("a finished run kept its cancel")
	}

	// Out to the dashboard and back: the last report is still there, and no
	// second gather was started.
	m = press(m, "esc")
	if m.view != viewDashboard {
		t.Fatal("esc did not return to the dashboard")
	}
	m, cmd = send(m, key("d"))
	if cmd != nil {
		t.Fatal("re-entering the doctor view started another gather")
	}
	if m.doctor.gen != gen || m.doctor.phase != doctorDone {
		t.Fatalf("re-entry disturbed the run: gen %d, phase %v", m.doctor.gen, m.doctor.phase)
	}
	if !strings.Contains(m.View(), "ran ") {
		t.Fatal("the persisted report does not show when it ran")
	}
}

// §4.1's doctor esc: cancel a running gather, else return to the dashboard.
// Two presses, two different meanings, and the first must not leave the view.
func TestDoctorEscIsATwoStep(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m = press(m, "d")
	gen := m.doctor.gen

	m = press(m, "esc")
	if m.view != viewDoctor {
		t.Fatal("the first esc left the doctor view instead of canceling")
	}
	if m.doctor.phase == doctorRunning {
		t.Fatal("the first esc did not cancel the run")
	}
	if m.doctor.gen == gen {
		t.Fatal("canceling did not bump the generation")
	}
	if m.doctor.cancel != nil {
		t.Fatal("a canceled run kept its cancel func")
	}

	m = press(m, "esc")
	if m.view != viewDashboard {
		t.Fatal("the second esc did not return to the dashboard")
	}
}

// D6: a canceled goroutine may take a probe timeout to unwind, and whatever it
// finally produces lands on nothing.
func TestDoctorStaleGenerationIsDropped(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m = press(m, "d")
	stale := m.doctor.gen
	m = press(m, "esc") // cancel: the generation moves on

	m, _ = send(m, doctorDoneMsg{gen: stale, report: doctorFixture(), ranAt: fixtureNow, elapsed: time.Second})
	if m.doctor.phase == doctorDone || len(m.doctor.report.Findings) != 0 {
		t.Fatal("a canceled run's report landed anyway")
	}
	m, _ = send(m, doctorFailedMsg{gen: stale, err: errors.New("boom"), ranAt: fixtureNow})
	if m.doctor.phase == doctorFailed || m.doctor.err != nil {
		t.Fatal("a canceled run's error landed anyway")
	}

	// The same guard covers a message that arrives after the phase moved on
	// without a cancel — nothing but a running model may be completed.
	done := doneModel(120, 40)
	got, _ := send(done, doctorDoneMsg{gen: done.doctor.gen, report: doctor.Report{}, ranAt: fixtureNow})
	if len(got.doctor.report.Findings) == 0 {
		t.Fatal("a completed run was overwritten by a second landing")
	}
}

// `R` re-runs plain; `p` re-runs with the half-close probe. Both bump the
// generation, so a slow predecessor cannot land on top of the new run.
func TestDoctorRerunAndProbe(t *testing.T) {
	m := doneModel(120, 40)
	gen := m.doctor.gen

	m, cmd := send(m, key("R"))
	if cmd == nil || m.doctor.phase != doctorRunning {
		t.Fatal("R did not start a gather")
	}
	if m.doctor.gen <= gen {
		t.Fatal("R did not bump the generation")
	}
	if m.doctor.probe {
		t.Fatal("R ran the priced probe")
	}
	// A canceled re-run falls back to the report it replaced rather than
	// throwing the previous diagnosis away.
	if got := press(m, "esc"); got.doctor.phase != doctorDone || len(got.doctor.report.Findings) == 0 {
		t.Fatalf("canceling a re-run lost the previous report: phase %v", got.doctor.phase)
	}

	rerun := m.doctor.gen
	m, cmd = send(m, key("p"))
	if cmd == nil || !m.doctor.probe {
		t.Fatal("p did not start a probing gather")
	}
	if m.doctor.gen <= rerun {
		t.Fatal("p did not bump the generation")
	}
	if !m.doctorOptions(true).Probe {
		t.Fatal("p's options do not carry Probe")
	}
	if m.doctorOptions(false).Probe {
		t.Fatal("a plain run's options carry Probe")
	}
	if !strings.Contains(m.View(), "probe") {
		t.Fatal("the running screen does not say it is the priced run")
	}
}

// §3.3's seeding rule, and §4.3's pass-through: the flags reach Gather intact
// and the timeout floor stays doctor's own.
func TestDoctorOptionsSeeding(t *testing.T) {
	m := testModel(120, 40, healthySnap(), rootSnap())
	if got := m.doctorOptions(false).VM; got != "lima:dev" {
		t.Fatalf("with no -vm the selected daemon's ref seeds the run, got %q", got)
	}
	if got := press(m, "tab").doctorOptions(false).VM; got != "colima:colima" {
		t.Fatalf("switching daemons did not move the doctor target: %q", got)
	}

	m.opts = Options{VM: "lima:other", HWAddr: "52:55:55:12:34:56", Timeout: 90 * time.Second}
	o := m.doctorOptions(false)
	if o.VM != "lima:other" {
		t.Fatalf("-vm did not win over the selected daemon: %q", o.VM)
	}
	if o.HWAddr != "52:55:55:12:34:56" || o.Timeout != 90*time.Second {
		t.Fatalf("-vm-mac/-timeout did not reach the run: %+v", o)
	}
	if o.CLIVersion != "v0.1.0" {
		t.Fatalf("CLIVersion did not reach the run: %q", o.CLIVersion)
	}

	// No daemon and no flag: Options.VM stays empty and doctor does its own
	// single-running-instance selection, exactly as the CLI verb does.
	if got := testModel(120, 40).doctorOptions(false).VM; got != "" {
		t.Fatalf("with nothing answering the run was seeded with %q", got)
	}
}

// j/k move the cursor and enter expands in place; the expansion is keyed by
// the finding's stable ID, so a re-run of the same check keeps it open.
func TestDoctorCursorAndExpansion(t *testing.T) {
	m := doneModel(120, 40)
	if got := press(m, "j", "j", "j").doctor.cursorIndex(); got != 3 {
		t.Fatalf("j three times left the cursor at %d", got)
	}
	if got := press(m, "k").doctor.cursorIndex(); got != 0 {
		t.Fatalf("k at the top left the cursor at %d", got)
	}
	last := len(m.doctor.report.Findings) - 1
	if got := press(m, "G").doctor.cursorIndex(); got != last {
		t.Fatalf("G left the cursor at %d, want %d", got, last)
	}
	if got := press(m, "G", "g").doctor.cursorIndex(); got != 0 {
		t.Fatalf("g left the cursor at %d", got)
	}

	m = press(m, "j", "j", "j", "enter")
	if !m.doctor.expanded[doctor.IDResolution] {
		t.Fatal("enter did not expand the selected finding")
	}
	v := m.View()
	for _, want := range []string{
		"fell back to the SSH forwarder",
		"→ grant Local Network permission",
	} {
		if !strings.Contains(v, want) {
			t.Fatalf("the expansion is missing %q:\n%s", want, v)
		}
	}
	if got := press(m, "enter"); got.doctor.expanded[doctor.IDResolution] {
		t.Fatal("enter did not collapse the finding again")
	}
	// The report survives a re-run's landing with the expansion intact.
	m, _ = send(m, key("R"))
	m, _ = send(m, doctorDoneMsg{gen: m.doctor.gen, report: doctorFixture(), ranAt: fixtureNow, elapsed: time.Second})
	if !m.doctor.expanded[doctor.IDResolution] {
		t.Fatal("a re-run lost the open finding")
	}
}

// Every finding's status word survives the loss of color (§3.6) and the
// summary sentence is doctor's own.
func TestDoctorRendersStatusesAndSummary(t *testing.T) {
	v := doneModel(120, 40).View()
	for _, want := range []string{"[ok]", "[warn]", "[fail]", "[skip]", "[info]", "colima:colima"} {
		if !strings.Contains(v, want) {
			t.Fatalf("the complete screen is missing %q:\n%s", want, v)
		}
	}
	if want := doctorFixture().Summary(); !strings.Contains(v, want) {
		t.Fatalf("the summary line %q is missing:\n%s", want, v)
	}
}

// Doctor's exit-2 class: one card, the error verbatim, and the key that
// retries it.
func TestDoctorGatherErrorCard(t *testing.T) {
	m := failedModel(120, 40)
	v := m.View()
	for _, want := range []string{"doctor could not gather", "no running vz instance", "press R to retry"} {
		if !strings.Contains(v, want) {
			t.Fatalf("the gather-error card is missing %q:\n%s", want, v)
		}
	}
	got, cmd := send(m, key("R"))
	if cmd == nil || got.doctor.phase != doctorRunning {
		t.Fatal("R did not retry the gather")
	}
	// A multi-line error cannot shear the frame.
	m.doctor.err = errors.New("first\nsecond")
	for _, l := range strings.Split(m.View(), "\n") {
		if strings.Contains(l, "second") && strings.Contains(l, "first") {
			continue
		}
	}
	if n := len(strings.Split(m.View(), "\n")); n != 40 {
		t.Fatalf("the failed view rendered %d lines at height 40", n)
	}
}

// §4.2: the footer swaps to the doctor view's own five and swaps back.
func TestDoctorFooterSwap(t *testing.T) {
	m := doneModel(120, 40)
	if !strings.Contains(m.View(), doctorHelpFull) {
		t.Fatalf("the doctor footer is not the doctor five:\n%s", m.View())
	}
	if strings.Contains(m.View(), shortHelpFull) {
		t.Fatal("the doctor view still advertises the dashboard footer")
	}
	if got := press(m, "esc").View(); !strings.Contains(got, shortHelpFull) {
		t.Fatal("leaving the doctor view did not restore the dashboard footer")
	}
}

// D6: the snapshot loop keeps running underneath, so returning to the
// dashboard is instant and current.
func TestDoctorTickKeepsFetching(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m.fetching = false
	m = press(m, "d")
	if !m.wantFetch() {
		t.Fatal("entering the doctor view closed the fetch guard")
	}
	m, cmd := send(m, tickMsg(fixtureNow.Add(time.Second)))
	if cmd == nil || !m.fetching {
		t.Fatal("a tick inside the doctor view did not start a fetch")
	}
	// And the snapshot it produces still lands.
	m, _ = send(m, snapshotsMsg{snaps: []*introspect.Snapshot{healthySnap(), rootSnap()}, at: fixtureNow})
	if len(m.snaps) != 2 || m.view != viewDoctor {
		t.Fatalf("a fetch under the doctor view landed wrong: %d snaps, view %v", len(m.snaps), m.view)
	}
}

// The spinner's own tick runs only while its run does: a canceled generation's
// chain ends rather than ticking forever.
func TestDoctorSpinnerTick(t *testing.T) {
	m := testModel(120, 40, healthySnap())
	m = press(m, "d")
	gen := m.doctor.gen

	m, cmd := send(m, doctorTickMsg{gen: gen})
	if cmd == nil {
		t.Fatal("the spinner tick did not re-arm")
	}
	if m.doctor.frame != 1 {
		t.Fatalf("the spinner frame is %d after one tick", m.doctor.frame)
	}
	if got := m.doctor.spinner(); got == "" {
		t.Fatal("the spinner rendered nothing")
	}

	stale, cmd := send(m, doctorTickMsg{gen: gen - 1})
	if cmd != nil {
		t.Fatal("a stale spinner tick re-armed itself")
	}
	if stale.doctor.frame != 1 {
		t.Fatal("a stale spinner tick advanced the frame")
	}
	done, cmd := send(m, doctorDoneMsg{gen: gen, report: doctorFixture(), ranAt: fixtureNow, elapsed: time.Second})
	if _, cmd = send(done, doctorTickMsg{gen: gen}); cmd != nil {
		t.Fatal("the spinner kept ticking after the run completed")
	}
}

// The running screen says what it is doing, for how long, and that it is not
// touching anything.
func TestDoctorRunningScreen(t *testing.T) {
	v := runningModel(120, 40).View()
	for _, want := range []string{"gathering…", "7s", doctorReadOnly, "esc cancel", spinnerFrames[3]} {
		if !strings.Contains(v, want) {
			t.Fatalf("the running screen is missing %q:\n%s", want, v)
		}
	}
	if strings.Contains(v, "%") {
		t.Fatal("the running screen invented a progress percentage")
	}
}

// §4.1's global table is global: the doctor view claims esc/enter/R/p and the
// movement keys, and everything else keeps working from inside it.
func TestDoctorViewKeepsGlobalKeys(t *testing.T) {
	m := doneModel(120, 40)
	m.snaps = append(m.snaps, rootSnap())
	sortSnaps(m.snaps)

	if got := press(m, "tab"); got.selected == m.selected {
		t.Fatal("tab did not switch daemons from the doctor view")
	}
	if got := press(m, "v"); got.overlay != overlaySwitcher {
		t.Fatal("v did not open the switcher from the doctor view")
	}
	if got := press(m, "r"); got.pane != paneRefusals || got.view != viewDoctor {
		t.Fatal("r did not toggle the refusals pane from the doctor view")
	}
	if got := press(m, "?"); got.overlay != overlayHelp {
		t.Fatal("? did not open the help overlay from the doctor view")
	}
	// `d` inside the view is idempotent, not a toggle: esc is how you leave.
	got, cmd := send(m, key("d"))
	if cmd != nil || got.view != viewDoctor {
		t.Fatal("d inside the doctor view was not a no-op")
	}
}

// The findings list is a scroll region with a cursor: it moves when the cursor
// would leave it, and not otherwise.
func TestDoctorListScrollsToTheCursor(t *testing.T) {
	m := doneModel(120, 14)
	rows, _ := m.doctorRows(m.layout())
	budget := m.doctorBudget(m.layout())
	if len(rows) <= budget {
		t.Fatalf("the fixture does not overflow: %d rows in %d", len(rows), budget)
	}
	if m.scroll.offset != 0 {
		t.Fatal("a fresh list did not start at the top")
	}
	// Moving inside the window leaves the offset alone.
	if got := press(m, "j").scroll.offset; got != 0 {
		t.Fatalf("one j scrolled the list to %d", got)
	}
	bottom := press(m, "G")
	if bottom.scroll.offset != maxOffset(len(rows), budget) {
		t.Fatalf("G left offset %d, want %d", bottom.scroll.offset, maxOffset(len(rows), budget))
	}
	if !strings.Contains(bottom.View(), "transport authentication") {
		t.Fatal("the cursor's own row is not on screen after G")
	}
	if got := press(bottom, "g").scroll.offset; got != 0 {
		t.Fatalf("g left offset %d", got)
	}
	// Expanding a finding near the fold pulls its body into view.
	deep := press(m, "G", "enter")
	if !strings.Contains(deep.View(), "static-hmac-v1") {
		t.Fatalf("expanding the last finding did not reveal its evidence:\n%s", deep.View())
	}
}

// No rendered line may exceed the terminal at any size, in any doctor state.
func TestDoctorViewFitsEveryWidth(t *testing.T) {
	for name, build := range map[string]func(w, h int) Model{
		"running":   runningModel,
		"probing":   probingModel,
		"done":      doneModel,
		"expanded":  expandedModel,
		"failed":    failedModel,
		"persisted": persistedModel,
		"withpane":  doctorPaneModel,
	} {
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

func doctorPaneModel(w, h int) Model {
	m := expandedModel(w, h)
	m.pane = paneRefusals
	m.refusals = map[string][]introspect.Refusal{userSock: refusalRing()}
	return m
}

func TestWrapText(t *testing.T) {
	if got := wrapText("one two three", 9); len(got) != 2 || got[0] != "one two" || got[1] != "three" {
		t.Fatalf("wrapped to %q", got)
	}
	// A single word wider than the region is split, never dropped.
	got := wrapText("/very/long/path/that/does/not/fit", 10)
	if strings.Join(got, "") != "/very/long/path/that/does/not/fit" {
		t.Fatalf("hard split lost bytes: %q", got)
	}
	for _, l := range got {
		if visWidth(l) > 10 {
			t.Fatalf("wrapped line %q is wider than the region", l)
		}
	}
	if wrapText("x", 0) != nil {
		t.Fatal("a zero-width region wrapped to something")
	}
}

func TestSecondsText(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"}, {900 * time.Millisecond, "0s"}, {14 * time.Second, "14s"},
		{90 * time.Second, "90s"}, {-time.Second, "0s"},
	} {
		if got := secondsText(tc.d); got != tc.want {
			t.Errorf("secondsText(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
