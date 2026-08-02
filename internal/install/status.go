package install

// Status is what `drawbridge status` reports. It is assembled from three
// independent observations — the filesystem, launchctl, and the log file —
// because they disagree in exactly the ways that matter: a plist present but
// not loaded means someone booted it out by hand, and a running pid whose
// log shows no `agent … (source=…)` line means the daemon is up but has not
// resolved an endpoint.
//
// Deliberately read-only and daemon-free: this half never talks to the
// daemon at all, and it stays the spine and the exit-code source of
// `drawbridge status`. The CLI additionally reads the daemon's read-only
// introspection socket when one answers (docs/doctor.md §D7) — enrichment
// printed after this report, never a thing status requires.
//
// Rendering lives in cmd/drawbridge (renderStatus): this package links into
// drawbridged and must stay free of terminal styling, so it reports data and
// the CLI owns presentation. The wording stays single-source there — the
// tail of a successful install prints through the same renderer as `status`.
type Status struct {
	PlistInstalled  bool
	BinaryInstalled bool

	Loaded bool   // launchctl knows the job
	State  string // launchd's own word, e.g. "running", "waiting"
	PID    int    // 0 when not running

	LogPresent bool
	LogTail    []string // last few lines, newest last
	AgentLine  string   // most recent "agent … (source=…)" line, if any
	LogNote    string   // why the log could not be read, when it could not
}

// Installed is the filesystem answer: are our artifacts on disk at all.
func (s Status) Installed() bool { return s.PlistInstalled || s.BinaryInstalled }

// Running is the launchd answer.
func (s Status) Running() bool { return s.Loaded && s.State == "running" }

// Step receives one progress line per completed action, printf-style and
// without any prefix. The caller owns presentation (cmd/drawbridge adds the
// `drawbridge: ` prefix and styling); nil discards.
type Step func(format string, args ...any)

func (s Step) emit(format string, args ...any) {
	if s != nil {
		s(format, args...)
	}
}
