// Package introspect is the daemon's read-only state endpoint: the payload
// drawbridged serves, the write-only server that serves it, the client
// doctor and status read it with, and the ID-tagged refusal ring that feeds
// its runtime evidence (docs/doctor.md §3).
//
// The protocol is the whole security argument (D2): on accept the daemon
// marshals one State, writes it with a deadline, and closes — it never calls
// Read on the conn. A listener that reads nothing cannot be driven, so there
// is no request grammar for control verbs to grow into, and the inbound
// surface is accept + write + close. Filesystem permissions are the only
// access control (D3), which is sound because the payload contains nothing
// that is not already derivable from netstat, the lease db, and the daemon
// log — and never secret bytes, proofs, or digests.
package introspect

import "time"

// Schema is this build's payload schema. Within a schema, changes are
// additive only and readers tolerate unknown and absent fields; a reader
// seeing a higher number uses Schema and Version and treats everything else
// as unusable (D4). Those two fields are frozen forever.
const Schema = 1

// State is one snapshot of the daemon, assembled on demand from the state it
// already maintains — no cache, no background sampler, nothing to go stale.
type State struct {
	Schema  int    `json:"schema"`
	Version string `json:"version"`
	PID     int    `json:"pid"`
	EUID    int    `json:"euid"`

	StartedAt time.Time `json:"startedAt"`

	VM       VM     `json:"vm"`
	MirrorIP string `json:"mirrorIP,omitempty"`

	// Resolution is the daemon's live result including re-resolves — the
	// thing `status` could never see. Note carries limaaddr's verbatim
	// Resolution.Note; doctor prints it unchanged.
	Resolution Resolution `json:"resolution"`

	Auth   Auth   `json:"auth"`
	Mirror Mirror `json:"mirror"`
	Sync   Sync   `json:"sync"`

	// RecentRefusals is the fixed-size ring fed at the same call sites as the
	// throttled refusal and skip log lines. It is what makes runtime auth
	// evidence work for a foreground daemon, which has no log file.
	RecentRefusals []Refusal `json:"recentRefusals,omitempty"`
}

// VM names the daemon's target. Ref is the -vm spelling; provider and
// instance are the canonical pair, so a consumer can match a snapshot to a
// VM rather than guess.
type VM struct {
	Ref      string `json:"ref"`
	Provider string `json:"provider,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// Resolution is where the agent endpoint came from, and when.
type Resolution struct {
	Endpoint   string    `json:"endpoint"`
	Source     string    `json:"source"`
	Note       string    `json:"note,omitempty"`
	ResolvedAt time.Time `json:"resolvedAt"`
}

// Auth modes and secret states. Mode is the scheme in force; SecretState is
// what the daemon's own last read of the file found.
const (
	AuthModeNone         = "none"
	AuthModeStaticHMACv1 = "static-hmac-v1"

	SecretOK        = "ok"
	SecretAbsent    = "absent"
	SecretMalformed = "malformed"
)

// Auth is the transport-auth posture. Mode and path only — never bytes,
// proofs, or digests (digest comparison is doctor's job, done directly
// against the files, and a socket any staff user can read is not where a
// digest belongs).
type Auth struct {
	Mode        string `json:"mode"`
	SecretPath  string `json:"secretPath,omitempty"`
	SecretState string `json:"secretState"`
}

// Mirror entry states. `skipped` plus Mirror.Skip make the skip-visibility
// check exact instead of log-scraping; `bind-failed` is the live evidence of
// a forwarder winning the bind race.
const (
	EntryBound      = "bound"
	EntrySkipped    = "skipped"
	EntryBindFailed = "bind-failed"
)

// MirrorEntry is one guest listener's Mac-side fate. Since is when the entry
// entered its current state.
type MirrorEntry struct {
	Proto string    `json:"proto"`
	Port  uint16    `json:"port"`
	State string    `json:"state"`
	Since time.Time `json:"since"`
}

// Mirror is the guest→Mac direction.
type Mirror struct {
	SessionUp   bool          `json:"sessionUp"`
	LastEventAt time.Time     `json:"lastEventAt,omitempty"`
	Entries     []MirrorEntry `json:"entries,omitempty"`
	Skip        []uint16      `json:"skip,omitempty"`
}

// Advertised is one (proto, port) pair the syncer offered the guest — the
// set a reverse-stream activation is bound to.
type Advertised struct {
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

// Sync is the Mac→guest direction.
type Sync struct {
	SessionUp  bool         `json:"sessionUp"`
	Advertised []Advertised `json:"advertised,omitempty"`
	UDPPorts   []uint16     `json:"udpPorts,omitempty"`
	PoolParked int          `json:"poolParked"`
}

// Refusal is one ring entry. ID is a stable check ID (the transport-auth §7
// contract for auth causes, or one of the IDs below) so doctor matches
// evidence by ID rather than by parsing log prose; Line is the log line
// verbatim.
type Refusal struct {
	At   time.Time `json:"at"`
	ID   string    `json:"id"`
	Line string    `json:"line"`
}

// Non-auth ring IDs. The auth IDs are transportauth's (docs/transport-auth.md
// §7), spelled there because the emit sites live in that package.
const (
	// IDMirrorSkip: a guest listener the skip-list declined to mirror.
	IDMirrorSkip = "mirror-skip"
	// IDReverseDialRefused: §7 row 7 — a 'D' activation named a port the
	// syncer never advertised.
	IDReverseDialRefused = "reverse-dial-refused"
	// IDActivationReserved: §7 row 9 — nonzero reserved byte in an
	// activation header; doctor folds it into the version-skew check.
	IDActivationReserved = "activation-reserved-byte"
	// IDAdvertisedEmptied: the syncer's advertised set went non-empty→empty
	// while the 'M' session was up. Every reverse activation is refused
	// until it refills; when no Mac listener actually closed, the likely
	// cause is a torn listener poll.
	IDAdvertisedEmptied = "advertised-emptied"
	// IDAdvertisedNone: a session was established advertising nothing —
	// the shape the transition alarm above cannot catch, and the shape the
	// 2026-08-01 incident actually had. A Mac never legitimately has zero
	// LISTEN sockets, so the likely cause is macOS 27.0b4's
	// per-responsible-app pcblist filter (local-network-permission.md
	// finding 5); a root daemon is exempt.
	IDAdvertisedNone = "advertised-none"
)
