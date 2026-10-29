// Package kernelfeat is the guest kernel feature probe: what `up` and doctor
// check 2 ask before trusting a guest kernel with the agent (audit
// 2026-10-28 L5, NEW-B4).
//
// The agent's hard kernel dependency is getsockopt(SO_NETNS_COOKIE): the
// loopback gateway scopes all eight cgroup hooks to the guest's own netns by
// that cookie, and internal/bpf refuses to attach on an error or a zero
// cookie. The option landed in v5.14 (e8b9eab99232) and was also queued for
// some 5.12.y and 5.13.y stable kernels, so a version compare cannot answer
// the question; asking the kernel can. The 5.8 floor the agent already had
// (BPF_MAP_TYPE_RINGBUF for the tracker's events, the cgroup getpeername
// hooks for the gateway) sits below it and is implied by it.
//
// The probe is `drawbridge-agent features`, which opens one socket, reads
// the option and prints one JSON line. A version compare remains only as
// the fallback for a guest where the probe cannot run: no agent installed
// yet, or an agent that predates the subcommand.
//
// This file is pure: no exec, no syscalls. The agent half lives in
// cmd/drawbridge-agent; the guest-side script that gates it is Script.
package kernelfeat

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Subcommand is the agent's argv[1] for the probe.
const Subcommand = "features"

// Marker is the report's version tag and the string Script greps the agent
// binary for before running it. The grep is load-bearing: an agent that
// predates the subcommand does not reject `features`, it ignores the
// positional argument and starts as the daemon (flag.Parse stops at the
// first non-flag). As the login user that dies at the BPF load, but not
// before trying to write /run/drawbridge-agent.version, and doctor must
// never mutate the guest. So a binary without the marker is never run.
const Marker = "drawbridge-features/v1"

// Key is the key=value key Script emits.
const Key = "features"

// Report is the agent's answer, one JSON line.
type Report struct {
	Probe string `json:"probe"` // always Marker

	// NetnsCookie is getsockopt(SOL_SOCKET, SO_NETNS_COOKIE) succeeding with
	// a non-zero value on a fresh socket: exactly the read the gateway
	// loader makes and refuses to start without.
	NetnsCookie    bool   `json:"so_netns_cookie"`
	NetnsCookieErr string `json:"so_netns_cookie_error,omitempty"`
}

// Why the probe did not answer. Each is a value Script emits in place of
// the JSON.
const (
	NotAsked   = ""           // the script never ran (doctor skipped the guest)
	Absent     = "absent"     // no agent binary at the path yet
	Unreadable = "unreadable" // the binary exists but cannot be read to look for Marker
	Predates   = "predates"   // the binary has no Marker: an agent from before this probe
	Failed     = "failed"     // the subcommand ran and printed no report
)

// Probe is what the guest said.
type Probe struct {
	Ran    bool // a parseable Report came back
	Report Report
	Why    string // when !Ran: one of the constants above, or the unparseable output
}

// Script returns the POSIX sh fragment that asks the agent binary at path.
// It emits exactly one `features=` line: the report, or a reason word.
// Read-only by construction: a test, a grep and, only for a binary that
// carries Marker, the subcommand itself. It runs as whoever runs the script;
// the probe needs no privilege.
//
// path must be one space-free word without quotes; every caller passes a
// constant (guestbin.GuestPath) or up's fixed staging path.
func Script(path string) string {
	return fmt.Sprintf(`db_feat_bin='%[1]s'
if [ ! -e "$db_feat_bin" ]; then
  echo "%[2]s=%[3]s"
elif [ ! -r "$db_feat_bin" ]; then
  echo "%[2]s=%[4]s"
elif ! grep -qF '%[5]s' "$db_feat_bin" 2>/dev/null; then
  echo "%[2]s=%[6]s"
else
  db_feat_out=$("$db_feat_bin" %[7]s 2>/dev/null | head -n 1)
  echo "%[2]s=${db_feat_out:-%[8]s}"
fi
`, path, Key, Absent, Unreadable, Marker, Predates, Subcommand, Failed)
}

// Parse reads the value of a `features=` line.
func Parse(v string) Probe {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "{") {
		if v == "" {
			v = Failed
		}
		return Probe{Why: v}
	}
	var r Report
	if err := json.Unmarshal([]byte(v), &r); err != nil || r.Probe != Marker {
		return Probe{Why: Failed + ": " + v}
	}
	return Probe{Ran: true, Report: r}
}

// Status is the verdict's severity.
type Status int

const (
	OK Status = iota
	Warn
	Fail
)

// Verdict is the classification `up` and doctor both phrase from.
type Verdict struct {
	Status Status
	// Probed says the answer came from the kernel rather than its version.
	Probed bool
	// Evidence is one line for doctor's evidence list.
	Evidence string
	// Problem is the plain-words sentence for a Warn or Fail.
	Problem string
}

// The version floors for the fallback.
var (
	// MinKernel is where SO_NETNS_COOKIE landed upstream.
	MinKernel = [2]int{5, 14}
	// MinBackport is the oldest stable series the backport was queued for.
	// At or above it but below MinKernel, only the probe can tell.
	MinBackport = [2]int{5, 12}
)

// Remedy is the shared fix for a Fail, phrased once so `up` and doctor say
// the same thing.
const Remedy = "the agent's loopback gateway scopes its BPF hooks to the guest's own network namespace by that cookie,\n" +
	"and will not start without it; use a guest kernel >= 5.14 (Ubuntu 22.04 or later, Fedora CoreOS),\n" +
	"or a 5.12.y/5.13.y stable kernel that carries the SO_NETNS_COOKIE backport"

// Classify turns the probe and the kernel release into a verdict. The probe
// wins whenever it ran, in either direction: a kernel that answers is the
// truth, whatever its version says.
func Classify(p Probe, kernel string) Verdict {
	if p.Ran {
		if p.Report.NetnsCookie {
			return Verdict{Status: OK, Probed: true,
				Evidence: "SO_NETNS_COOKIE: supported (asked the kernel through `drawbridge-agent features`)"}
		}
		why := strings.TrimPrefix(p.Report.NetnsCookieErr, "getsockopt(SO_NETNS_COOKIE): ")
		if why == "" {
			why = "no reason given"
		}
		return Verdict{Status: Fail, Probed: true,
			Evidence: "SO_NETNS_COOKIE: not supported (asked the kernel): " + why,
			Problem:  fmt.Sprintf("guest kernel %s does not support getsockopt(SO_NETNS_COOKIE): %s", kernel, why)}
	}

	not := "SO_NETNS_COOKIE: not probed (" + whyText(p.Why) + "), judged by kernel version"
	maj, min, ok := ParseMajorMinor(kernel)
	switch {
	case !ok:
		return Verdict{Status: Warn, Evidence: not,
			Problem: fmt.Sprintf("cannot read the guest kernel version from %q, and %s, so nothing confirms getsockopt(SO_NETNS_COOKIE), which the agent needs",
				kernel, whyText(p.Why))}
	case !below(maj, min, MinKernel):
		return Verdict{Status: OK, Evidence: fmt.Sprintf("%s: %d.%d >= %d.%d", not, maj, min, MinKernel[0], MinKernel[1])}
	case !below(maj, min, MinBackport):
		return Verdict{Status: Warn, Evidence: not,
			Problem: fmt.Sprintf("cannot confirm getsockopt(SO_NETNS_COOKIE) on guest kernel %s: it landed in %d.%d and only some 5.12.y/5.13.y stable kernels carry the backport, and %s",
				kernel, MinKernel[0], MinKernel[1], whyText(p.Why))}
	default:
		return Verdict{Status: Fail, Evidence: not,
			Problem: fmt.Sprintf("guest kernel %s is older than %d.%d: the agent needs getsockopt(SO_NETNS_COOKIE), which landed in %d.%d",
				kernel, MinBackport[0], MinBackport[1], MinKernel[0], MinKernel[1])}
	}
}

func whyText(why string) string {
	switch why {
	case NotAsked:
		return "the probe was not run"
	case Absent:
		return "no agent is installed in the guest yet"
	case Unreadable:
		return "the agent binary is not readable"
	case Predates:
		return "the agent binary predates the `features` probe"
	case Failed:
		return "the agent's `features` probe printed no answer"
	}
	return "the agent's `features` probe gave an unreadable answer: " + why
}

func below(maj, min int, floor [2]int) bool {
	return maj < floor[0] || (maj == floor[0] && min < floor[1])
}

// ParseMajorMinor reads the leading `major.minor` of a kernel release
// ("6.8.0-51-generic", "5.13", "7.1.3-200.fc44.aarch64"). Numeric, never
// lexical: 5.9 is older than 5.14.
func ParseMajorMinor(rel string) (maj, min int, ok bool) {
	fields := strings.FieldsFunc(rel, func(r rune) bool { return r < '0' || r > '9' })
	if len(fields) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(fields[0])
	min, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, min, true
}
