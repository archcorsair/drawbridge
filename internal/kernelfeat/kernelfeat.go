// Package kernelfeat is the guest kernel feature probe: what `up` and doctor
// check 2 ask before trusting a guest kernel with the agent (audit
// 2026-10-28 L5, NEW-B4).
//
// The agent has two kernel dependencies a version compare answers badly:
//
//   - getsockopt(SO_NETNS_COOKIE). The loopback gateway scopes all eight
//     cgroup hooks to the guest's own netns by that cookie, and internal/bpf
//     refuses to attach on an error or a zero cookie. The option landed in
//     v5.14 (e8b9eab99232) and was also queued for some 5.12.y and 5.13.y
//     stable kernels, so the kernel is asked: `drawbridge-agent features`
//     opens one socket, reads the option and prints one JSON line.
//   - fentry/fexit on kernel functions, which the listener tracker attaches
//     to inet_csk_listen_start and friends. That needs a BPF trampoline the
//     kernel can reach through ftrace direct calls
//     (CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS). x86_64 has had them since
//     v5.5 (562955fe6a55), under the cookie's floor; arm64 got the BPF
//     trampoline in v6.0 (efc9909fdce0) and direct calls only in v6.4
//     (2aa6ac03516d). Verified live 2026-10-29 on Ubuntu 22.04's GA arm64
//     kernel, 5.15.0-185: the cookie probe says yes, the gateway attaches,
//     and the tracker's first fentry program fails BPF_PROG_LOAD with
//     ENOTSUPP; the kernel config has no *_DIRECT_CALLS options at all. The
//     probe reads the option from the kernel config (no privilege, no BPF);
//     only a guest with no readable config falls back to the arch's version.
//
// The 5.8 floor the agent already had (BPF_MAP_TYPE_RINGBUF for the
// tracker's events, the cgroup getpeername hooks for the gateway) sits below
// both and is implied by them.
//
// A version compare remains only as the fallback for whatever the guest
// cannot answer: no agent installed yet, an agent that predates the
// subcommand, or no readable kernel config.
//
// This file is pure: no exec, no syscalls. The agent half lives in
// cmd/drawbridge-agent; the guest-side script is Script.
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

// The key=value keys Script emits, one line each.
const (
	Key            = "features"                     // the agent's report, or why there is none
	KeyArch        = "features-arch"                // uname -m
	KeyDirectCalls = "features-ftrace-direct-calls" // y, n or unknown, from the kernel config
)

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

// The values of KeyDirectCalls.
const (
	ConfigYes     = "y"
	ConfigNo      = "n"
	ConfigUnknown = "unknown" // no readable kernel config
)

// Probe is what the guest said.
type Probe struct {
	Ran    bool // a parseable Report came back
	Report Report
	Why    string // when !Ran: one of the constants above, or the unparseable output

	// Arch is `uname -m`; DirectCalls is ConfigYes, ConfigNo, ConfigUnknown,
	// or "" when the script did not say (not asked).
	Arch        string
	DirectCalls string
}

// configOption is the kernel config line the tracker's fentry/fexit attach
// depends on.
const configOption = "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS"

// Script returns the POSIX sh fragment that asks the guest. It emits three
// lines: KeyArch, KeyDirectCalls, and Key (the agent's report or a reason
// word). Read-only by construction: uname, tests and greps of the kernel
// config (/boot/config-<release> on Ubuntu, /lib/modules/<release>/config on
// Fedora, /proc/config.gz where built in), and, only for an agent binary at
// path that carries Marker, the subcommand itself. It runs as whoever runs
// the script; nothing in it needs privilege.
//
// path must be one space-free word without quotes; every caller passes a
// constant (guestbin.GuestPath) or up's fixed staging path.
func Script(path string) string {
	return fmt.Sprintf(`db_feat_rel=$(uname -r 2>/dev/null)
echo "%[9]s=$(uname -m 2>/dev/null)"
db_feat_cfg=%[13]s
for db_feat_f in "/boot/config-$db_feat_rel" "/lib/modules/$db_feat_rel/config"; do
  if [ -r "$db_feat_f" ]; then
    if grep -q '^%[10]s=y' "$db_feat_f" 2>/dev/null; then db_feat_cfg=%[11]s; else db_feat_cfg=%[12]s; fi
    break
  fi
done
if [ "$db_feat_cfg" = %[13]s ] && [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
  if db_feat_z=$(zcat /proc/config.gz 2>/dev/null); then
    if printf '%%s\n' "$db_feat_z" | grep -q '^%[10]s=y'; then db_feat_cfg=%[11]s; else db_feat_cfg=%[12]s; fi
  fi
fi
echo "%[14]s=$db_feat_cfg"
db_feat_bin='%[1]s'
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
`, path, Key, Absent, Unreadable, Marker, Predates, Subcommand, Failed,
		KeyArch, configOption, ConfigYes, ConfigNo, ConfigUnknown, KeyDirectCalls)
}

// Parse reads the value of a `features=` line into a fresh Probe.
func Parse(v string) Probe {
	var p Probe
	p.setReport(v)
	return p
}

// Set records one key=value line Script emitted, and reports whether the
// key was one of Script's. Callers loop over the output and hand every line
// here, so a new key never needs a new case in each of them.
func (p *Probe) Set(k, v string) bool {
	v = strings.TrimSpace(v)
	switch k {
	case Key:
		p.setReport(v)
	case KeyArch:
		p.Arch = v
	case KeyDirectCalls:
		switch v {
		case ConfigYes, ConfigNo:
			p.DirectCalls = v
		default:
			p.DirectCalls = ConfigUnknown
		}
	default:
		return false
	}
	return true
}

func (p *Probe) setReport(v string) {
	v = strings.TrimSpace(v)
	p.Ran, p.Report, p.Why = false, Report{}, ""
	if !strings.HasPrefix(v, "{") {
		if v == "" {
			v = Failed
		}
		p.Why = v
		return
	}
	var r Report
	if err := json.Unmarshal([]byte(v), &r); err != nil || r.Probe != Marker {
		p.Why = Failed + ": " + v
		return
	}
	p.Ran, p.Report = true, r
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
	// Probed says the cookie answer came from the kernel rather than its
	// version.
	Probed bool
	// Evidence is one line per dependency for doctor's evidence list.
	Evidence []string
	// Problem is the plain-words sentence for a Warn or Fail, every
	// dependency that is not OK joined.
	Problem string
	// Short names what is wrong in a few words, for a title.
	Short string
	// Remedy is the shared fix, phrased once so `up` and doctor say the same
	// thing. Empty when Status is OK.
	Remedy string
}

// The version floors for the fallbacks.
var (
	// MinKernel is where SO_NETNS_COOKIE landed upstream.
	MinKernel = [2]int{5, 14}
	// MinBackport is the oldest stable series the backport was queued for.
	// At or above it but below MinKernel, only the probe can tell.
	MinBackport = [2]int{5, 12}
	// MinArm64DirectCalls is where arm64 gained ftrace direct calls, and
	// with them fentry/fexit on kernel functions.
	MinArm64DirectCalls = [2]int{6, 4}
)

// The remedies. TracerRemedy is the one `up` and doctor share for the
// tracker failure; CookieRemedy is arch-aware so an arm64 reader is never
// pointed at a 5.14 kernel the tracker cannot run on.
const (
	floorArm64 = "use a guest kernel >= 6.4: Ubuntu 24.04, Ubuntu 22.04 with the HWE kernel\n" +
		"(linux-generic-hwe-22.04; its GA 5.15 kernel is not enough), or Fedora CoreOS"
	floorOther = "use a guest kernel >= 5.14 (Ubuntu 22.04 or later, Fedora CoreOS),\n" +
		"or a 5.12.y/5.13.y stable kernel that carries the SO_NETNS_COOKIE backport"

	TracerRemedy = "the agent's listener tracker attaches fentry/fexit programs to kernel functions, which needs ftrace\n" +
		"direct calls (" + configOption + "); arm64 has them from Linux 6.4.\n" + floorArm64
)

// CookieRemedy is the fix for a missing SO_NETNS_COOKIE on arch.
func CookieRemedy(arch string) string {
	floor := floorOther
	if isArm64(arch) {
		floor = floorArm64
	}
	return "the agent's loopback gateway scopes its BPF hooks to the guest's own network namespace by that cookie,\n" +
		"and will not start without it; " + floor
}

const cookieWarnRemedy = "re-run `drawbridge up <vm>`: it asks the kernel directly and refuses with this explanation if the answer is no.\n" +
	"The agent will not start without the cookie; a guest kernel >= 5.14 settles it"

// part is one dependency's verdict.
type part struct {
	status   Status
	evidence string
	problem  string
	short    string
	remedy   string
}

// Classify turns the probe and the kernel release into a verdict. Each
// dependency is judged on its own and the worst wins. Where the guest
// answered, the answer wins in either direction, whatever the version says.
func Classify(p Probe, kernel string) Verdict {
	parts := []part{classifyCookie(p, kernel), classifyTracer(p, kernel)}
	v := Verdict{Probed: p.Ran}
	var problems, shorts []string
	for _, pt := range parts {
		v.Evidence = append(v.Evidence, pt.evidence)
		if pt.status > v.Status {
			v.Status = pt.status
		}
	}
	for _, pt := range parts {
		if pt.status == OK {
			continue
		}
		problems = append(problems, pt.problem)
		shorts = append(shorts, pt.short)
		// The worst part's remedy; the tracker's floor (arm64 6.4) covers
		// the cookie's, so on a tie it is the one to give.
		if pt.status == v.Status {
			v.Remedy = pt.remedy
		}
	}
	v.Problem = strings.Join(problems, "; and ")
	v.Short = strings.Join(shorts, " and ")
	return v
}

func classifyCookie(p Probe, kernel string) part {
	if p.Ran {
		if p.Report.NetnsCookie {
			return part{status: OK, evidence: "SO_NETNS_COOKIE: supported (asked the kernel through `drawbridge-agent features`)"}
		}
		why := strings.TrimPrefix(p.Report.NetnsCookieErr, "getsockopt(SO_NETNS_COOKIE): ")
		if why == "" {
			why = "no reason given"
		}
		return part{status: Fail, short: "lacks SO_NETNS_COOKIE", remedy: CookieRemedy(p.Arch),
			evidence: "SO_NETNS_COOKIE: not supported (asked the kernel): " + why,
			problem:  fmt.Sprintf("guest kernel %s does not support getsockopt(SO_NETNS_COOKIE): %s", kernel, why)}
	}

	not := "SO_NETNS_COOKIE: not probed (" + whyText(p.Why) + "), judged by kernel version"
	maj, min, ok := ParseMajorMinor(kernel)
	switch {
	case !ok:
		return part{status: Warn, evidence: not, short: "SO_NETNS_COOKIE unconfirmed", remedy: cookieWarnRemedy,
			problem: fmt.Sprintf("cannot read the guest kernel version from %q, and %s, so nothing confirms getsockopt(SO_NETNS_COOKIE), which the agent needs",
				kernel, whyText(p.Why))}
	case !below(maj, min, MinKernel):
		return part{status: OK, evidence: fmt.Sprintf("%s: %d.%d >= %d.%d", not, maj, min, MinKernel[0], MinKernel[1])}
	case !below(maj, min, MinBackport):
		return part{status: Warn, evidence: not, short: "SO_NETNS_COOKIE unconfirmed", remedy: cookieWarnRemedy,
			problem: fmt.Sprintf("cannot confirm getsockopt(SO_NETNS_COOKIE) on guest kernel %s: it landed in %d.%d and only some 5.12.y/5.13.y stable kernels carry the backport, and %s",
				kernel, MinKernel[0], MinKernel[1], whyText(p.Why))}
	default:
		return part{status: Fail, evidence: not, short: "lacks SO_NETNS_COOKIE", remedy: CookieRemedy(p.Arch),
			problem: fmt.Sprintf("guest kernel %s is older than %d.%d: the agent needs getsockopt(SO_NETNS_COOKIE), which landed in %d.%d",
				kernel, MinBackport[0], MinBackport[1], MinKernel[0], MinKernel[1])}
	}
}

func classifyTracer(p Probe, kernel string) part {
	const what = "fentry/fexit (listener tracker)"
	switch p.DirectCalls {
	case ConfigYes:
		return part{status: OK, evidence: fmt.Sprintf("%s: %s=y in the kernel config", what, configOption)}
	case ConfigNo:
		return part{status: Fail, short: "cannot attach the tracker's fentry hooks", remedy: TracerRemedy,
			evidence: fmt.Sprintf("%s: %s is not set in the kernel config", what, configOption),
			problem: fmt.Sprintf("guest kernel %s%s has no ftrace direct calls (%s is not set), so the agent's listener tracker cannot attach its fentry/fexit hooks and the agent will not start",
				kernel, archSuffix(p.Arch), configOption)}
	}

	// No readable config (or not asked): the arch decides what the version
	// can prove.
	not := fmt.Sprintf("%s: no readable kernel config", what)
	if p.DirectCalls == "" {
		not = fmt.Sprintf("%s: kernel config not read", what)
	}
	switch {
	case isX86(p.Arch):
		return part{status: OK, evidence: not + "; x86_64 has had ftrace direct calls since 5.5, below the SO_NETNS_COOKIE floor"}
	case !isArm64(p.Arch):
		return part{status: OK, evidence: fmt.Sprintf("%s; not judged for arch %q", not, p.Arch)}
	}
	maj, min, ok := ParseMajorMinor(kernel)
	switch {
	case !ok:
		return part{status: Warn, evidence: not, short: "ftrace direct calls unconfirmed", remedy: TracerRemedy,
			problem: fmt.Sprintf("cannot read the guest kernel version from %q and there is no readable kernel config, so nothing confirms the ftrace direct calls the agent's listener tracker needs on arm64",
				kernel)}
	case !below(maj, min, MinArm64DirectCalls):
		return part{status: OK, evidence: fmt.Sprintf("%s; arm64 %d.%d >= %d.%d", not, maj, min, MinArm64DirectCalls[0], MinArm64DirectCalls[1])}
	default:
		return part{status: Fail, evidence: not, short: "cannot attach the tracker's fentry hooks", remedy: TracerRemedy,
			problem: fmt.Sprintf("guest kernel %s (arm64) is older than %d.%d, where arm64 gained ftrace direct calls, so the agent's listener tracker cannot attach its fentry/fexit hooks and the agent will not start",
				kernel, MinArm64DirectCalls[0], MinArm64DirectCalls[1])}
	}
}

func isArm64(arch string) bool { return arch == "aarch64" || arch == "arm64" }
func isX86(arch string) bool   { return arch == "x86_64" || arch == "amd64" }

func archSuffix(arch string) string {
	if arch == "" {
		return ""
	}
	return " (" + arch + ")"
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
