// Package install is the macOS install story for the privileged daemon:
// path policy, LaunchDaemon plist rendering, log rotation, and launchctl
// wrappers, driven by the `drawbridge install|uninstall|status` verbs.
//
// Why root at all (docs/privileged-daemon.md §1): macOS reserves ports
// <1024 for root and has no `reservedhigh` sysctl, so `--network host nginx`
// → `curl localhost:80` is impossible unprivileged; and per TN3179 a launchd
// daemon running as root is exempt from the Local Network permission gate,
// which is what makes the vzNAT-direct transport work on a fresh machine
// with no defaults ritual and no reboot.
//
// This file is the portable half — pure string/policy functions, unit
// testable on any GOOS. The privileged, macOS-only half lives in install.go.
package install

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// ErrNotInstalled is InstalledVersion's answer when there is no daemon
// binary to ask. Distinct from a failure to run one: "not installed" is a
// legitimate state (`doctor` names both ways forward), a binary that will
// not answer is a broken install.
var ErrNotInstalled = errors.New("no drawbridged installed at " + BinaryPath)

// parseVersionOutput reads `drawbridged v0.1.0`, the spelling
// cmd/drawbridged prints. A bare version is accepted too, so a future format
// that drops the program name still reads.
func parseVersionOutput(out string) (string, error) {
	fields := strings.Fields(out)
	switch len(fields) {
	case 0:
		return "", fmt.Errorf("%s -version printed nothing", BinaryPath)
	default:
		return fields[len(fields)-1], nil
	}
}

// Identity and path policy. Changing any of these after real installs exist
// strands them: an uninstall by a newer CLI looks for the new label and
// leaves the old daemon bootstrapped.
const (
	// Label is the launchd job label; ServiceTarget is how launchctl's
	// subcommands address it in the system domain.
	Label         = "com.archcorsair.drawbridged"
	ServiceTarget = "system/" + Label

	// PlistPath, BinaryPath: both root-owned files in root-owned
	// directories. The binary is *copied* here from the build tree at
	// install time and never referenced in place — a plist pointing into a
	// user-writable directory is a user→root escalation, since whoever can
	// write that file runs as root at the next boot (§6).
	PlistPath  = "/Library/LaunchDaemons/" + Label + ".plist"
	BinaryDir  = "/usr/local/libexec"
	BinaryPath = BinaryDir + "/drawbridged"

	// Logs are launchd-owned (StandardOutPath/StandardErrorPath) and are
	// deliberately kept by uninstall — they are the post-mortem.
	LogDir  = "/Library/Logs/drawbridge"
	LogPath = LogDir + "/drawbridged.log"

	// NewsyslogPath bounds the log. See NewsyslogConf for the caveat.
	NewsyslogPath = "/etc/newsyslog.d/drawbridge.conf"

	// BinaryName is what install looks for next to the invoking CLI.
	BinaryName = "drawbridged"
)

// Config is what the install renders into the plist. Everything here ends up
// as literal text in an XML document that launchd executes as root, so the
// fields are validated (and rejected), never escaped: a VM name that needs
// escaping is a VM name Lima would not accept either, and "we quoted it
// correctly" is a worse security argument than "it cannot contain that".
type Config struct {
	// VM is the daemon's -vm value, verbatim: a bare Lima instance name, or
	// `provider:name` (`colima:default`, `lima:myvm`). It is rendered as
	// given rather than canonicalised into an instance name — the daemon
	// does that mapping itself at boot, and a plist that said `colima` where
	// the user wrote `colima:default` would not read back as what was
	// installed.
	VM  string
	UDP []uint16 // Mac UDP ports to offer the guest → -udp a,b (omitted when empty)

	// MAC is the guest's expected hardware address → -vm-mac (omitted when
	// empty). The daemon resolves its peer out of the DHCP lease db, whose
	// records are named by the guest itself; pinning the MAC is what stops a
	// second VM on this Mac from claiming this VM's name and inheriting a
	// root daemon's trust. Empty means the daemon matches by name only and
	// says so in its log.
	MAC string

	// Subnet overrides the vmnet subnet lease records must fall inside →
	// -vm-subnet (omitted when empty, i.e. limaaddr.DefaultSubnet). Only a
	// Mac whose vmnet is configured off the default needs it.
	Subnet string

	// Skip is the port skip-list → -skip, set through SetSkip. Nil means
	// "leave the daemon's own default alone" and renders nothing; a non-nil
	// value renders, INCLUDING the empty slice, which renders `-skip ""` and
	// is how an installed daemon is told to skip nothing. nil and []uint16{}
	// are therefore different configurations — hence SetSkip rather than a
	// bare field assignment.
	Skip []uint16

	// SecretFile is the transport secret's path → -secret-file (omitted when
	// empty). A *path*, never the secret itself: ProgramArguments is
	// ps-visible, and the bytes are file-borne only (docs/transport-auth.md
	// §5). Root reading a user-owned 0600 file is intended — the user is this
	// system's trust root, and the file grants transport identity, not code
	// execution — which is why `install` renders the invoking user's path
	// (SUDO_USER-derived) rather than root's.
	SecretFile string
}

// DefaultVM matches drawbridged's own -vm default.
const DefaultVM = "drawbridge"

// DefaultSkip matches drawbridged's own -skip default (docs/ergonomics.md §7:
// `22` only — the Mac's Remote Login must not be synced into the guest, where
// it would steer in-guest `ssh localhost` at the Mac's sshd). Speculative
// entries are deliberately absent: users come to depend on entries, so growing
// this list is far cheaper than shrinking it.
const DefaultSkip = "22"

// DefaultSkipPorts is DefaultSkip parsed. It panics on a malformed constant,
// which is a build-time error in practice (a unit test parses it).
func DefaultSkipPorts() []uint16 {
	ports, err := ParsePorts("", DefaultSkip)
	if err != nil {
		panic("install: malformed DefaultSkip: " + err.Error())
	}
	return ports
}

// macRE and subnetRE are the same discipline applied to the two arguments
// added since: an allowlist of the literal shape, so nothing that reaches
// root's ProgramArguments has ever needed escaping. Both are re-parsed by
// the daemon at boot; these only have to make the *text* safe and obviously
// well-formed, which a regexp does and a "does it parse" check does not.
var (
	macRE    = regexp.MustCompile(`^[0-9A-Fa-f]{1,2}(:[0-9A-Fa-f]{1,2}){5}$`)
	subnetRE = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`)
)

// Validate rejects anything that would land unreviewed in root's argv.
func (c Config) Validate() error {
	// vmprovider.ParseRef is the same allowlist the daemon parses -vm with,
	// so an install can never render a value drawbridged would refuse at
	// boot — and, being an allowlist over a two-token grammar, nothing that
	// reaches root's ProgramArguments has ever needed escaping.
	if _, err := vmprovider.ParseRef(c.VM); err != nil {
		return fmt.Errorf("invalid VM %q: %w", c.VM, err)
	}
	for _, p := range c.UDP {
		if p == 0 {
			return fmt.Errorf("invalid UDP port 0")
		}
	}
	for _, p := range c.Skip {
		if p == 0 {
			return fmt.Errorf("invalid skip port 0")
		}
	}
	if c.MAC != "" && !macRE.MatchString(c.MAC) {
		return fmt.Errorf("invalid VM hardware address %q: expected six colon-separated hex octets, e.g. 52:55:55:a5:de:d2", c.MAC)
	}
	if c.Subnet != "" && !subnetRE.MatchString(c.Subnet) {
		return fmt.Errorf("invalid vmnet subnet %q: expected an IPv4 CIDR, e.g. 192.168.64.0/24", c.Subnet)
	}
	if err := validateSecretFile(c.SecretFile); err != nil {
		return err
	}
	return nil
}

// validateSecretFile is the same validate-never-escape rule applied to a path
// this package cannot describe with a regexp: `~/Library/Application Support`
// legitimately contains a space, and plist argv elements are separate
// <string>s with no shell in the path, so a space is fine and an XML
// metacharacter is not. Control characters are rejected because a plist is
// text and a NUL or newline in an argument is never intentional.
func validateSecretFile(p string) error {
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("invalid transport secret path %q: must be absolute", p)
	}
	if strings.ContainsAny(p, "&<>\"'") {
		return fmt.Errorf("invalid transport secret path %q: must not contain any of & < > \" '", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid transport secret path %q: must not contain control characters", p)
		}
	}
	return nil
}

// Args is the daemon's argv as installed. `-agent auto` rather than a pinned
// endpoint is load-bearing: a pinned -agent disables drawbridged's
// re-resolve hook, so a recreated VM (new MAC → new vzNAT IP) would leave
// the daemon dialing a dead address until someone re-ran install (§4).
//
// -mirror-ip is deliberately absent: the default is 127.0.0.1 and the daemon
// refuses any non-loopback value under root, so the installed plist has no
// way to express a wildcard bind.
// -vm-mac and -vm-subnet are rendered only when given: an absent -vm-mac is
// the daemon's own "match by name only" default, and writing a placeholder
// would make an unpinned install look pinned.
func (c Config) Args() []string {
	args := []string{BinaryPath, "-agent", "auto", "-vm", c.VM}
	if len(c.UDP) > 0 {
		args = append(args, "-udp", joinPorts(c.UDP))
	}
	if c.Skip != nil { // nil ⇒ the daemon's own default; empty ⇒ `-skip ""`
		args = append(args, "-skip", joinPorts(c.Skip))
	}
	if c.MAC != "" {
		args = append(args, "-vm-mac", c.MAC)
	}
	if c.Subnet != "" {
		args = append(args, "-vm-subnet", c.Subnet)
	}
	if c.SecretFile != "" {
		// Rendered explicitly rather than left to the daemon's own
		// derivation: as root the daemon would derive root's home, and the
		// secret belongs to the user who ran `up` (docs/transport-auth.md §5).
		args = append(args, "-secret-file", c.SecretFile)
	}
	return args
}

// joinPorts renders a port list as the daemon's flags spell it. Ports are
// numeric by type, so the rendered text needs no escaping and no allowlist
// regexp — the parse into []uint16 (ParsePorts) is the validation, and
// Validate re-checks the one value the type still allows and the flags do
// not (0).
func joinPorts(ports []uint16) string {
	out := make([]string, len(ports))
	for i, p := range ports {
		out[i] = strconv.Itoa(int(p))
	}
	return strings.Join(out, ",")
}

// RenderPlist produces the LaunchDaemon definition.
//
// LaunchDaemon, not LaunchAgent: agents run as the logging-in user and are
// not TN3179-exempt. RunAtLoad+KeepAlive give reboot survival and crash
// restart (launchd's 10 s ThrottleInterval is the crash-loop backstop; the
// daemon's own 1 s reconnect loops mean a stopped VM never exits the
// process, so KeepAlive churn only follows a real crash). ProcessType
// Interactive keeps a data-plane process out of background QoS throttling.
//
// No signing is needed — Gatekeeper gates quarantined downloads, not local
// builds — and no other keys are set: every key here is one launchd would
// otherwise get wrong for a data plane.
func RenderPlist(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString("<dict>\n")
	b.WriteString("\t<key>Label</key>\n\t<string>" + Label + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, a := range c.Args() {
		b.WriteString("\t\t<string>" + a + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")
	b.WriteString("\t<key>ProcessType</key>\n\t<string>Interactive</string>\n")
	b.WriteString("\t<key>StandardOutPath</key>\n\t<string>" + LogPath + "</string>\n")
	b.WriteString("\t<key>StandardErrorPath</key>\n\t<string>" + LogPath + "</string>\n")
	b.WriteString("</dict>\n")
	b.WriteString("</plist>\n")
	return b.String(), nil
}

// NewsyslogConf bounds the daemon's log at 1 MB, keeping 5 archives.
//
// The N flag is not optional decoration: with no pid_file field, newsyslog's
// default is to SIGHUP *syslogd*, which has nothing to do with us. N says
// there is no process to signal.
//
// Known caveat, stated in the file itself: launchd — not drawbridged — opens
// the log and dup2s it onto the daemon's stdout/stderr, and nothing can make
// it reopen. So the first rotation moves the file out from under a live fd
// and the daemon keeps appending to the archive until it next restarts
// (reboot, crash, or reinstall), at which point launchd opens the fresh
// file. Fixing that properly costs a pid file plus a SIGHUP-reopen handler
// in the daemon, and buying it means newsyslog holding a root signal target
// that goes stale — a worse trade than a log that is bounded per daemon
// lifetime at this log volume (a line per mirror open/close).
func NewsyslogConf() string {
	return "# logfilename\t\t[owner:group]\tmode count size when flags\n" +
		"# drawbridged's log is opened by launchd (StandardOutPath), so there is no\n" +
		"# process to signal on rotation (flag N) — and the running daemon keeps\n" +
		"# appending to the rotated file until it restarts. See internal/install.\n" +
		LogPath + "\troot:wheel\t644\t5\t1024\t*\tN\n"
}

// ParsePorts turns one of the CLI's comma-separated port-list values into
// ports. It is the one parser both `drawbridge install` and drawbridged use,
// so an install can never render a flag value the daemon would reject at
// boot. what qualifies the error ("UDP"; "" when the caller already names the
// flag). Empty (or all-whitespace) is an empty list, not an error — that is
// how -skip spells "no skip-list".
func ParsePorts(what, s string) ([]uint16, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	label := "port"
	if what != "" {
		label = what + " port"
	}
	var out []uint16
	for _, f := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(strings.TrimSpace(f), 10, 16)
		if err != nil || v == 0 {
			return nil, fmt.Errorf("bad %s %q", label, f)
		}
		out = append(out, uint16(v))
	}
	return out, nil
}

// ParseUDPPorts is ParsePorts for the -udp flag.
func ParseUDPPorts(s string) ([]uint16, error) { return ParsePorts("UDP", s) }

// SetSkip records the CLI's -skip value on the config.
//
// It renders into the plist only when it differs from the daemon's own
// default (DefaultSkip) — the rule -vm-mac and -vm-subnet already follow:
// never write an argument that merely restates a default, or a future change
// to that default cannot reach installs that never asked for the old value.
// An explicitly empty list (`-skip ""`, the disable spelling) does differ
// from the default, and renders as `-skip ""`.
func (c *Config) SetSkip(spec string) error {
	ports, err := ParsePorts("", spec)
	if err != nil {
		return err
	}
	if samePorts(ports, DefaultSkipPorts()) {
		c.Skip = nil
		return nil
	}
	if ports == nil {
		ports = []uint16{} // non-nil: "explicitly none" is not "unset"
	}
	c.Skip = ports
	return nil
}

func samePorts(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
