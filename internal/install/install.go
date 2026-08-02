//go:build darwin

package install

// The privileged half: filesystem mutation and launchctl. macOS-only by
// design (docs/privileged-daemon.md §11 q3) — the guest side stays
// `just agent-up`, and nothing here manages guest state.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrNeedRoot is returned by the mutating verbs when euid != 0. The message
// is the remedy, since that is the only thing the user can do with it.
var ErrNeedRoot = errors.New("this needs root — re-run with sudo (the daemon binds ports <1024 and must be a root LaunchDaemon)")

// startTimeout bounds the post-bootstrap wait for launchd to report the job
// running. Generous: launchd's own ThrottleInterval is 10 s.
const startTimeout = 15 * time.Second

// transportTimeout bounds the wait for the freshly bootstrapped daemon's
// `agent … (source=…)` line: resolution is sub-second when the guest is
// reachable, so anything longer means the daemon is retrying and install
// should report "not resolved yet" rather than block.
const transportTimeout = 5 * time.Second

// versionTimeout bounds `drawbridged -version`, which prints and exits.
const versionTimeout = 5 * time.Second

// Install lays down the daemon and bootstraps it, idempotently: re-running
// over an existing install refreshes the binary and plist rather than
// failing. Steps are ordered so that a failure never leaves a bootstrapped
// job pointing at a half-written binary — we boot out first, replace the
// files, and bootstrap last.
//
// The returned Status is the post-install state, with the log tail cut at
// the moment of bootstrap: the log file persists across installs, so an
// uncut tail would show a previous daemon's lines as if this run wrote them.
func Install(cfg Config, binSrc string, step Step) (Status, error) {
	if err := cfg.Validate(); err != nil {
		return Status{}, err
	}
	plist, err := RenderPlist(cfg)
	if err != nil {
		return Status{}, err
	}
	if os.Geteuid() != 0 {
		return Status{}, ErrNeedRoot
	}
	src, err := resolveBinarySource(binSrc)
	if err != nil {
		return Status{}, err
	}

	// 1. Refresh path: an already-loaded job holds the old binary and the
	//    mirror ports. Boot it out before touching anything.
	if loaded, _, _ := printJob(); loaded {
		step.emit("booting out the running %s", ServiceTarget)
		if err := bootout(); err != nil {
			return Status{}, fmt.Errorf("launchctl bootout: %w", err)
		}
	}

	// 2. Copy the binary out of the (user-writable) build tree. This is the
	//    escalation boundary: after install, nothing the user account can
	//    write is executed as root.
	if err := ensureRootDir(BinaryDir, 0o755); err != nil {
		return Status{}, err
	}
	if err := installFile(src, BinaryPath, 0o755); err != nil {
		return Status{}, fmt.Errorf("install %s: %w", BinaryPath, err)
	}
	step.emit("installed %s → %s", src, BinaryPath)

	// 3. Logs + rotation.
	if err := ensureRootDir(LogDir, 0o755); err != nil {
		return Status{}, err
	}
	if err := writeRootFile(NewsyslogPath, []byte(NewsyslogConf()), 0o644); err != nil {
		return Status{}, fmt.Errorf("write %s: %w", NewsyslogPath, err)
	}

	// 4. Plist + bootstrap. The log mark is taken here — after the old
	//    daemon is out and has had the file steps' worth of time to flush
	//    its last lines — so everything past it was written by the new one.
	if err := ensureRootDir(filepath.Dir(PlistPath), 0o755); err != nil {
		return Status{}, err
	}
	if err := writeRootFile(PlistPath, []byte(plist), 0o644); err != nil {
		return Status{}, fmt.Errorf("write %s: %w", PlistPath, err)
	}
	step.emit("wrote %s", PlistPath)
	logMark := logSize(LogPath)
	if err := bootstrap(); err != nil {
		return Status{}, fmt.Errorf("launchctl bootstrap: %w", err)
	}

	// 5. Confirm launchd actually started it, and wait (bounded) for the
	//    daemon's own account of which transport it resolved — the one line
	//    that says whether the root path found the guest.
	if err := waitRunning(startTimeout); err != nil {
		return Status{}, err
	}
	st := queryFrom(logMark)
	step.emit("daemon running (pid %d)", st.PID)
	for deadline := time.Now().Add(transportTimeout); st.AgentLine == "" && time.Now().Before(deadline); {
		time.Sleep(250 * time.Millisecond)
		st = queryFrom(logMark)
	}
	return st, nil
}

// Uninstall removes what Install put down and leaves the logs: they are the
// post-mortem, and nothing else on the system references them.
func Uninstall(step Step) error {
	if os.Geteuid() != 0 {
		return ErrNeedRoot
	}
	if loaded, _, _ := printJob(); loaded {
		if err := bootout(); err != nil {
			return fmt.Errorf("launchctl bootout: %w", err)
		}
		step.emit("booted out %s", ServiceTarget)
	}
	var firstErr error
	for _, p := range []string{PlistPath, BinaryPath, NewsyslogPath} {
		switch err := os.Remove(p); {
		case err == nil:
			step.emit("removed %s", p)
		case errors.Is(err, fs.ErrNotExist):
			// already gone; uninstall is idempotent
		default:
			if firstErr == nil {
				firstErr = err
			}
			step.emit("could not remove %s: %v", p, err)
		}
	}
	step.emit("logs kept at %s", LogDir)
	return firstErr
}

// Query assembles the status. It never fails: every unknown becomes a field
// the report can say "missing"/"not loaded" about, because a status command
// that errors out tells you less than one that says what it could see.
func Query() Status { return queryFrom(0) }

// queryFrom is Query with the log read cut at byte offset `since`: Install
// passes the pre-bootstrap size so the tail (and the transport line found in
// it) can only come from the daemon it just started, never a previous run's.
func queryFrom(since int64) Status {
	st := Status{
		PlistInstalled:  fileExists(PlistPath),
		BinaryInstalled: fileExists(BinaryPath),
	}
	st.Loaded, st.State, st.PID = printJob()
	tail, agent, err := tailLog(LogPath, since, 8)
	switch {
	case err == nil:
		st.LogPresent, st.LogTail, st.AgentLine = true, tail, agent
	case errors.Is(err, fs.ErrNotExist):
		st.LogNote = "no log yet — the daemon has not run"
	default:
		st.LogNote = fmt.Sprintf("cannot read: %v", err)
	}
	return st
}

// InstalledVersion asks the installed daemon what it is, by running it with
// -version. That path is root-owned 0755, so an unprivileged `drawbridge
// doctor` can read the answer without launchctl, a log file, or root.
//
// ErrNotInstalled is a distinct result from a failure to run: "no daemon
// installed" is a state doctor reports as `warn` with two ways forward,
// while a binary that will not answer is evidence of a broken install.
func InstalledVersion() (string, error) {
	if !fileExists(BinaryPath) {
		return "", ErrNotInstalled
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, BinaryPath, "-version").Output()
	if err != nil {
		return "", fmt.Errorf("%s -version: %w", BinaryPath, err)
	}
	return parseVersionOutput(string(out))
}

// resolveBinarySource finds the drawbridged to install: an explicit -bin, or
// the sibling of the invoking CLI (which is how `sudo ./bin/drawbridge
// install` finds ./bin/drawbridged).
func resolveBinarySource(override string) (string, error) {
	if override != "" {
		return checkBinary(override)
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate this binary (pass -bin): %w", err)
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return "", fmt.Errorf("resolve %s (pass -bin): %w", self, err)
	}
	return checkBinary(filepath.Join(filepath.Dir(self), BinaryName))
}

func checkBinary(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("daemon binary %s: %w (run `just build`, or pass -bin)", abs, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("daemon binary %s is not a regular file", abs)
	}
	return abs, nil
}

// ensureRootDir creates a directory and then insists the whole path down to
// it is root-owned and not group/other-writable. This is the check that
// makes "copy the binary out of the build tree" mean something: on a machine
// where /usr/local is owned by the admin user (Homebrew-on-Intel layout),
// dropping a root-executed binary into /usr/local/libexec would hand that
// user a root escalation at the next boot. Refusing is the only safe answer
// — there is no repair we should be making to someone's /usr/local.
func ensureRootDir(dir string, mode fs.FileMode) error {
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	// MkdirAll honours umask; be explicit about the result.
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	if err := os.Chown(dir, 0, 0); err != nil {
		return fmt.Errorf("chown %s: %w", dir, err)
	}
	return checkSecurePath(dir)
}

// checkSecurePath walks / → dir and rejects any component that a non-root
// user could replace.
func checkSecurePath(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(abs), "/"), "/")
	cur := "/"
	for i := 0; ; i++ {
		fi, err := os.Stat(cur)
		if err != nil {
			return fmt.Errorf("stat %s: %w", cur, err)
		}
		if err := secureDirInfo(cur, fi); err != nil {
			return err
		}
		if i >= len(parts) || parts[i] == "" {
			return nil
		}
		cur = filepath.Join(cur, parts[i])
	}
}

// ownerUID reads the owning uid off a stat result. Darwin-only, hence its
// home in this file.
func ownerUID(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func secureDirInfo(path string, fi fs.FileInfo) error {
	uid, ok := ownerUID(fi)
	if ok && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root: refusing to install a root-executed binary under a directory a non-root user can replace", path, uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group- or other-writable (%#o): refusing to install a root-executed binary under it", path, fi.Mode().Perm())
	}
	return nil
}

// installFile copies src over dst atomically: write a private temp file in
// the destination directory, fix mode and ownership, then rename. The
// intermediate is never world-readable and never executable, so there is no
// window where a half-written root binary is runnable.
func installFile(src, dst string, mode fs.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeRootFile(dst, data, mode)
}

func writeRootFile(dst string, data []byte, mode fs.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chown(tmpName, 0, 0); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// --- launchctl ---------------------------------------------------------

func bootstrap() error {
	out, err := exec.Command("launchctl", "bootstrap", "system", PlistPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func bootout() error {
	out, err := exec.Command("launchctl", "bootout", ServiceTarget).CombinedOutput()
	if err == nil {
		return nil
	}
	// "No such process" / "Could not find specified service" — the job is
	// already gone, which is the state we wanted.
	if strings.Contains(string(out), "No such process") || strings.Contains(string(out), "Could not find") {
		return nil
	}
	return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
}

// launchctl print indents the job's own fields with exactly one tab and
// nests per-endpoint blocks deeper — those carry their own `state = active`
// lines, which must not be mistaken for the job's. Hence the anchored
// pattern, with a loose fallback so a future indentation change degrades to
// a slightly less precise read rather than to "unknown".
//
// State values are multi-word ("not running"), so the capture runs to end of
// line: a \S+ capture would report a stopped job as state "not".
var (
	stateRE      = regexp.MustCompile(`(?m)^\t?state\s*=\s*(.+?)\s*$`)
	stateLooseRE = regexp.MustCompile(`(?m)^\s*state\s*=\s*(.+?)\s*$`)
	pidRE        = regexp.MustCompile(`(?m)^\t?pid\s*=\s*(\d+)`)
	pidLooseRE   = regexp.MustCompile(`(?m)^\s*pid\s*=\s*(\d+)`)
)

// printJob asks launchd what it knows. Works unprivileged for reads, which
// is why `drawbridge status` needs no sudo.
func printJob() (loaded bool, state string, pid int) {
	out, err := exec.Command("launchctl", "print", ServiceTarget).CombinedOutput()
	if err != nil {
		return false, "", 0
	}
	return true, parseState(string(out)), parsePID(string(out))
}

func parseState(s string) string {
	for _, re := range []*regexp.Regexp{stateRE, stateLooseRE} {
		if m := re.FindStringSubmatch(s); m != nil {
			return m[1]
		}
	}
	return "unknown"
}

func parsePID(s string) int {
	for _, re := range []*regexp.Regexp{pidRE, pidLooseRE} {
		if m := re.FindStringSubmatch(s); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				return n
			}
		}
	}
	return 0
}

// waitRunning polls until launchd reports the job running. A bootstrap that
// "succeeds" and then immediately throttles is the failure this catches —
// without it, install would report success for a daemon that exited on its
// first line.
func waitRunning(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		loaded, state, pid := printJob()
		if loaded && state == "running" && pid > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not reach state=running within %s (last: loaded=%v state=%q pid=%d) — check %s",
				ServiceTarget, timeout, loaded, state, pid, LogPath)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// --- log ---------------------------------------------------------------

// logSize is the mark Install takes before bootstrap: everything the file
// gains past it was written by the new daemon. 0 (no file, unreadable) means
// "no mark", which tailLog treats as "read the whole window".
func logSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// tailLog returns the last n lines past byte offset `since`, plus the most
// recent transport line among them. The `agent … (source=…)` line is the
// observable transport state: which endpoint the daemon resolved, and — for
// the root path — whether it got there via the lease db.
//
// `since` 0 reads the whole window (status); Install passes its pre-bootstrap
// mark so a persisting log cannot surface a previous run's lines. A file now
// smaller than the mark was rotated out from under it, so everything present
// is newer than the mark and the whole window is read.
func tailLog(path string, since int64, n int) (tail []string, agent string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	const window = 64 << 10
	off := int64(0)
	if since > 0 && since <= fi.Size() {
		off = since // the mark is a line boundary: the old daemon's writes end in \n
	}
	fragment := false
	if fi.Size()-off > window {
		off = fi.Size() - window
		fragment = true
	}
	buf := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, "", err
	}
	body := strings.TrimRight(string(buf), "\n")
	if body == "" {
		return nil, "", nil
	}
	lines := strings.Split(body, "\n")
	if fragment && len(lines) > 0 {
		lines = lines[1:] // the first line is a fragment
	}
	for _, l := range lines {
		if strings.Contains(l, "agent ") && strings.Contains(l, "(source=") {
			agent = l
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, agent, nil
}
