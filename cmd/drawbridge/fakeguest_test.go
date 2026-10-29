package main

// A stand-in for a guest, good enough that `up` and `down` can be run
// end-to-end against it and the *result* asserted — which files exist, with
// what content — rather than only the sequence of commands issued.
//
// It is deliberately not a shell. It recognizes exactly the snippets this
// package emits, and fails the test on anything else: a new guest command
// that nobody modelled is a command nobody reviewed, and the loud failure is
// the point. What it models is the small algebra those snippets use — `&&`
// sequencing, `|| true`, redirection to /dev/null — because that is what
// distinguishes "the step ran" from "the step was skipped".

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/kernelfeat"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

type fakeGuest struct {
	t *testing.T

	// files is the guest filesystem: path → content. A missing key is a
	// missing file, which is the distinction daemon.json's revert turns on.
	files map[string]string

	// unit state, as systemctl would report it.
	transient bool // a `just agent-up` unit holds the name
	enabled   bool
	active    bool

	preflight string // what the probe script answers

	// inspect is what the podman driver's `machine inspect` would answer.
	inspect vmprovider.PodmanInspect

	// hasRestorecon models an SELinux-managed guest: every installed file is
	// relabelled, and the fake records the calls so the ordering is testable.
	hasRestorecon bool
	relabelled    []string

	// podman's API service, as the socket-activated unit it is. Present but
	// not running is the common case on a real machine, and the one the
	// restart marker calls `idle`; podmanRestarted records that the unit was
	// actually bounced, which `idle` deliberately does not do.
	hasPodmanAPI    bool
	podmanAPIActive bool
	podmanAPIBroken bool
	podmanRestarted bool

	// docker, as a unit of its own: the agent's active state says nothing
	// about the engine's, and the restart paths turn on exactly that.
	hasDocker    bool
	dockerActive bool
	// dockerWedged is the systemd start-rate-limit case reproduced live:
	// docker.service is `failed`, restart refuses — and `reset-failed`
	// clears it, which is what makes the fix observable in a test.
	dockerWedged bool
	// dockerBroken is an engine that will not come up whatever we do (bad
	// config elsewhere, no disk). reset-failed does not help.
	dockerBroken bool

	// The kernel feature probe (kernelfeat.Script). A binary in files is
	// asked only when its content carries the marker, which is what the
	// real script's grep does, so the plain "agent-bytes" fixtures model an
	// agent from before the probe. noCookie is the kernel's answer when it
	// is asked; directCalls is the kernel config's
	// CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS as the script reports it ("" is
	// y, the 6.x answer); probed records every path the probe ran against,
	// and probedAsRoot whether any probe arrived through sudo.
	noCookie     bool
	directCalls  string
	probed       []string
	probedAsRoot bool

	// calls is every script executed, in order, for sequence assertions.
	calls []string
	// removed records rm targets even when the file was not there, so a
	// teardown that *tried* is distinguishable from one that skipped.
	removed []string
}

func newFakeGuest(t *testing.T) *fakeGuest {
	return &fakeGuest{
		t:     t,
		files: map[string]string{},
		preflight: strings.Join([]string{
			"arch=aarch64", "kernel=6.8.0-51-generic", "btf=yes",
			"cgroup2=yes", "systemd=yes", "sudo=yes", "engine=none",
			"restorecon=no", "ostree=no", "selinux=", "crun=", "unpriv_port=0",
			"rootful=no",
		}, "\n"),
	}
}

func (f *fakeGuest) withDocker() *fakeGuest {
	f.hasDocker, f.dockerActive = true, true
	f.preflight = strings.ReplaceAll(f.preflight, "engine=none", "engine=docker")
	return f
}

// withFCOS is the podman machine guest as the 7.0 spike measured it: Fedora
// CoreOS, SELinux Enforcing, restorecon present, podman as the only engine,
// no runc, unprivileged ports from 1024 up.
//
// Note what it does NOT have: docker. The real image symlinks
// /usr/local/bin/docker to podman, which is exactly why the preflight reports
// an engine rather than a `command -v docker` boolean.
func (f *fakeGuest) withFCOS() *fakeGuest {
	f.hasRestorecon = true
	f.hasPodmanAPI = true // socket-activated, and therefore idle
	f.preflight = strings.Join([]string{
		"arch=aarch64", "kernel=7.1.3-200.fc44.aarch64", "btf=yes",
		"cgroup2=yes", "systemd=yes", "sudo=yes", "engine=podman",
		"restorecon=yes", "ostree=yes", "selinux=Enforcing", "crun=1.28",
		"crun_path=/usr/bin/crun", "user=core", "containers_fs=",
		"unpriv_port=1024", "rootful=no",
	}, "\n")
	f.inspect = vmprovider.PodmanInspect{
		Name:  "spike",
		State: "running",
		SSH: vmprovider.PodmanSSH{
			IdentityPath:   "/Users/u/.local/share/containers/podman/machine/machine",
			Port:           57446,
			RemoteUsername: "core",
		},
	}
	return f
}

// Inspect is the podman driver's half the record is written from.
func (f *fakeGuest) Inspect(inst string) (vmprovider.PodmanInspect, error) {
	if f.inspect.Name == "" {
		return vmprovider.PodmanInspect{}, fmt.Errorf("fakeGuest: no inspect answer configured for %q", inst)
	}
	return f.inspect, nil
}

// withRootfulPodman is a `podman machine init --rootful` guest: podman runs
// as root in the init user namespace, the API service is root's, and the OCI
// socket needs no ownership widening at all.
func (f *fakeGuest) withRootfulPodman() *fakeGuest {
	f.withFCOS()
	// The login user stays `core` (a rootful machine is podman-as-root
	// inside a guest you still ssh into as core), which is exactly why
	// `rootful` and not the user name is what decides the socket ownership.
	f.preflight = strings.ReplaceAll(f.preflight, "rootful=no", "rootful=yes")
	f.podmanAPIActive = true // root's podman.service is up on a rootful machine
	return f
}

// withWedgedDocker is the live finding: systemd's start rate limit leaves
// docker.service `failed`, and every `restart` after that is refused until
// the counter is reset.
func (f *fakeGuest) withWedgedDocker() *fakeGuest {
	f.withDocker()
	f.dockerWedged, f.dockerActive = true, false
	return f
}

// withBrokenDocker is an engine no amount of reset-failed will revive.
func (f *fakeGuest) withBrokenDocker() *fakeGuest {
	f.withDocker()
	f.dockerBroken, f.dockerActive = true, false
	return f
}

// --- vmprovider.Provider ---------------------------------------------------

func (f *fakeGuest) List() ([]vmprovider.Instance, error) {
	return nil, fmt.Errorf("fakeGuest.List is not part of these tests")
}

func (f *fakeGuest) GuestArch(string) (string, error) { return "aarch64", nil }

// Shell models what `limactl shell` actually does with argv: it joins the
// words into a shell command without quoting them. So an argv element
// containing a space would be re-split in the guest, and this fake refuses
// one — that refusal is the regression test for the whole convention.
func (f *fakeGuest) Shell(_ string, stdin io.Reader, argv ...string) ([]byte, error) {
	for _, a := range argv {
		if strings.ContainsAny(a, " \t\n") {
			f.t.Fatalf("fakeGuest: argv element %q contains whitespace; `limactl shell` joins argv unquoted, so it would be re-split in the guest", a)
		}
	}
	asRoot := len(argv) > 0 && argv[0] == "sudo"
	if asRoot {
		argv = argv[1:]
		for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
			argv = argv[1:]
		}
	}
	switch {
	case len(argv) == 3 && argv[0] == "dd" && strings.HasPrefix(argv[1], "of=") && argv[2] == "status=none":
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		path := strings.TrimPrefix(argv[1], "of=")
		f.files[path] = string(b)
		f.calls = append(f.calls, "dd of="+path)
		return nil, nil

	case len(argv) == 1 && argv[0] == "sh":
		script, err := io.ReadAll(stdin) // the script rides on stdin
		if err != nil {
			return nil, err
		}
		f.calls = append(f.calls, string(script))
		if strings.Contains(string(script), kernelfeat.Marker) {
			f.probedAsRoot = f.probedAsRoot || asRoot
			return f.execFeatures(string(script))
		}
		return f.exec(string(script))
	}
	f.t.Fatalf("fakeGuest: unmodelled invocation %q", strings.Join(argv, " "))
	return nil, nil
}

var reFeatBin = regexp.MustCompile(`db_feat_bin='([^']*)'`)

// execFeatures answers kernelfeat.Script the way the real one does: the
// arch and the kernel config's direct-call option, then absent, predates (no
// marker in the binary), or the agent's JSON report.
func (f *fakeGuest) execFeatures(script string) ([]byte, error) {
	m := reFeatBin.FindStringSubmatch(script)
	if m == nil {
		f.t.Fatalf("fakeGuest: feature probe without a binary path:\n%s", script)
	}
	path := m[1]
	f.probed = append(f.probed, path)
	cfg := f.directCalls
	if cfg == "" {
		cfg = kernelfeat.ConfigYes
	}
	head := kernelfeat.KeyArch + "=aarch64\n" + kernelfeat.KeyDirectCalls + "=" + cfg + "\n"
	body, ok := f.files[path]
	switch {
	case !ok:
		return []byte(head + kernelfeat.Key + "=" + kernelfeat.Absent + "\n"), nil
	case !strings.Contains(body, kernelfeat.Marker):
		return []byte(head + kernelfeat.Key + "=" + kernelfeat.Predates + "\n"), nil
	case f.noCookie:
		return []byte(head + kernelfeat.Key + `={"probe":"` + kernelfeat.Marker +
			`","so_netns_cookie":false,"so_netns_cookie_error":"getsockopt(SO_NETNS_COOKIE): protocol not available"}` + "\n"), nil
	}
	return []byte(head + kernelfeat.Key + `={"probe":"` + kernelfeat.Marker + `","so_netns_cookie":true}` + "\n"), nil
}

// exec runs one snippet. `&&` chains stop at the first failure, exactly as
// the shell would, which is what makes `install … && mv …` meaningful.
func (f *fakeGuest) exec(script string) ([]byte, error) {
	if strings.Contains(script, "uname -m") {
		return []byte(f.preflight), nil // the probe
	}
	if strings.Contains(script, "drawbridge-docker=") {
		return f.execRestartDocker(), nil // down's engine reload
	}
	if strings.Contains(script, "drawbridge-podman=") {
		return f.execRestartPodmanAPI(), nil // the API socket's cached runtime path
	}
	// A trailing `|| true` covers the whole chain, as it does in sh.
	script = strings.TrimSpace(script)
	tolerant := strings.HasSuffix(script, "|| true")
	script = strings.TrimSpace(strings.TrimSuffix(script, "|| true"))

	var out strings.Builder
	for _, part := range strings.Split(script, "&&") {
		cmd := strings.TrimSpace(part)
		for _, redirect := range []string{">/dev/null 2>&1", "2>/dev/null", ">/dev/null"} {
			cmd = strings.TrimSpace(strings.ReplaceAll(cmd, redirect, ""))
		}
		got, err := f.one(cmd)
		if err != nil {
			if tolerant {
				return []byte(out.String()), nil
			}
			return nil, err
		}
		out.WriteString(got)
	}
	return []byte(out.String()), nil
}

var (
	reSha        = regexp.MustCompile(`^sha256sum '([^']*)'\s*\| cut -d' ' -f1$`)
	rePresent    = regexp.MustCompile(`^if \[ -e '([^']*)' \]; then echo present; cat '([^']*)'; else echo absent; fi$`)
	reInstall    = regexp.MustCompile(`^install -m (\d+) -o root -g root '([^']*)' '([^']*)'$`)
	reMv         = regexp.MustCompile(`^mv -f '([^']*)' '([^']*)'$`)
	reRm         = regexp.MustCompile(`^rm -(?:f|rf) '?([^' ]*)'?$`)
	reMkdir      = regexp.MustCompile(`^mkdir -p '([^']*)'$`)
	reCat        = regexp.MustCompile(`^cat (\S+)$`)
	reSystemd    = regexp.MustCompile(`^systemctl (.*)$`)
	reBash       = regexp.MustCompile(`^bash '([^']*)'(.*)$`)
	reRuncFlag   = regexp.MustCompile(`--runc '([^']*)'`)
	reRestorecon = regexp.MustCompile(`^restorecon -F '([^']*)'$`)
)

func (f *fakeGuest) one(cmd string) (string, error) {
	switch {
	case cmd == "":
		return "", nil

	case reSha.MatchString(cmd):
		path := reSha.FindStringSubmatch(cmd)[1]
		body, ok := f.files[path]
		if !ok {
			return "", nil // sha256sum's failure is swallowed by the pipe
		}
		return sha256Hex([]byte(body)) + "\n", nil

	case rePresent.MatchString(cmd):
		path := rePresent.FindStringSubmatch(cmd)[1]
		if body, ok := f.files[path]; ok {
			return "present\n" + body, nil
		}
		return "absent\n", nil

	case reInstall.MatchString(cmd):
		m := reInstall.FindStringSubmatch(cmd)
		body, ok := f.files[m[2]]
		if !ok {
			return "", fmt.Errorf("install: %s: no such file", m[2])
		}
		f.files[m[3]] = body
		return "", nil

	case reMv.MatchString(cmd):
		m := reMv.FindStringSubmatch(cmd)
		body, ok := f.files[m[1]]
		if !ok {
			return "", fmt.Errorf("mv: %s: no such file", m[1])
		}
		delete(f.files, m[1])
		f.files[m[2]] = body
		return "", nil

	case reRm.MatchString(cmd):
		path := reRm.FindStringSubmatch(cmd)[1]
		f.removed = append(f.removed, path)
		for p := range f.files {
			if p == path || strings.HasPrefix(p, path+"/") {
				delete(f.files, p)
			}
		}
		return "", nil

	case reMkdir.MatchString(cmd):
		return "", nil

	case reCat.MatchString(cmd):
		path := strings.Trim(reCat.FindStringSubmatch(cmd)[1], "'")
		body, ok := f.files[path]
		if !ok {
			return "", fmt.Errorf("cat: %s: no such file", path)
		}
		return body, nil

	case reSystemd.MatchString(cmd):
		return f.systemctl(reSystemd.FindStringSubmatch(cmd)[1])

	case reBash.MatchString(cmd):
		m := reBash.FindStringSubmatch(cmd)
		if _, ok := f.files[m[1]]; !ok {
			return "", fmt.Errorf("bash: %s: no such file", m[1])
		}
		if src := reRuncFlag.FindStringSubmatch(m[2]); src != nil {
			// what the real script's --runc branch does
			body, ok := f.files[src[1]]
			if !ok {
				return "", fmt.Errorf("provision-docker: --runc %s: no such file", src[1])
			}
			f.files["/usr/local/bin/drawbridge-runc"] = body
		}
		if strings.Contains(m[2], "--restart-docker") {
			// and its restart branch, reset-failed included — that ordering
			// is the whole of finding 1, so the fake has to have it too or
			// the fix would be untested.
			if _, err := f.systemctlDocker("reset-failed"); err != nil {
				return "", err
			}
			if _, err := f.systemctlDocker("restart"); err != nil {
				return "", err
			}
		}
		return "provision-docker: ok (docker 27.0.0, wrapper deadbeefcafe)\n", nil

	case cmd == "command -v docker":
		if !f.hasDocker {
			return "", fmt.Errorf("docker: not found")
		}
		return "", nil

	case reRestorecon.MatchString(cmd):
		path := reRestorecon.FindStringSubmatch(cmd)[1]
		if !f.hasRestorecon {
			return "", fmt.Errorf("restorecon: not found")
		}
		if _, ok := f.files[path]; !ok {
			return "", fmt.Errorf("restorecon: %s: no such file", path)
		}
		f.relabelled = append(f.relabelled, path)
		return "", nil

	case cmd == "echo restarted":
		return "restarted\n", nil
	}
	f.t.Fatalf("fakeGuest: unmodelled command %q", cmd)
	return "", nil
}

func (f *fakeGuest) systemctl(args string) (string, error) {
	args = strings.ReplaceAll(args, "'", "")
	if strings.HasSuffix(args, " docker") {
		return f.systemctlDocker(strings.TrimSuffix(args, " docker"))
	}
	switch {
	case strings.HasPrefix(args, "show -p Transient --value"):
		if f.transient {
			return "yes\n", nil
		}
		return "no\n", nil
	case args == "daemon-reload":
		return "", nil
	case strings.HasPrefix(args, "enable --now"):
		f.enabled, f.active = true, true
		return "", nil
	case strings.HasPrefix(args, "disable --now"):
		f.enabled, f.active = false, false
		return "", nil
	case strings.HasPrefix(args, "restart"):
		f.active = true
		return "", nil
	case strings.HasPrefix(args, "stop"):
		f.active, f.transient = false, false
		return "", nil
	case strings.HasPrefix(args, "reset-failed"):
		return "", nil
	case strings.HasPrefix(args, "is-active"):
		if f.active {
			return "active\n", nil
		}
		return "inactive\n", nil
	}
	f.t.Fatalf("fakeGuest: unmodelled systemctl %q", args)
	return "", nil
}

// systemctlDocker models the engine's unit, including the one behaviour that
// mattered live: once systemd's start limit has been hit, `restart` fails
// and `reset-failed` is what clears it.
func (f *fakeGuest) systemctlDocker(verb string) (string, error) {
	verb = strings.TrimSpace(verb)
	if !f.hasDocker {
		return "", fmt.Errorf("Unit docker.service not found")
	}
	switch {
	case verb == "reset-failed":
		f.dockerWedged = false
		return "", nil
	case verb == "restart", verb == "start":
		if f.dockerWedged {
			return "", fmt.Errorf("Job for docker.service failed because start-limit-hit")
		}
		if f.dockerBroken {
			return "", fmt.Errorf("Job for docker.service failed because the control process exited with error code")
		}
		f.dockerActive = true
		return "", nil
	case strings.HasPrefix(verb, "is-active"):
		if f.dockerActive {
			return "active\n", nil
		}
		return "", fmt.Errorf("inactive")
	}
	f.t.Fatalf("fakeGuest: unmodelled systemctl %q docker", verb)
	return "", nil
}

// execRestartDocker models restartDockerScript, which is multi-line and
// reports through a marker rather than an exit status. It never errors, for
// the same reason the script never exits non-zero.
func (f *fakeGuest) execRestartDocker() []byte {
	if !f.hasDocker {
		return []byte("drawbridge-docker=absent\n")
	}
	_, _ = f.systemctlDocker("reset-failed")
	if _, err := f.systemctlDocker("restart"); err != nil || !f.dockerActive {
		return []byte("drawbridge-docker=failed\n")
	}
	return []byte("drawbridge-docker=restarted\n")
}

// execRestartPodmanAPI models restartPodmanAPIScript: a marker, never an
// exit status, and `idle` for the socket-activated unit that is simply not
// running, which is the common case, not an edge.
func (f *fakeGuest) execRestartPodmanAPI() []byte {
	switch {
	case !f.hasPodmanAPI:
		return []byte("drawbridge-podman=absent\n")
	case !f.podmanAPIActive:
		return []byte("drawbridge-podman=idle\n")
	case f.podmanAPIBroken:
		return []byte("drawbridge-podman=failed\n")
	}
	f.podmanRestarted = true
	return []byte("drawbridge-podman=restarted\n")
}

// ran reports whether any executed script contained a substring — the shape
// most sequence assertions want.
func (f *fakeGuest) ran(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}
