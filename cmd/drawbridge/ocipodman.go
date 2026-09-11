package main

// `up --oci` and `down` on a podman guest (docs/podman.md §6.2, §6.3).
//
// The whole registration is one file that did not exist: podman reads
// /etc/containers/containers.conf.d/*.conf, so there is no merge into
// anything the user owns, no formatter to round-trip, and no "before" to
// record: only a digest of what we wrote, which is what makes `down`'s
// deletion exact rather than hopeful.
//
// What is shared with the docker path, deliberately: the wrapper binary
// (one build, installed under the runtime's name), the state file, and the
// "reset-failed, then confirm with is-active, and report through a marker
// rather than an exit status" discipline for restarting the engine's
// service. What is not shared: the provisioning script, which is Docker's
// and stays Docker's (§5.3).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/archcorsair/drawbridge/internal/guestbin"
)

// provisionOCIPodman installs the wrapper, writes the drop-in that points
// podman's `crun` runtime at it, and nudges the API service.
//
// Ordering is the failure posture: the wrapper first, the drop-in second.
// The reverse would leave a registration pointing at a path nothing
// installed. Harmless here, because the drop-in's second element is the
// real crun and podman falls back to it, but "harmless because of a
// fallback" is not an ordering to rely on.
func provisionOCIPodman(g *guest, wrapper []byte, pf preflight, sockOwner string, otherPodmanMachines []string) error {
	wrapperPath := guestbin.WrapperPath(EnginePodman)
	changedWrapper, err := g.pushBinary(wrapper, wrapperPath)
	if err != nil {
		return err
	}
	if changedWrapper {
		fmt.Fprintf(g.out, "drawbridge: installed %s\n", wrapperPath)
	} else {
		fmt.Fprintf(g.out, "drawbridge: %s already current\n", wrapperPath)
	}

	want, err := guestbin.DropinBytes(pf.CrunPath)
	if err != nil {
		return err
	}
	cur, exists, err := g.readFile(guestbin.DropinPath)
	if err != nil {
		return err
	}
	changed := !exists || string(cur) != string(want)
	if changed {
		// writeFile creates the parent, which matters here: a stock Fedora
		// CoreOS podman machine has no containers.conf.d at all.
		if err := g.writeFile(want, guestbin.DropinPath, "0644"); err != nil {
			return err
		}
		fmt.Fprintf(g.out, "drawbridge: wrote %s (podman's crun runtime now execs %s)\n", guestbin.DropinPath, wrapperPath)
		noteSharedContainersConf(g, pf, otherPodmanMachines)
	}

	// The state file is rewritten whenever it no longer describes what is on
	// disk, unlike the docker path, which keeps the first one.
	//
	// The reason those differ is not style. Docker's state carries
	// DaemonJSONBefore, content that only existed before the first `up`, so
	// re-recording it would overwrite the truth with the merged file.
	// Podman's carries nothing but a description of what we wrote, so a
	// stale one is simply wrong: it would make `down` read "edited since
	// `up`" about a file `up` itself had just replaced.
	st := guestbin.PodmanState{
		Version:      guestbin.StateVersionPodman,
		Engine:       guestbin.EnginePodman,
		RuntimePath:  wrapperPath,
		DropinPath:   guestbin.DropinPath,
		DropinSHA256: sha256Hex(want),
		Rootful:      pf.Rootful,
		OCISockOwner: sockOwner,
	}
	blob, err := guestbin.EncodePodmanState(st)
	if err != nil {
		return err
	}
	if have, _, err := g.readFile(guestbin.ProvisionPath); err != nil {
		return err
	} else if string(have) != string(blob) {
		if err := g.writeFile(blob, guestbin.ProvisionPath, "0644"); err != nil {
			return err
		}
	}

	// Only the socket-activated API service caches the runtime path; the
	// podman CLI re-reads its config per invocation, so there is no daemon
	// to bounce and nothing to lose if the service is not running.
	if changed {
		reportPodmanRestart(g, g.restartPodmanAPI(pf.Rootful, pf.User), "--oci")
	}
	return nil
}

// ociSockOwner decides whether the agent's unit carries `-oci-sock-owner`,
// and for whom.
//
// Rootful machines get nothing: the runtime is root and the socket's 0600
// root is already right. Rootless machines get the machine's own login user,
// because that is the uid podman, conmon and crun all run as, and a wrapper
// that cannot connect execs crun untouched, silently and by design, which is
// exactly why this must not be left to chance.
//
// The `!oci` branch is the one that is easy to get wrong: re-running plain
// `drawbridge up` on a machine that was provisioned with `--oci` must not
// quietly drop the flag and disable arbitration, so an existing version-2
// state file's answer is carried forward. `down` is what removes it.
func ociSockOwner(g *guest, pf preflight, oci bool) (string, error) {
	if pf.Rootful || pf.User == "" || pf.User == "root" {
		return "", nil
	}
	if oci {
		return pf.User, nil
	}
	st, have, err := readPodmanState(g)
	if err != nil || !have {
		return "", err
	}
	return st.OCISockOwner, nil
}

// readPodmanState reads /etc/drawbridge/provision.json when it is a
// version-2 (podman) one. A version-1 file is a docker guest's and is not
// this function's business; a newer one is an error, the same refusal
// `down` gives.
func readPodmanState(g *guest) (guestbin.PodmanState, bool, error) {
	blob, have, err := g.readFile(guestbin.ProvisionPath)
	if err != nil || !have {
		return guestbin.PodmanState{}, false, err
	}
	v, err := guestbin.PeekStateVersion(blob)
	if err != nil {
		return guestbin.PodmanState{}, false, err
	}
	if v != guestbin.StateVersionPodman {
		return guestbin.PodmanState{}, false, nil
	}
	st, err := guestbin.DecodePodmanState(blob)
	if err != nil {
		return guestbin.PodmanState{}, false, err
	}
	return st, true, nil
}

// ---------------------------------------------------------------------------
// The API-service restart (docs/podman.md §6.2)
// ---------------------------------------------------------------------------

// podmanRestart is the outcome of asking the guest to reload its API
// service. `idle` is the common case, not an edge: podman.service is
// socket-activated and spends most of its life not running, and a service
// that is not running has no cached runtime path to invalidate.
type podmanRestart int

const (
	podmanFailed podmanRestart = iota
	podmanRestarted
	podmanIdle
	podmanAbsent
)

// restartPodmanAPIScript reports through an explicit marker and always exits
// 0, for the reasons restartDockerScript does: an exit status through a
// provider shell is one `|| true` away from being lost, and a bare "did it
// print something" check breaks on any stray systemctl output. The restart
// is confirmed with `is-active` rather than believed.
//
// `reset-failed` before the restart is AGENTS.md's rule applied verbatim:
// two restarts inside systemd's start-limit burst window leave a unit in
// `failed`, after which `restart` does nothing at all.
//
// $SC is the systemd instance to aim at: plain `systemctl` for a rootful
// machine, and `systemctl --user -M <user>@.host` for a rootless one, where
// the API service lives in the login user's own manager and root reaches it
// through machinectl's host container.
const restartPodmanAPIScript = `
SC=%s
U=podman.service
$SC cat $U >/dev/null 2>&1 || { echo drawbridge-podman=absent; exit 0; }
$SC is-active --quiet $U || { echo drawbridge-podman=idle; exit 0; }
$SC reset-failed $U >/dev/null 2>&1 || true
if $SC restart $U >/dev/null 2>&1 && $SC is-active --quiet $U; then
  echo drawbridge-podman=restarted
else
  echo drawbridge-podman=failed
fi
exit 0
`

func (g *guest) restartPodmanAPI(rootful bool, user string) podmanRestart {
	sc := "systemctl"
	if !rootful {
		if user == "" {
			// No user to aim at and not rootful: there is no manager this
			// can address, and guessing one would restart the wrong thing.
			return podmanAbsent
		}
		sc = "systemctl --user -M " + user + "@.host"
	}
	out, err := g.sudoSh(fmt.Sprintf(restartPodmanAPIScript, sc))
	if err != nil {
		return podmanFailed
	}
	switch {
	case strings.Contains(out, "drawbridge-podman=restarted"):
		return podmanRestarted
	case strings.Contains(out, "drawbridge-podman=idle"):
		return podmanIdle
	case strings.Contains(out, "drawbridge-podman=absent"):
		return podmanAbsent
	default:
		return podmanFailed
	}
}

// reportPodmanRestart says what happened, and only says something alarming
// when it is.
//
// A failure here is not fatal in either direction: the podman *CLI* reads
// its config per invocation, so `podman run` already sees the new
// registration (or, after `down`, the absence of it). What a stale API
// service affects is clients of the socket (docker-compose through
// podman's docker-compatible endpoint, Podman Desktop), so the message
// names the one command that fixes it rather than failing the run.
func reportPodmanRestart(g *guest, r podmanRestart, phase string) {
	switch r {
	case podmanRestarted:
		fmt.Fprintf(g.out, "drawbridge: restarted podman.service (the API socket's cached runtime path)\n")
	case podmanIdle:
		fmt.Fprintf(g.out, "drawbridge: podman.service is not running; nothing to reload\n")
	case podmanAbsent:
		// No API service in this guest at all. The CLI is the only client.
	default:
		fmt.Fprintf(g.out, "drawbridge: WARNING: podman.service did not restart after the %s change.\n"+
			"  `podman run` is unaffected (the CLI re-reads its config every invocation), but a client\n"+
			"  of the API socket (docker-compose, Podman Desktop) keeps the old runtime path until it does.\n"+
			"  In the guest:  systemctl --user reset-failed podman.service && systemctl --user restart podman.service\n", phase)
	}
}

// ---------------------------------------------------------------------------
// `down`'s half
// ---------------------------------------------------------------------------

// revertOCIPodman deletes the drop-in, if it is still ours to delete, and
// reloads the API service.
//
// The wrapper binary is not removed here: `down` removes both wrapper names
// after this returns, which is the same ordering the docker path relies on
// (revert the registration while the binary it names still exists).
func revertOCIPodman(g *guest, st guestbin.PodmanState) error {
	path := st.DropinPath
	if path == "" {
		path = guestbin.DropinPath
	}
	cur, exists, err := g.readFile(path)
	if err != nil {
		return err
	}
	if !exists {
		cur = nil
	}
	del, reason := guestbin.RevertDropin(st, cur)
	if reason != "" {
		fmt.Fprintf(g.out, "drawbridge: %s\n", reason)
	}
	if !del {
		return nil
	}
	if _, err := g.sudoSh("rm -f " + shquote(path)); err != nil {
		return fmt.Errorf("removing %s: %w", path, err)
	}
	fmt.Fprintf(g.out, "drawbridge: removed %s\n", path)
	// The socket owner doubles as the systemd manager to aim at, and that is
	// not a coincidence: on a rootless machine both are the machine's login
	// user, the one `up` recorded. On a rootful machine it is empty and
	// Rootful sends the restart at the system manager instead.
	reportPodmanRestart(g, g.restartPodmanAPI(st.Rootful, st.OCISockOwner), "revert")
	return nil
}

// sharedFS are the filesystem types that mean /etc/containers is not the
// guest's own directory. A podman machine image ships an
// `etc-containers.mount` unit that virtiofs-mounts the Mac's podman config
// directory there, which is podman's own design (registries, auth and
// policy follow the user into every machine) and was not anticipated by
// §6.2.
var sharedFS = map[string]bool{"virtiofs": true, "9p": true, "nfs": true, "nfs4": true, "fuse.sshfs": true}

// noteSharedContainersConf says what the drop-in actually is on a podman
// machine, because it is not what its path suggests.
//
// The file itself is unchanged and the registration works exactly as
// designed: `podman info` reads the wrapper path, which is the acceptance
// line. What is different is scope: one file on the Mac rather than one
// file per guest, read by every podman machine and by the Mac's own podman
// client. That is worth a sentence at the moment it is written, because the
// next person to wonder where it came from will be looking at their Mac.
//
// The Mac-side path is named only when it is actually found there. Podman's
// config directory can be moved, and a guessed path in a message about a
// file you did not expect is worse than no path at all.
func noteSharedContainersConf(g *guest, pf preflight, others []string) {
	if !sharedFS[strings.TrimSpace(pf.ContainersFS)] {
		return
	}
	fmt.Fprintf(g.out, "drawbridge: note: the guest's %s is a %s mount of your Mac's podman config directory\n"+
		"  (podman machine's own etc-containers.mount), so that drop-in is one file on the Mac, shared by\n"+
		"  every podman machine and read by the Mac's podman client too. `drawbridge down` on any of them\n"+
		"  removes it, and a machine without the wrapper falls back to the drop-in's second entry, the real crun.\n",
		"/etc/containers", pf.ContainersFS)
	if p, err := macContainersDropin(); err == nil {
		fmt.Fprintf(g.out, "  On this Mac it is %s\n", p)
	}
	warnOtherMachines(g, others)
}

// warnOtherMachines says who else this registration reaches.
//
// A warning and never a refusal. The registration is correct for every
// machine that has the wrapper, and a machine that does not falls back to
// the drop-in's second entry, the real crun (verified live, 7.4). So there
// is nothing here to stop; there is only a fact a user cannot discover from
// the path they were shown, and being told it once at the moment it becomes
// true is the whole remedy.
func warnOtherMachines(g *guest, others []string) {
	if len(others) == 0 {
		return
	}
	fmt.Fprintf(g.out, "drawbridge: WARNING: %d other podman machine(s) on this Mac read that same file: %s\n"+
		"  They will exec %s too, and fall back to the real crun where it is not installed.\n"+
		"  `drawbridge down` on ANY machine removes the registration for all of them.\n",
		len(others), strings.Join(others, ", "), guestbin.WrapperPath(EnginePodman))
}

// macContainersDropin returns the Mac-side path of the drop-in when it is
// where podman's conventional config directory would put it, and an error
// otherwise. Existence is the whole test: this is evidence, not a guess.
func macContainersDropin() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	p := filepath.Join(home, ".config", "containers", "containers.conf.d", filepath.Base(guestbin.DropinPath))
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}
