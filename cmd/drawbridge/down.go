package main

// `drawbridge down` — take drawbridge back out of a guest
// (docs/ergonomics.md §4.1).
//
// Idempotent and total: a guest that never had drawbridge is a no-op
// success, and one that had `up --oci` gets its /etc/docker/daemon.json back
// byte-for-byte (internal/guestbin/provision.go, and §8's Phase 4 verify,
// which asserts exactly that).
//
// Ordering is the whole design. daemon.json is reverted and docker restarted
// *before* the wrapper binary is removed: the other order leaves an engine
// whose default-runtime points at a path that no longer exists, which is a
// guest where no container starts at all.

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func runDown(args []string) int {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	instance, err := parsePositional(fs, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge down: %v\n", err)
		return 2
	}

	providers := vmprovider.Detect()
	if len(providers) == 0 {
		fmt.Fprintf(os.Stderr, "drawbridge down: %v\n", noCandidateError(nil))
		return 1
	}
	sel, err := pickInstance(instance, listAll(providers, os.Stderr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge down: %v\n", err)
		return 1
	}

	g := &guest{p: vmprovider.ForRef(sel.Ref), inst: sel.Ref.Instance, out: os.Stdout}
	if err := down(g, sel); err != nil {
		fmt.Fprintf(os.Stderr, "drawbridge down: %v\n", err)
		return 1
	}
	return 0
}

// down removes the agent, its unit, the wrapper and the state directory, and
// reverts the `--oci` daemon.json edit if there was one.
func down(g *guest, sel selection) error {
	fmt.Fprintf(g.out, "drawbridge: removing drawbridge from %s\n", qualify(sel.Instance))

	// 1. Stop supervising the agent. `disable --now` covers the persistent
	//    unit; a transient unit from `just agent-up` has no unit file to
	//    disable but does stop, so both are tried and neither is required to
	//    have been there.
	g.try("systemctl disable --now " + shquote(guestbin.UnitName))
	g.try("systemctl stop " + shquote(guestbin.UnitName))
	g.try("systemctl reset-failed " + shquote(guestbin.UnitName))
	if _, had, err := g.readFile(guestbin.UnitPath); err != nil {
		return err
	} else if had {
		if _, err := g.sudoSh("rm -f " + shquote(guestbin.UnitPath)); err != nil {
			return fmt.Errorf("removing %s: %w", guestbin.UnitPath, err)
		}
		fmt.Fprintf(g.out, "drawbridge: removed %s\n", guestbin.UnitPath)
	}
	g.try("systemctl daemon-reload")

	// 2. Revert the --oci changes, if any, while the wrapper still exists.
	if err := revertOCI(g); err != nil {
		return err
	}

	// 3. Binaries and state last: nothing references them any more.
	for _, p := range []string{
		guestbin.GuestPath(guestbin.NameAgent),
		guestbin.GuestPath(guestbin.NameRunc),
	} {
		if _, had, err := g.readFile(p); err != nil {
			return err
		} else if had {
			if _, err := g.sudoSh("rm -f " + shquote(p)); err != nil {
				return fmt.Errorf("removing %s: %w", p, err)
			}
			fmt.Fprintf(g.out, "drawbridge: removed %s\n", p)
		}
	}
	// The version file is a tmpfs artifact of the running agent; removing it
	// keeps a subsequent `doctor` from reporting a version for an agent that
	// is no longer installed.
	g.try("rm -f /run/drawbridge-agent.version")
	// StateDir covers the transport secret too, so its guest half dies with
	// everything else and needs no removal code of its own.
	if _, err := g.sudoSh("rm -rf " + shquote(guestbin.StateDir)); err != nil {
		return fmt.Errorf("removing %s: %w", guestbin.StateDir, err)
	}
	fmt.Fprintf(g.out, "drawbridge: done — the guest has no drawbridge files left\n")
	// The Mac half is deliberately kept: `down` is guest-scoped, so a
	// recreated VM plus `up` re-adopts the same identity, and an installed
	// root daemon's plist keeps pointing at a file that exists
	// (docs/transport-auth.md §5).
	if p, err := transportauth.PathForRef(sel.Ref); err == nil {
		fmt.Fprintf(g.out, "drawbridge: kept the Mac-side transport secret %s\n"+
			"  (`down` is guest-scoped; re-running `up` re-adopts the same identity. Delete it to rotate.)\n", p)
	}
	return nil
}

// revertOCI undoes what `up --oci` recorded, and only that.
//
// No state file means no `--oci` run to undo: `down` leaves daemon.json
// alone rather than removing a `drawbridge` runtime entry it cannot prove it
// wrote. That is also what makes `down` safe after the dev flow — `just
// vm-docker` provisions the same wrapper and writes no state file, and it is
// not `down`'s business to revert the developer's own VM setup.
func revertOCI(g *guest) error {
	blob, have, err := g.readFile(guestbin.ProvisionPath)
	if err != nil {
		return err
	}
	if !have {
		return nil
	}
	st, err := guestbin.DecodeState(blob)
	if err != nil {
		return err
	}

	cur, exists, err := g.readFile(guestbin.DaemonJSONPath)
	if err != nil {
		return err
	}
	if !exists {
		cur = nil
	}
	out, remove, changed, err := guestbin.Revert(cur, st)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	switch {
	case remove:
		// `up --oci` created the file; a revert that left an empty object
		// behind would be a change, not a revert.
		if _, err := g.sudoSh("rm -f " + shquote(guestbin.DaemonJSONPath)); err != nil {
			return fmt.Errorf("removing %s: %w", guestbin.DaemonJSONPath, err)
		}
		fmt.Fprintf(g.out, "drawbridge: removed %s (it did not exist before `up --oci`)\n", guestbin.DaemonJSONPath)
	default:
		if err := g.writeFile(out, guestbin.DaemonJSONPath, "0644"); err != nil {
			return err
		}
		fmt.Fprintf(g.out, "drawbridge: restored %s\n", guestbin.DaemonJSONPath)
	}

	// docker is holding the old config; restart it, but only because the
	// file actually changed. A guest with no docker (the wrapper was
	// installed and the engine later removed) is not an error at this point.
	switch g.restartDocker() {
	case dockerRestarted:
		fmt.Fprintf(g.out, "drawbridge: restarted docker\n")
	case dockerAbsent:
		// Nothing to reload; the config revert stands on its own.
	default:
		// Loud, because of what happens next: the wrapper binary is about to
		// be deleted, and a dockerd still running the merged config has
		// default-runtime pointing at it. That guest starts no containers at
		// all, and the only clue would have been a container failing to run
		// hours later.
		fmt.Fprintf(g.out, "drawbridge: WARNING: %s was reverted but docker did not restart.\n"+
			"  The running engine is still on the old config, whose default runtime is the wrapper\n"+
			"  this command is about to remove — no container will start until docker reloads.\n"+
			"  Run in the guest:  sudo systemctl reset-failed docker && sudo systemctl restart docker\n",
			guestbin.DaemonJSONPath)
	}
	return nil
}

// dockerRestart is the outcome of asking the guest to reload its engine.
type dockerRestart int

const (
	dockerFailed dockerRestart = iota
	dockerRestarted
	dockerAbsent
)

// restartDockerScript reports its result in a marker line rather than an
// exit status, and always exits 0.
//
// Two reasons. Exit status through a provider shell is one `|| true` away
// from being lost, and this failure must never be silent — see the caller.
// And a bare "did the command print something" check breaks on any stray
// systemctl output, so the marker is explicit and the restart is confirmed
// with `is-active` rather than believed: `systemctl restart` can return
// success for a unit that then dies in its post-start.
//
// `reset-failed` first for the same reason the provisioning script does it:
// systemd's start rate limit puts docker.service into `failed` after two
// restarts inside the burst window, and from there `restart` does nothing at
// all (observed live on colima). On a healthy unit it is a no-op.
const restartDockerScript = `
command -v docker >/dev/null 2>&1 || { echo drawbridge-docker=absent; exit 0; }
systemctl reset-failed docker >/dev/null 2>&1 || true
if systemctl restart docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
  echo drawbridge-docker=restarted
else
  echo drawbridge-docker=failed
fi
exit 0
`

func (g *guest) restartDocker() dockerRestart {
	out, err := g.sudoSh(restartDockerScript)
	if err != nil {
		return dockerFailed
	}
	switch {
	case strings.Contains(out, "drawbridge-docker=restarted"):
		return dockerRestarted
	case strings.Contains(out, "drawbridge-docker=absent"):
		return dockerAbsent
	default:
		return dockerFailed
	}
}
