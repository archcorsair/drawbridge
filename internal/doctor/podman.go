package doctor

// The podman branches of the catalog (docs/podman.md §7), as the same kind
// of pure classifier as everything else in checks.go: one input struct, no
// process, no socket, no file.
//
// The catalog numbering does not change. What changes is that several checks
// now have two vocabularies, because "vz" and "vzNAT" are Lima words that
// mean nothing to a podman machine: its transport is a gvproxy-published
// loopback port, there is no vmnet route to inspect and no Local Network
// gate to be denied by. The rule throughout is that a Lima or Colima run
// sees byte-identical text.

import (
	"fmt"
	"strings"

	"github.com/archcorsair/drawbridge/internal/vmprovider"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
)

// PodmanInput is everything the podman branches classify. Target is the
// gate: false leaves every check exactly as it was.
type PodmanInput struct {
	Target   bool // the selected VM is a podman machine
	Instance string

	// Config is the machine's own config file, read rather than exec'd.
	// Root may read it too (through the SUDO_USER home, as `install` does),
	// which is what keeps "root never runs `podman machine`" true.
	Config    vmprovider.MachineConfig
	ConfigErr string

	// Record is the Mac-side per-VM record `up` wrote, and Disagreements is
	// Record.Disagreements(Config): the same comparison `install` refuses
	// on, reported here rather than enforced.
	Record        vmrecord.Record
	RecordPresent bool
	RecordPath    string
	RecordErr     string
	Disagreements []string

	// EUID0 marks the root run. The record is a user-owned file and root
	// does not read it (`install` pins the endpoint into the plist precisely
	// so root never has to), so check 4 reports PinnedAgent instead.
	EUID0       bool
	PinnedAgent string

	// Publish is branch A's evidence: the agent's own journal lines and the
	// entry in gvproxy's forward table that carries the transport.
	Publish PublishEvidence

	// Dropin is the `--oci` registration, and the fact that on a podman
	// machine it is not where its path suggests (docs/podman.md §"7.4
	// results").
	Dropin DropinEvidence
}

// PublishEvidence is what makes "the agent is up" and "the Mac can reach it"
// two different statements on a podman machine. The guest agent owns its own
// forward: it posts the expose at every start, so a machine that came back
// without the publish has an agent that is running and unreachable.
type PublishEvidence struct {
	Known   bool     // gvproxy's table was read
	Err     string   // why it was not
	Local   string   // the Mac-side host:port the transport is published on
	Remote  string   // the guest-side host:port it forwards to
	Journal []string // the agent's own `gvproxy:` lines, most recent last
}

// DropinEvidence is the `--oci` registration as it actually exists.
//
// Shared is the finding 7.4 landed on: a podman machine mounts the Mac's own
// podman config directory onto the guest's /etc/containers, so the drop-in
// is one file on the Mac that every machine reads. Doctor's job is to say
// so and name who else is registered, never to change it.
type DropinEvidence struct {
	Present     bool
	Path        string
	Shared      bool   // /etc/containers is a shared mount, not the guest's own directory
	FS          string // the filesystem type that made it shared
	MacPath     string // the Mac-side path, when it is really there
	RuntimePath string // `podman info --format {{.Host.OCIRuntime.Path}}`
	WrapperPath string // where `up --oci` installs the wrapper
	Machines    []string
}

// providerEvidence renders check 1's per-instance lines for a podman
// machine.
//
// "Running on libkrun" is not a complaint. libkrun is podman 6's default
// macOS provider, the whole 7.0 spike ran on it, and both it and applehv are
// attachable (docs/podman.md §"7.0 results", the §4.2 amendment), so the
// "no host-reachable guest IP" wording that a qemu Lima instance earns must
// never appear here.
func podmanProviderEvidence(i vmprovider.Instance, pm PodmanInput) string {
	line := fmt.Sprintf("%s:%s running on %s", i.Provider, i.Name, i.VMType)
	if !pm.Target || pm.Instance != i.Name || pm.ConfigErr != "" {
		return line + " (gvproxy user-mode networking; the transport is a published loopback port)"
	}
	rootful := "rootless"
	if pm.Config.Rootful {
		rootful = "rootful"
	}
	if pm.Config.SSH.Port != 0 {
		return fmt.Sprintf("%s, %s, ssh port %d", line, rootful, pm.Config.SSH.Port)
	}
	return line + ", " + rootful
}

// podmanStoppedNote is the sentence that keeps a stopped podman machine from
// reading as trouble.
//
// Only one podman machine runs at a time, across providers: starting a
// second fails with "only one VM can be active at a time" (verified live,
// docs/podman.md §"7.0 results"). So a Mac with three machines has two
// stopped ones by construction, and a check that called that a problem would
// be wrong on every correctly configured Mac.
const podmanStoppedNote = "only one podman machine runs at a time, so other machines being stopped is the normal state, not a fault"

// CheckPodmanOCI is the shared-drop-in report (check 2's podman half).
//
// It is an `info` and never a `warn`: the registration works, `podman info`
// is the acceptance line, and a machine that has the drop-in without the
// wrapper falls back to the real crun (verified live). What the user needs
// is to know where the file is when they go looking, and who else reads it.
func podmanOCIEvidence(d DropinEvidence) []string {
	if !d.Present {
		return nil
	}
	out := []string{"--oci: " + d.Path + " registers " + d.WrapperPath + " as podman's crun runtime"}
	if d.RuntimePath != "" {
		line := "`podman info` runtime path: " + d.RuntimePath
		if d.WrapperPath != "" && d.RuntimePath != d.WrapperPath {
			line += " (NOT the wrapper: the drop-in is present but podman is not reading it)"
		}
		out = append(out, line)
	}
	if !d.Shared {
		return out
	}
	line := "that path is on a " + d.FS + " mount of this Mac's own podman config directory (podman machine's etc-containers.mount), " +
		"so the drop-in is ONE file on the Mac, shared by every podman machine and read by the Mac's podman client too"
	out = append(out, line)
	if d.MacPath != "" {
		out = append(out, "on this Mac: "+d.MacPath)
	}
	if len(d.Machines) > 0 {
		out = append(out, "podman machines that therefore also see it: "+strings.Join(d.Machines, ", ")+
			" (a machine without the wrapper falls back to the drop-in's second entry, the real crun)")
	}
	return out
}

// podmanAgentEvidence is check 3's branch-A addition: the agent being active
// is not the same claim as the Mac being able to reach it.
func podmanAgentEvidence(p PublishEvidence) []string {
	var out []string
	out = append(out, p.Journal...)
	switch {
	case !p.Known:
		out = append(out, "gvproxy's forward table could not be read: "+firstNonEmpty(p.Err, "no reason given"))
	case p.Local == "":
		out = append(out, "gvproxy forwards nothing to the guest's transport port")
	default:
		out = append(out, "gvproxy: "+p.Local+" -> "+p.Remote+" (the endpoint this Mac dials)")
	}
	return out
}

// podmanPublished reports whether the transport publish is actually in
// place. Unknown (the table could not be read) is deliberately not "missing":
// a check that failed because it could not look is a skip, not a verdict.
func podmanPublished(p PublishEvidence) (ok, known bool) {
	if !p.Known {
		return false, false
	}
	return p.Local != "", true
}

// podmanResolutionOK is check 4's verdict for a podman machine.
//
// A gvproxy-published loopback endpoint is not a fallback. It is the only
// path a podman machine has, chosen at design time (docs/podman.md §3.2), so
// the `warn` a Lima run earns for landing on the forwarder would be wrong
// here: there is nothing better it failed to reach.
func podmanResolutionEvidence(pm PodmanInput) []string {
	var out []string
	if pm.EUID0 {
		if pm.PinnedAgent != "" {
			out = append(out, "running as root: the per-VM record is a user-owned file and is not read here; "+
				"the installed daemon's pinned -agent is "+pm.PinnedAgent)
		} else {
			out = append(out, "running as root: the per-VM record is a user-owned file and is not read here, "+
				"and no daemon is installed to report a pinned -agent from")
		}
		return out
	}
	switch {
	case pm.RecordErr != "":
		out = append(out, "the per-VM record could not be read: "+pm.RecordErr)
	case !pm.RecordPresent:
		out = append(out, "no per-VM record at "+pm.RecordPath+": `drawbridge up` writes it and the daemon reads it")
	default:
		out = append(out, "record: "+pm.RecordPath+" -> "+pm.Record.Endpoint+" (source "+pm.Record.Transport+")")
	}
	if pm.ConfigErr != "" {
		out = append(out, "the machine's own config could not be read: "+pm.ConfigErr)
	}
	for _, d := range pm.Disagreements {
		out = append(out, "record vs `podman machine inspect`: "+d)
	}
	return out
}

// podmanRecordRemedy is the one command that heals a record the machine no
// longer matches. Both halves, in order, because the daemon's plist carries
// the endpoint the record named and re-running `up` alone leaves root
// pointing at the old one.
const podmanRecordRemedy = "the machine no longer matches what `drawbridge up` recorded; re-run `drawbridge up <vm>` and then\n" +
	"`sudo drawbridge install -vm <vm>` (the installed daemon pins the endpoint the record named)"

// podmanCoexistenceNote is check 10's podman wording.
//
// The tradeoff is genuinely different from Lima's, and saying Lima's would
// be wrong rather than merely vague: a published container is bridged, has
// its own netns, is excluded by the tracker's host_netns_inum check, and was
// never a mirror candidate. So nothing is being taken away from drawbridge.
// What a publication can do is hold a Mac-side port that a *host-netns*
// guest listener would otherwise have been mirrored onto.
var podmanCoexistenceNote = []string{
	"these are podman's own `-p` publications through gvproxy. A published container is bridged: it has its own " +
		"network namespace, the agent's netns check excludes it, and it was never a mirror candidate.",
	"so the overlap is narrow: a publication only matters when a host-netns guest listener wants the same Mac-side port, " +
		"in which case the mirror bind loses the race and that port degrades to gvproxy (reachable, but without drawbridge's " +
		"synchronous EADDRINUSE arbitration).",
}

const podmanCoexistenceRemedy = "nothing to fix unless a port collides: `podman run --network host` needs no `-p` at all with drawbridge attached,\n" +
	"which is the whole point of it: drop the `-p` and the listener is mirrored with full semantics"
