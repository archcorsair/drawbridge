package doctor

// The impure half: everything that runs a process, opens a socket or reads a
// file. It is deliberately thin — it produces the values checks.go and
// auth.go classify, and makes no verdicts of its own.
//
// Every probe is deadline-bounded so doctor terminates against a wedged VM
// (§4): the global -timeout, 10 s per provider-shell script, 250 ms per
// socket dial. Every guest command is read-only, and doctor never spawns
// sudo on the Mac.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/podmanaddr"
	"github.com/archcorsair/drawbridge/internal/transport"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
	"github.com/archcorsair/drawbridge/internal/vmrecord"
)

// Probe bounds. The global one is the caller's; these are the per-probe
// ceilings §4 fixes.
const (
	shellTimeout = 10 * time.Second
	dialTimeout  = 250 * time.Millisecond
	execTimeout  = 5 * time.Second
)

// Options is the flag set, parsed.
type Options struct {
	VM         string // -vm, "" means "pick the single running vz instance"
	Subnet     netip.Prefix
	HWAddr     string
	Timeout    time.Duration
	CLIVersion string
	Now        time.Time
	// Probe is -probe: run check 8's active half-close probe. Off by default —
	// it is the one check that opens a session rather than reading state, and
	// it costs a ProbePostFINWindow wait.
	Probe bool
}

// Inputs is everything Classify needs. It is the seam the tests drive:
// a fixture Inputs produces a whole Report with no machine involved.
type Inputs struct {
	CLIVersion string
	RanAt      time.Time
	VM         string

	Providers    ProvidersInput
	GuestSkip    string
	Guest        GuestProbe
	Bind         AgentBind
	Resolution   ResolutionInput
	Route        RouteInput
	LocalNetwork LocalNetworkInput
	NEExtensions []NEExtension
	NEErr        string
	Daemon       DaemonInput
	Coexistence  CoexistenceInput
	Podman       PodmanInput
	LogTail      []string
	SkipVisible  SkipInput
	Auth         AuthInput
	HalfClose    HalfCloseProbe

	// Snapshot is the matched VM's daemon snapshot, embedded verbatim in the
	// report (§D5). Nil is the ordinary no-daemon case.
	Snapshot *introspect.State
}

// Classify runs the catalog in report order (§4: 1–11, then the auth block).
func Classify(in Inputs) Report {
	r := Report{CLIVersion: in.CLIVersion, RanAt: in.RanAt, VM: in.VM, Daemon: in.Snapshot}
	in.Providers.Podman = in.Podman
	in.Resolution.Podman = in.Podman
	in.Route.Podman = in.Podman.Target
	in.LocalNetwork.Podman = in.Podman.Target
	in.HalfClose.DirectPath = in.HalfClose.DirectPath || in.Podman.Target
	r.add(CheckProviders(in.Providers))
	r.add(CheckGuestPrereqs(in.Guest, in.GuestSkip, in.Podman))
	r.add(CheckAgent(in.Guest, in.Bind, in.CLIVersion, in.GuestSkip, in.Podman))
	r.add(CheckResolution(in.Resolution))
	r.add(CheckVZNATRoute(in.Route))
	r.add(CheckLocalNetwork(in.LocalNetwork))
	r.add(CheckNEFilter(in.NEExtensions, in.NEErr))
	r.add(CheckHalfClose(in.HalfClose))
	r.add(CheckDaemon(in.Daemon))
	r.add(CheckCoexistence(in.Coexistence))
	r.add(CheckSkipVisibility(in.SkipVisible))
	r.add(CheckAuth(in.Auth)...)
	return r
}

// effectiveTimeout applies the default and the -probe floor. The floor is not
// politeness: the half-close probe has to outlast the agent's liveness ping
// (probe.go), and a budget that cuts it short would report the killer
// signature for a perfectly healthy agent — a wrong answer, not a missing one.
func effectiveTimeout(o Options) time.Duration {
	t := o.Timeout
	if t <= 0 {
		t = 30 * time.Second
	}
	if o.Probe && t < ProbeBudget {
		t = ProbeBudget
	}
	return t
}

// guestScript is the one round trip into the guest: read-only commands only,
// answers as key=value lines, with the multi-line `ss` output fenced by
// markers. It rides on stdin, so nothing in it depends on how a provider
// shell quotes argv.
const guestScript = `
echo "kernel=$(uname -r 2>/dev/null)"
[ -r /sys/kernel/btf/vmlinux ] && echo btf=yes || echo btf=no
[ -e /sys/fs/cgroup/cgroup.controllers ] && echo cgroup2=yes || echo cgroup2=no
command -v systemctl >/dev/null 2>&1 && echo systemd=yes || echo systemd=no
sudo -n true >/dev/null 2>&1 && echo sudo=yes || echo sudo=no
[ -e /etc/drawbridge/provision.json ] && echo oci=yes || echo oci=no
echo "runc=$(runc --version 2>/dev/null | head -n1)"
echo "crun=$(crun --version 2>/dev/null | head -n1)"
echo "agent-active=$(systemctl is-active drawbridge-agent.service 2>/dev/null || true)"
echo "agent-enabled=$(systemctl is-enabled drawbridge-agent.service 2>/dev/null || true)"
echo "agent-transient=$(systemctl show -p Transient --value drawbridge-agent.service 2>/dev/null || true)"
echo "agent-version=$(cat /run/drawbridge-agent.version 2>/dev/null || true)"
echo "guest-ips=$(hostname -I 2>/dev/null)"
if [ -e /etc/drawbridge/transport-secret ]; then
  echo secret=present
  echo "secret-mode=$(stat -c %a /etc/drawbridge/transport-secret 2>/dev/null)"
  echo "secret-owner=$(stat -c %U:%G /etc/drawbridge/transport-secret 2>/dev/null)"
  echo "secret-size=$(stat -c %s /etc/drawbridge/transport-secret 2>/dev/null)"
  echo "secret-digest=$(sudo -n sha256sum /etc/drawbridge/transport-secret 2>/dev/null | cut -d' ' -f1)"
else
  echo secret=absent
fi
echo "selinux=$(getenforce 2>/dev/null || true)"
echo "unpriv_port=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || true)"
echo "containers_fs=$(findmnt -no FSTYPE --target /etc/containers 2>/dev/null || true)"
[ -e /etc/containers/containers.conf.d/50-drawbridge.conf ] && echo dropin=yes || echo dropin=no
if command -v podman >/dev/null 2>&1; then
  echo "oci_runtime=$(podman info --format '{{.Host.OCIRuntime.Path}}' 2>/dev/null || true)"
fi
echo ss-begin
ss -H -ltn 2>/dev/null || true
echo ss-end
if command -v curl >/dev/null 2>&1; then
  gv=$(curl -sS --max-time 3 http://192.168.127.1/services/forwarder/all 2>/dev/null) || gv=""
  [ -n "$gv" ] || echo "gvproxy-err=gvproxy's in-guest API did not answer"
else
  gv=""
  echo "gvproxy-err=no curl in the guest"
fi
echo gvproxy-begin
echo "$gv"
echo gvproxy-end
echo journal-begin
journalctl -u drawbridge-agent.service -n 200 --no-pager 2>/dev/null | grep -F "gvproxy:" | tail -n 3 || true
echo journal-end
`

// target is the VM doctor is diagnosing.
type target struct {
	Ref  vmprovider.Ref
	Inst vmprovider.Instance
}

// Gather runs every probe. The error return is the exit-code-2 case — doctor
// itself could not gather — and is deliberately narrow: everything a check
// can describe becomes a Finding instead.
func Gather(ctx context.Context, o Options) (Inputs, error) {
	o.Timeout = effectiveTimeout(o)
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	in := Inputs{CLIVersion: o.CLIVersion, RanAt: o.Now}

	// A malformed -vm is a bad flag, not a diagnosis: reject it before any
	// probe runs, whatever else is on this Mac.
	if strings.TrimSpace(o.VM) != "" {
		if _, err := vmprovider.ParseRef(o.VM); err != nil {
			return in, err
		}
	}

	euid0 := os.Geteuid() == 0
	// The installed daemon's own arguments, read before target selection so
	// the podman branch can report root's pinned -agent without re-reading
	// the plist. Cheap and exec-free (install.Query parses the plist).
	st0 := install.Query()

	// --- 1. providers ------------------------------------------------------
	providers := vmprovider.Detect()
	byTag := map[string]vmprovider.Provider{}
	for _, p := range providers {
		tag := providerTag(p)
		in.Providers.Providers = append(in.Providers.Providers, tag)
		byTag[tag] = p
		insts, err := p.List()
		if err != nil {
			if errors.Is(err, vmprovider.ErrRootScoped) {
				in.Providers.RootScoped = true
			}
			in.Providers.ListErrors = append(in.Providers.ListErrors, fmt.Sprintf("%s: %v", tag, err))
			continue
		}
		in.Providers.Instances = append(in.Providers.Instances, insts...)
	}

	// --- 2. target selection (mirrors `up`; under euid 0, the root daemon) --
	var (
		tgt  target
		skip string
	)
	if euid0 {
		// limactl refuses euid 0, so there is no instance list to select
		// from. Mirror the root daemon instead: -vm (else the installed
		// daemon's -vm, else drawbridged's default) through
		// ParseRef — the one vmprovider symbol root may touch — and let the
		// lease db resolve it. Without this, `sudo drawbridge doctor` skips
		// the very probe it exists to run.
		tgt, skip = rootTarget(o.VM, st0.VM)
		in.VM = tgt.Ref.Provider + ":" + tgt.Ref.Instance
	} else {
		var err error
		tgt, skip, err = selectTarget(o.VM, in.Providers.Instances)
		if err != nil {
			if len(providers) == 0 {
				return in, err
			}
			skip = err.Error()
		}
		if skip == "" {
			in.VM = tgt.Ref.Provider + ":" + tgt.Ref.Instance
		}
	}
	in.GuestSkip = skip
	// The root run has a target to resolve and probe even though every
	// guest-shell check must skip; resSkip is the narrower gate for the
	// checks that only need the target, not the shell.
	haveTarget := skip == "" || euid0
	resSkip := skip
	if euid0 {
		resSkip = ""
	}

	running := 0
	for _, i := range in.Providers.Instances {
		if i.Running && i.Attachable {
			running++
		}
	}

	// --- 3. parallel probes ------------------------------------------------
	var (
		wg       sync.WaitGroup
		netstat  execResult
		sysext   execResult
		fwdKnown bool
		fwd      vmprovider.Forwarding
		fwdErr   string
		res      limaaddr.Resolution
		resRan   bool
		snaps    []*introspect.Snapshot
		snapErrs []error
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		netstat = runCommand(ctx, "netstat", "-rn", "-f", "inet")
	}()
	// The enrichment tier (§3.3): every socket that exists, dialed with the
	// 250 ms budget. Nothing here is required — no daemon is a state doctor
	// must diagnose, not a state that stops it.
	wg.Add(1)
	go func() {
		defer wg.Done()
		snaps, snapErrs = introspect.FetchAll(introspect.DialTimeout)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		sysext = runCommand(ctx, "systemextensionsctl", "list")
	}()

	if skip == "" {
		p := byTag[tgt.Ref.Provider]
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := shellScript(ctx, p, tgt.Ref.Instance, guestScript)
			if err != nil {
				in.Guest = GuestProbe{Err: fmt.Sprintf("the guest shell failed: %v", err)}
				return
			}
			in.Guest = ParseGuestProbe(string(out))
		}()
		if f, ok := p.(vmprovider.Forwarder); ok && tgt.Ref.Provider != vmprovider.ProviderPodman {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := f.Forwarding(tgt.Ref.Instance)
				if err != nil {
					fwdErr = err.Error()
					return
				}
				fwdKnown, fwd = true, got
			}()
		}
	}
	if haveTarget {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res = resolveTarget(tgt.Ref, o, euid0)
			resRan = true
		}()
	}
	wg.Wait()

	// The matched daemon is the one serving *this* VM: a snapshot from a
	// daemon attached to something else says nothing about the target, and
	// tier-2 evidence from it would be a misdiagnosis.
	matched := matchSnapshot(snaps, tgt.Ref)

	in.Bind = BindOf(in.Guest.Listeners, in.Guest.GuestIPs)
	in.Podman = podmanInput(tgt, in.Guest, in.Providers.Instances, euid0)
	in.NEExtensions = ParseSystemExtensions(sysext.Out)
	if sysext.Err != "" {
		in.NEErr = sysext.Err
	}
	if tgt.Ref.Provider == vmprovider.ProviderPodman {
		// One read of gvproxy's table per run: the guest script already
		// fetched it (check 3 wants the transport's own entry), so asking
		// the Forwarder interface again would be a second round trip whose
		// answer could differ from the one check 3 classified.
		fwdKnown, fwd, fwdErr = podmanForwarding(tgt.Ref.Instance, in.Guest)
	}
	in.Coexistence = CoexistenceInput{Known: fwdKnown, Fwd: fwd, Err: fwdErr, Skip: skip,
		BindFailed: entriesInState(matched, introspect.EntryBindFailed)}
	in.Resolution = ResolutionInput{
		Res:            res,
		Ran:            resRan,
		AgentListening: in.Bind.Reachable(),
		RunningVMs:     running,
		Skip:           resSkip,
		GuestUp:        skip == "",
		GuestUnknown:   euid0,
	}

	// --- 4. the vzNAT candidate, and everything that needs it --------------
	subnet := o.Subnet
	if !subnet.IsValid() {
		subnet = netip.MustParsePrefix(limaaddr.DefaultSubnet)
	}
	candidate := vznatCandidate(in.Guest.GuestIPs, res, subnet)

	// The probe first: its result is what makes a missing ARP entry either
	// meaningful or stale-cache noise.
	in.LocalNetwork = localNetworkInput(ctx, candidate, res, in, subnet, resSkip)
	in.LocalNetwork.Root = tier2Evidence(matched)

	route := RouteInput{
		Subnet:      subnet,
		NetstatOut:  netstat.Out,
		NetstatErr:  netstat.Err,
		CandidateIP: candidate,
		GuestUp:     haveTarget,
		ProbeOK:     in.LocalNetwork.UserProbe == ProbeOK,
		ProbeNote:   in.LocalNetwork.ProbeNote,
	}
	if candidate != "" {
		arp := runCommand(ctx, "arp", "-n", candidate)
		route.ARPOut, route.ARPErr = arp.Out, arp.Err
	}
	// The whole table, for the subnet-wide emptiness signal that corroborates
	// the crutch verdict (a single candidate line can age out innocently).
	route.ARPTableOut = runCommand(ctx, "arp", "-an").Out
	in.Route = route

	// --- 5. Mac-side daemon state ------------------------------------------
	st := st0
	in.LogTail = st.LogTail
	dv, err := install.InstalledVersion()
	daemon := DaemonInput{Status: st, CLIVersion: o.CLIVersion, Snapshots: snaps}
	for _, e := range snapErrs {
		daemon.SnapshotProblems = append(daemon.SnapshotProblems, e.Error())
	}
	switch {
	case err == nil:
		daemon.InstalledVersion = dv
	case errors.Is(err, install.ErrNotInstalled):
	default:
		daemon.VersionErr = err.Error()
	}
	in.Daemon = daemon

	// --- 6. the enrichment tier, fed into the checks that have one ---------
	in.SkipVisible = SkipInput{LogTail: st.LogTail}
	if matched != nil {
		in.Snapshot = &matched.State
		in.SkipVisible.Known = true
		in.SkipVisible.Daemon = matched.Path
		in.SkipVisible.Skip = matched.State.Mirror.Skip
		in.SkipVisible.Skipped = entriesInState(matched, introspect.EntrySkipped)
	}

	// --- 7. auth state comparison ------------------------------------------
	in.Auth = authInput(tgt, skip, in.Guest, st.LogTail, res.Source)
	if matched != nil {
		in.Auth.Evidence = append(in.Auth.Evidence, MatchAuthRing(matched.State.RecentRefusals)...)
		in.Auth.Sessions = Sessions{
			MirrorUp:    matched.State.Mirror.SessionUp,
			SyncUp:      matched.State.Sync.SessionUp,
			MirrorSince: matched.State.Mirror.Since,
			SyncSince:   matched.State.Sync.Since,
		}
	}

	// --- 8. the one active probe, opt-in and last ---------------------------
	// Last because it is the only probe that spends real time (it outlasts the
	// agent's liveness ping), and because it dials the endpoint check 4
	// resolved — whichever that turned out to be.
	in.HalfClose = halfCloseInput(ctx, o, res, resRan, in)
	return in, nil
}

// resolveTarget dispatches resolution the way the daemon does.
//
// A podman ref must never reach the lease db: gvproxy is user-mode and
// writes no lease record, so limaaddr would match `lima-<name>` (Target's
// own default) and resolve some other VM entirely, which is exactly what
// doctor did before this branch existed, reporting the Lima dev VM's
// forwarded 127.0.0.1:4777 as a podman machine's endpoint.
//
// The root run does not read the record, for the reason drawbridged does
// not: it is a user-writable file, and `install` pinned the endpoint into
// the plist so root never has to. Check 4 reports the pin instead.
func resolveTarget(ref vmprovider.Ref, o Options, euid0 bool) limaaddr.Resolution {
	if ref.Provider != vmprovider.ProviderPodman {
		return limaaddr.ResolveTarget(limaaddr.Target{
			VM:        ref.Instance,
			Provider:  ref.Provider,
			LeaseName: ref.LeaseName,
			LimaHome:  ref.LimaHome,
			Subnet:    o.Subnet,
			HWAddr:    o.HWAddr,
		}, ControlPort)
	}
	if euid0 {
		ep, _ := install.InstalledAgent()
		return limaaddr.Resolution{
			Endpoint: ep,
			Source:   podmanaddr.Source,
			Note: "running as root: the per-VM record is user-writable and is not read here; " +
				"this is the endpoint `drawbridge install` pinned into the daemon's plist",
		}
	}
	return podmanaddr.Resolve(ref)
}

// halfCloseInput runs check 8's probe, or explains why it did not. Nothing
// here decides anything: the transcript goes to CheckHalfClose.
func halfCloseInput(ctx context.Context, o Options, res limaaddr.Resolution, resRan bool, in Inputs) HalfCloseProbe {
	if !o.Probe {
		return HalfCloseProbe{Skip: "the active half-close probe is opt-in; pass -probe to run it."}
	}
	if !resRan || res.Endpoint == "" {
		return HalfCloseProbe{Skip: "no endpoint was resolved, so there is nothing to probe (see checks 1 and 4)."}
	}
	target := HalfCloseTarget{
		Endpoint: res.Endpoint,
		Source:   res.Source,
		VM:       in.VM,
		NEFilter: in.LocalNetwork.NEFilterNames,
	}
	// The same per-VM secret path the daemon would use — derived once, in
	// authInput, so doctor cannot disagree with itself about where it lives.
	if in.Auth.Mac.Present && !in.Auth.Mac.Malformed {
		target.SecretFile = in.Auth.Mac.Path
	}
	return RunHalfCloseProbe(ctx, target)
}

// matchSnapshot picks the answering daemon that serves the target VM. The
// payload names its own vm, so this is a match rather than a guess (§D3);
// provider+instance is the canonical pair, and Ref.Spec is only the user's
// spelling of it.
func matchSnapshot(snaps []*introspect.Snapshot, ref vmprovider.Ref) *introspect.Snapshot {
	if ref.Provider == "" {
		return nil
	}
	for _, s := range snaps {
		if s == nil || !s.Usable {
			continue
		}
		vm := s.State.VM
		if vm.Provider == ref.Provider && vm.Instance == ref.Instance {
			return s
		}
		if vm.Provider == "" && vm.Ref != "" && vm.Ref == ref.Spec {
			return s
		}
	}
	return nil
}

// entriesInState is the mirror table filtered to one state — the exact
// vantage checks 10 and 11 use instead of scraping log prose.
func entriesInState(s *introspect.Snapshot, state string) []introspect.MirrorEntry {
	if s == nil || !s.Usable {
		return nil
	}
	var out []introspect.MirrorEntry
	for _, e := range s.State.Mirror.Entries {
		if e.State == state {
			out = append(out, e)
		}
	}
	return out
}

// tier2Evidence is §D1's tier 2: a root daemon that resolved vznat-direct
// and has a live session is the root vantage reaching the guest, observed
// passively with no new probe. Only an *ok* reading flows — a root snapshot
// showing a fallback source or dead sessions is not evidence of failure,
// because the daemon re-resolves on its own cadence and a stale failure
// would misdiagnose. Anything short of the ok reading stays "unknown", which
// is the branch that prints the tier-1 instruction.
func tier2Evidence(s *introspect.Snapshot) RootEvidence {
	if s == nil || !s.Usable || s.State.EUID != 0 {
		return RootEvidence{Kind: "unknown"}
	}
	// Both vznat sources are the direct path (the check-4 rule); a root
	// daemon always reports vznat-leases — the lease db is its only legal
	// candidate source — so accepting only vznat-direct would deny tier-2
	// evidence to the one daemon the tier was designed around.
	src := s.State.Resolution.Source
	if src != limaaddr.SourceVZNATDirect && src != limaaddr.SourceVZNATLeases {
		return RootEvidence{Kind: "unknown"}
	}
	if !s.State.Mirror.SessionUp && !s.State.Sync.SessionUp {
		return RootEvidence{Kind: "unknown"}
	}
	return RootEvidence{
		Kind:  "tier2",
		Probe: ProbeOK,
		Note: fmt.Sprintf("the root daemon at %s resolved %s (%s) with a live session",
			s.Path, s.State.Resolution.Endpoint, s.State.Resolution.Source),
	}
}

// providerTag names a provider the way a -vm value does.
func providerTag(p vmprovider.Provider) string {
	type tagger interface{ Provider() string }
	if t, ok := p.(tagger); ok {
		return t.Provider()
	}
	return "unknown"
}

// rootTarget is the euid-0 half of target selection. There is no instance
// list to consult — limactl is user-scoped — so root doctor names its target
// the way the root daemon does: an explicit -vm, else the installed daemon's
// own -vm (installedVM, read from the root-owned 0644 plist; Query already
// parsed it), else drawbridged's built-in default, resolved later from the
// lease db. Defaulting to the installed VM is what makes the root run mirror
// the daemon it exists to stand in for: before, a colima user's
// `sudo drawbridge doctor` probed lima:drawbridge (audit 2026-10-28 M22).
//
// ParseRef cannot fail on an explicit -vm (validated before any probe ran)
// or on the constant. An installed value that does not parse (a hand edit)
// falls through to the default and says so. The skip string is the
// guest-shell checks' reason; resolution and the root probe still run
// against the ref.
func rootTarget(arg, installedVM string) (target, string) {
	arg = strings.TrimSpace(arg)
	whose := ""
	if arg == "" {
		if r, err := vmprovider.ParseRef(installedVM); err == nil && strings.TrimSpace(installedVM) != "" {
			return target{Ref: r}, rootSkip(r, ", the installed daemon's VM")
		}
		arg = install.DefaultVM
		whose = ", drawbridged's default VM (no installed daemon names one)"
	}
	ref, _ := vmprovider.ParseRef(arg)
	return target{Ref: ref}, rootSkip(ref, whose)
}

func rootSkip(ref vmprovider.Ref, whose string) string {
	return fmt.Sprintf(
		"limactl is user-scoped and refuses euid 0, so the provider and guest halves run only as your own user — "+
			"this run carries the root half of the discriminator against %s:%s%s (-vm overrides)",
		ref.Provider, ref.Instance, whose)
}

// selectTarget mirrors `up`'s step 1: an explicit `provider:name` wins, else
// the single running vz instance; ambiguity is not an error but a reason for
// the guest-side checks to skip.
func selectTarget(arg string, insts []vmprovider.Instance) (target, string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		var ok []vmprovider.Instance
		for _, i := range insts {
			if i.Running && i.Attachable {
				ok = append(ok, i)
			}
		}
		switch len(ok) {
		case 0:
			return target{}, "no running VM to attach to: start one, then re-run (`drawbridge doctor -vm provider:name` names one explicitly)", nil
		case 1:
			ref, err := vmprovider.ParseRef(ok[0].Provider + ":" + ok[0].Name)
			if err != nil {
				return target{}, "", err
			}
			return target{Ref: ref, Inst: ok[0]}, "", nil
		}
		names := make([]string, 0, len(ok))
		for _, i := range ok {
			names = append(names, i.Provider+":"+i.Name)
		}
		return target{}, "several VMs are running (" + strings.Join(names, ", ") + ") — pass -vm provider:name", nil
	}

	// A named VM keeps its Ref even when the guest-side checks have to skip:
	// the Mac-side half of the auth comparison is derived from the Ref alone
	// and is worth reporting for a VM that is merely stopped.
	ref, err := vmprovider.ParseRef(arg)
	if err != nil {
		return target{}, "", err
	}
	for _, i := range insts {
		if i.Provider != ref.Provider || i.Name != ref.Instance {
			continue
		}
		if !i.Running {
			return target{Ref: ref}, fmt.Sprintf("%s:%s is not running", i.Provider, i.Name), nil
		}
		if !i.Attachable {
			return target{Ref: ref}, fmt.Sprintf("%s:%s runs on %s: %s", i.Provider, i.Name, i.VMType,
				firstNonEmpty(i.AttachNote, "no host-reachable guest IP")), nil
		}
		return target{Ref: ref, Inst: i}, "", nil
	}
	return target{Ref: ref}, fmt.Sprintf("no %s instance named %q on this Mac", ref.Provider, ref.Instance),
		fmt.Errorf("no %s instance named %q", ref.Provider, ref.Instance)
}

// vznatCandidate is the address check 5 and check 6 talk about: the guest's
// own vmnet address when the guest told us, else whatever the resolver
// settled on if that was a direct path.
func vznatCandidate(guestIPs []string, res limaaddr.Resolution, subnet netip.Prefix) string {
	for _, ip := range guestIPs {
		addr, err := netip.ParseAddr(ip)
		if err == nil && addr.Is4() && subnet.Contains(addr) {
			return ip
		}
	}
	if strings.HasPrefix(res.Source, "vznat") {
		if host, _, err := net.SplitHostPort(strings.TrimPrefix(res.Endpoint, "tcp://")); err == nil {
			return host
		}
	}
	return ""
}

// localNetworkInput runs doctor's own unprivileged dial and packages the
// discriminator's inputs. It never runs sudo: the tier-1 branch is an
// instruction printed to the user, and under euid 0 this run *is* the root
// probe (§D1).
func localNetworkInput(ctx context.Context, candidate string, res limaaddr.Resolution, in Inputs, subnet netip.Prefix, skip string) LocalNetworkInput {
	out := LocalNetworkInput{
		Subnet:          subnet,
		EUID0:           os.Geteuid() == 0,
		NEFilterPresent: len(in.NEExtensions) > 0,
		AgentListening:  in.Bind.Reachable(),
		Root:            RootEvidence{Kind: "unknown"},
		Skip:            skip,
		VM:              in.VM,
	}
	for _, e := range in.NEExtensions {
		out.NEFilterNames = append(out.NEFilterNames, e.BundleID)
	}
	if candidate == "" {
		out.UserProbe = ProbeSkipped
		return out
	}
	out.ProbeAddr = net.JoinHostPort(candidate, strconv.Itoa(ControlPort))

	// The resolver already connected to this address if it reported a direct
	// source: re-probing would only add a second dial with the same answer.
	if res.Source == limaaddr.SourceVZNATDirect || res.Source == limaaddr.SourceVZNATLeases {
		out.UserProbe = ProbeOK
		out.ProbeNote = "the resolver's own probe connected (source " + res.Source + ")"
		return out
	}

	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", out.ProbeAddr)
	if err != nil {
		out.UserProbe = ProbeFail
		out.ProbeNote = classifyDialError(err)
		return out
	}
	conn.Close()
	out.UserProbe = ProbeOK
	return out
}

// classifyDialError reports what the dial did, not what it means: on macOS
// 27.0b4 the Local Network denial presents as a silent timeout, so errno is
// an input to check 6, never its verdict.
func classifyDialError(err error) string {
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		return "dial: ENETUNREACH (the route table cannot carry a packet there — a gateway static whose gateway has no connected route to resolve through does this; check 5 classifies)"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "dial: EHOSTUNREACH (no route, or the host-side gate refused it)"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "dial: ECONNREFUSED (something answered and refused — nothing is listening there)"
	case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT), isTimeout(err):
		return "dial: timed out with no response — the macOS 27.0b4 Local Network denial presents exactly like this"
	}
	return "dial: " + err.Error()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// authInput builds the state comparison. The Mac side is read directly (as
// the file's owner); the guest side arrives as a stat plus a `sudo -n
// sha256sum` digest, because the guest file is 0600 root:root.
func authInput(tgt target, skip string, g GuestProbe, logTail []string, source string) AuthInput {
	in := AuthInput{
		VM:               tgt.Ref.Spec,
		Evidence:         MatchAuthLog(logTail),
		ResolutionSource: source,
		Guest:            SecretFile{Path: transportauth.GuestPath},
	}
	if in.VM == "" {
		in.VM = "<vm>"
	}

	switch {
	case tgt.Ref.Provider == "":
		// No VM was selected, so there is no per-VM secret path to derive.
		// Naming a file assembled from an empty ref would be worse than
		// saying nothing.
		in.MacSkip = firstNonEmpty(skip, "no VM selected, so no per-VM secret path to compare")
		in.Mac = SecretFile{}
	default:
		macPath, err := transportauth.PathForRef(tgt.Ref)
		if err != nil {
			in.Mac = SecretFile{Path: "(underivable)", Malformed: true, Why: err.Error()}
		} else {
			in.Mac = macSecretState(macPath)
		}
	}

	switch {
	case skip != "":
		in.GuestSkip = skip
	case !g.Ran:
		in.GuestSkip = firstNonEmpty(g.Err, "the guest did not answer")
	case !g.Secret.Present:
		in.Guest.Present = false
	default:
		in.Guest.Present = true
		in.Guest.Mode = g.Secret.Mode
		in.Guest.Owner = g.Secret.Owner
		in.Guest.Size = g.Secret.Size
		in.Guest.Digest = g.Secret.Digest
		// 64 hex characters plus a newline. The bytes stay in the guest, so
		// the size is the only format evidence available from here.
		if g.Secret.Size != 0 && g.Secret.Size != 2*transportauth.SecretLen+1 {
			in.Guest.Malformed = true
			in.Guest.Why = fmt.Sprintf("%d bytes, want %d (64 hex characters plus a newline)", g.Secret.Size, 2*transportauth.SecretLen+1)
		}
		if g.Secret.Digest == "" {
			in.Guest.Why = firstNonEmpty(in.Guest.Why, "`sudo -n sha256sum` was refused in the guest, so the digests could not be compared")
		}
	}
	return in
}

// macSecretState stats, reads and format-checks the Mac half. The digest is
// taken over the *canonical* rendering, which is what `up`'s convergence
// step compares against the guest's `sha256sum` — so doctor and `up` agree
// on what "the same secret" means even when a file's whitespace differs.
func macSecretState(path string) SecretFile {
	s := SecretFile{Path: path}
	fi, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.Malformed, s.Why = true, err.Error()
		}
		return s
	}
	s.Present = true
	s.Mode = fmt.Sprintf("%o", fi.Mode().Perm())
	s.Size = fi.Size()
	s.Owner = ownerName(fi)

	sec, err := transportauth.Load(path)
	if err != nil {
		s.Malformed, s.Why = true, err.Error()
		return s
	}
	sum := sha256Of(sec.Format())
	s.Digest = sum
	return s
}

func ownerName(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}

// --- process and shell plumbing --------------------------------------------

type execResult struct {
	Out string
	Err string
}

// runCommand runs a read-only Mac-side command. A missing binary is not an
// error a user needs to act on — the check reports `skip` with the reason.
func runCommand(ctx context.Context, name string, args ...string) execResult {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		// Partial output still classifies: `arp` exits non-zero on a miss and
		// prints the miss on stdout.
		return execResult{Out: string(out), Err: fmt.Sprintf("%s %s: %v", name, strings.Join(args, " "), err)}
	}
	return execResult{Out: string(out)}
}

// shellScript runs a read-only script in the guest, bounded.
//
// vmprovider.Provider.Shell takes no context, so a wedged limactl leaves this
// goroutine parked until the process exits. That is the honest bound
// available without widening the provider interface, which this phase does
// not touch — and doctor's own deadline still fires.
func shellScript(ctx context.Context, p vmprovider.Provider, inst, script string) ([]byte, error) {
	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := p.Shell(inst, strings.NewReader(script), "sh")
		ch <- result{out, err}
	}()
	t := time.NewTimer(shellTimeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-t.C:
		return nil, fmt.Errorf("no answer within %s", shellTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// sha256Of matches what `sha256sum` prints in the guest — the comparison
// happens between a digest computed here and one computed there, and the
// secret never crosses.
func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// The podman half of the gather (docs/podman.md §7)
// ---------------------------------------------------------------------------

// podmanInput assembles everything the podman branches classify. Reads only:
// the machine's own config file, the Mac-side record, and what the guest
// script already brought back.
//
// Root is the case this function is shaped around. `install` pins the
// endpoint into the plist so root never opens the user's record, and doctor
// must not undo that by reading it here, so the euid-0 path reports the pin
// and stops, which is also exactly what the daemon is dialing.
func podmanInput(tgt target, g GuestProbe, insts []vmprovider.Instance, euid0 bool) PodmanInput {
	if tgt.Ref.Provider != vmprovider.ProviderPodman {
		return PodmanInput{}
	}
	pm := PodmanInput{Target: true, Instance: tgt.Ref.Instance, EUID0: euid0}

	for _, i := range insts {
		if i.Provider == vmprovider.ProviderPodman && i.Name != tgt.Ref.Instance {
			pm.Dropin.Machines = append(pm.Dropin.Machines, i.Provider+":"+i.Name)
		}
	}

	// The machine's own config: exec-free, and the same source `install`
	// reads, so doctor and the install refusal cannot disagree about what
	// the machine is.
	home, err := machineConfigHome()
	if err != nil {
		pm.ConfigErr = err.Error()
	} else if cfg, err := vmprovider.ReadPodmanMachineConfig(home, tgt.Ref.Instance); err != nil {
		pm.ConfigErr = err.Error()
	} else {
		pm.Config = cfg
	}

	if euid0 {
		if a, ok := install.InstalledAgent(); ok {
			pm.PinnedAgent = a
		}
	} else {
		pm.RecordPath, _ = vmrecord.Path(tgt.Ref)
		rec, err := vmrecord.Read(tgt.Ref)
		switch {
		case err == nil:
			pm.Record, pm.RecordPresent = rec, true
			if pm.ConfigErr == "" {
				pm.Disagreements = rec.Disagreements(pm.Config)
			}
		case errors.Is(err, vmrecord.ErrAbsent):
		default:
			pm.RecordErr = err.Error()
		}
	}

	pm.Publish = publishEvidence(g)
	pm.Dropin.Present = g.Dropin
	pm.Dropin.Path = guestbin.DropinPath
	pm.Dropin.WrapperPath = guestbin.WrapperPath(guestbin.EnginePodman)
	pm.Dropin.RuntimePath = g.OCIRuntime
	pm.Dropin.FS = strings.TrimSpace(g.ContainersFS)
	pm.Dropin.Shared = sharedContainersFS[pm.Dropin.FS]
	if pm.Dropin.Present && pm.Dropin.Shared {
		if p, err := macDropinPath(); err == nil {
			pm.Dropin.MacPath = p
		}
	}
	return pm
}

// sharedContainersFS are the filesystem types that mean /etc/containers is
// not the guest's own directory but a mount of the Mac's podman config dir
// (docs/podman.md §"7.4 results").
var sharedContainersFS = map[string]bool{"virtiofs": true, "9p": true, "nfs": true, "nfs4": true, "fuse.sshfs": true}

// macDropinPath names the Mac-side file only when it is really there.
// Podman's config directory can be moved, and a guessed path in a report
// about a file the reader did not expect is worse than no path.
func macDropinPath() (string, error) {
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

// machineConfigHome is the home the machine configs live under: the invoking
// user's, or SUDO_USER's when this run is root. Root must never read its own
// (there is nothing there) and must never run `podman machine`.
func machineConfigHome() (string, error) {
	if os.Geteuid() == 0 {
		if u := os.Getenv("SUDO_USER"); u != "" {
			if acct, err := user.Lookup(u); err == nil {
				return acct.HomeDir, nil
			}
		}
		return "", fmt.Errorf("running as root with no SUDO_USER to resolve a home from, so the machine's own config is not readable here")
	}
	return os.UserHomeDir()
}

// publishEvidence pulls branch A's two pieces out of the guest script's
// output: the agent's own journal lines, and the forward table entry that
// carries the transport.
func publishEvidence(g GuestProbe) PublishEvidence {
	p := PublishEvidence{Journal: g.Journal}
	if g.GvproxyErr != "" {
		p.Err = g.GvproxyErr
		return p
	}
	if strings.TrimSpace(g.Gvproxy) == "" {
		p.Err = "gvproxy's forward table was empty"
		return p
	}
	var entries []struct {
		Local  string `json:"local"`
		Remote string `json:"remote"`
	}
	if err := json.Unmarshal([]byte(g.Gvproxy), &entries); err != nil {
		p.Err = "gvproxy's forward table did not parse: " + err.Error()
		return p
	}
	p.Known = true
	for _, e := range entries {
		if _, port, err := net.SplitHostPort(e.Remote); err == nil && port == strconv.Itoa(transport.DefaultAgentPort) {
			p.Local, p.Remote = e.Local, e.Remote
			return p
		}
	}
	return p
}

// podmanForwarding classifies the same table check 3 read, so the gvproxy
// API is asked exactly once per doctor run.
func podmanForwarding(inst string, g GuestProbe) (bool, vmprovider.Forwarding, string) {
	if g.GvproxyErr != "" {
		return false, vmprovider.Forwarding{Instance: inst, Provider: vmprovider.ProviderPodman}, g.GvproxyErr
	}
	fwd, err := vmprovider.ParseGvproxyForwards(inst, "drawbridge-gvproxy=ok\n"+g.Gvproxy)
	if err != nil {
		return false, fwd, err.Error()
	}
	return true, fwd, ""
}
