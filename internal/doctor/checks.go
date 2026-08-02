package doctor

// The check catalog (docs/doctor.md §4), as pure classifiers: one exported
// function per entry, each taking injected probe results. Nothing in this
// file runs a process, opens a socket or reads a file — gather.go does that,
// and the split is what makes the whole catalog testable from fixtures.

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/archcorsair/drawbridge/internal/install"
	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/limaaddr"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// Catalog IDs. Stable: `-json` consumers and the acceptance matrix key on
// them.
const (
	IDProviders    = "providers"
	IDGuestPrereqs = "guest-prereqs"
	IDAgent        = "agent"
	IDResolution   = "resolution"
	IDVZNATRoute   = "vznat-route"
	IDLocalNetwork = "local-network"
	IDNEFilter     = "ne-filter"
	IDHalfClose    = "half-close-probe"
	IDDaemon       = "daemon"
	IDCoexistence  = "coexistence"
	IDSkipVisible  = "skip-visibility"
)

// ControlPort is the agent's transport port — the one guest listener every
// check that talks about reachability is talking about.
const ControlPort = 4777

// AgentUnit is the systemd unit `up` installs. `just agent-up`'s transient
// unit deliberately shares the name (one agent per guest by construction),
// so there is exactly one unit to interrogate and Transient= is what tells
// the two apart.
const AgentUnit = "drawbridge-agent.service"

// lsMonitorCaveat is the standing warning attached to every non-ok state of
// check 6. Two independent observations, both earned the hard way: LS 6.5's
// Network Monitor shows nothing for flows its own filter drops, and the
// 27.0b4 Local Network gate drops flows before any filter sees them.
const lsMonitorCaveat = "caveat: absence from Little Snitch's Network Monitor is not exoneration — " +
	"LS 6.5's monitor shows nothing for flows its own filter drops, and the macOS 27.0b4 Local Network gate " +
	"drops flows before any filter sees them."

// discriminatorInstruction is the tier-1 branch, printed verbatim whenever
// doctor needs the root vantage. Doctor never spawns sudo itself (§D1): the
// user runs this and re-reads.
const discriminatorInstruction = "run `sudo drawbridge doctor` and compare: root-ok + user-fail ⇒ Local Network gate; " +
	"both-fail ⇒ content filter or network fault."

// ---------------------------------------------------------------------------
// 1. providers
// ---------------------------------------------------------------------------

// ProvidersInput is what Detect()/List() reported.
type ProvidersInput struct {
	Providers  []string // detected provider tags, in Detect order
	Instances  []vmprovider.Instance
	ListErrors []string
	RootScoped bool // a List() failed with vmprovider.ErrRootScoped
}

// CheckProviders classifies the provider landscape: something to attach to,
// or the one command that creates it.
func CheckProviders(in ProvidersInput) Finding {
	f := Finding{ID: IDProviders, Title: "VM providers"}
	if len(in.Providers) == 0 {
		f.Status = StatusFail
		f.Title = "VM providers — none installed"
		f.Evidence = append(f.Evidence, "no lima or colima state directory on this Mac")
		f.Remedy = "drawbridge attaches to a VM it does not create; install a provider and start a vz VM:\n" +
			"  colima start --vm-type vz --cpu 4 --memory 8      # Colima (Docker CLI included)\n" +
			"  limactl start --vm-type vz template://ubuntu-lts  # Lima"
		return f
	}
	f.Evidence = append(f.Evidence, "providers: "+strings.Join(in.Providers, ", "))
	for _, e := range in.ListErrors {
		f.Evidence = append(f.Evidence, "warning: "+e)
	}

	// The euid-0 posture: providers exist but their instances are not
	// listable as root, which is scoping, not absence — "nothing running"
	// would misread a Mac whose VM is up.
	if in.RootScoped && len(in.Instances) == 0 {
		f.Status = StatusSkip
		f.Title = "VM providers — instances not listable as root"
		f.Evidence = append(f.Evidence,
			"limactl is user-scoped (its state lives in the invoking user's LIMA_HOME); the provider and guest halves run only as your own user.",
			"this run still carries the root half of the discriminator — checks 4-6 resolve the target from the DHCP lease db, the way the root daemon does.")
		return f
	}

	var runningVZ, runningQEMU, stopped []vmprovider.Instance
	for _, i := range in.Instances {
		switch {
		case !i.Running:
			stopped = append(stopped, i)
		case strings.EqualFold(i.VMType, "vz"):
			runningVZ = append(runningVZ, i)
		default:
			runningQEMU = append(runningQEMU, i)
		}
	}
	for _, i := range runningVZ {
		mac := i.MACAddress
		if mac == "" {
			mac = "no vzNAT interface"
		}
		f.Evidence = append(f.Evidence, fmt.Sprintf("%s:%s running on vz, MAC %s", i.Provider, i.Name, mac))
	}
	for _, i := range stopped {
		f.Evidence = append(f.Evidence, fmt.Sprintf("%s:%s stopped (%s)", i.Provider, i.Name, i.VMType))
	}
	for _, i := range runningQEMU {
		f.Evidence = append(f.Evidence, fmt.Sprintf("%s:%s running on %s — no host-reachable guest IP", i.Provider, i.Name, i.VMType))
	}

	switch {
	case len(runningQEMU) > 0:
		f.Status = StatusWarn
		f.Title = fmt.Sprintf("VM providers — %d running vz, %d on qemu", len(runningVZ), len(runningQEMU))
		f.Remedy = "qemu's user-mode networking gives the guest no address this Mac can dial, so drawbridge cannot attach:\n  " +
			strings.Join(vzSwitchHints(runningQEMU), "\n  ")
	case len(runningVZ) == 0:
		f.Status = StatusWarn
		f.Title = "VM providers — installed, nothing running"
		f.Remedy = "start a VM, then re-run:\n  " + strings.Join(startHints(stopped), "\n  ")
	default:
		f.Status = StatusOK
		f.Title = fmt.Sprintf("VM providers — %d running vz instance(s)", len(runningVZ))
	}
	f.Data = map[string]any{"runningVZ": len(runningVZ), "runningQEMU": len(runningQEMU), "stopped": len(stopped)}
	return f
}

func vzSwitchHints(insts []vmprovider.Instance) []string {
	out := make([]string, 0, len(insts))
	for _, i := range insts {
		if i.Provider == vmprovider.ProviderColima {
			profile := strings.TrimPrefix(i.Name, "colima-")
			if profile == "colima" {
				out = append(out, "colima stop && colima start --vm-type vz")
				continue
			}
			out = append(out, fmt.Sprintf("colima stop -p %s && colima start -p %s --vm-type vz", profile, profile))
			continue
		}
		out = append(out, fmt.Sprintf("limactl stop %s && limactl edit %s   # set vmType: vz, then: limactl start %s", i.Name, i.Name, i.Name))
	}
	return out
}

func startHints(insts []vmprovider.Instance) []string {
	if len(insts) == 0 {
		return []string{
			"colima start --vm-type vz --cpu 4 --memory 8      # Colima (Docker CLI included)",
			"limactl start --vm-type vz template://ubuntu-lts  # Lima",
		}
	}
	out := make([]string, 0, len(insts))
	for _, i := range insts {
		if i.Provider == vmprovider.ProviderColima {
			profile := strings.TrimPrefix(i.Name, "colima-")
			if profile == "colima" {
				out = append(out, "colima start")
				continue
			}
			out = append(out, "colima start -p "+profile)
			continue
		}
		out = append(out, "limactl start "+i.Name)
	}
	return out
}

// ---------------------------------------------------------------------------
// The guest probe (one read-only script; §4's "key=value lines" contract)
// ---------------------------------------------------------------------------

// GuestProbe is the parsed output of the one read-only script doctor runs in
// the guest. Every field is injected into a classifier below; nothing here
// interprets.
type GuestProbe struct {
	Ran bool   // the script executed and produced output
	Err string // why it did not

	Kernel  string
	BTF     bool
	CGroup2 bool
	Systemd bool
	Sudo    bool

	OCI  bool   // /etc/drawbridge/provision.json present: the VM was provisioned --oci
	Runc string // `runc --version` first line
	Crun string // `crun --version` first line

	AgentActive    string // systemctl is-active
	AgentEnabled   string // systemctl is-enabled
	AgentTransient bool   // the `just agent-up` unit holds the name
	AgentVersion   string

	GuestIPs  []string
	Listeners []Listener

	Secret GuestSecret
}

// GuestSecret is what the guest half of the transport secret looks like from
// outside root: a stat anyone can take, and a digest only `sudo -n` can.
type GuestSecret struct {
	Present bool
	Mode    string // octal, as `stat -c %a` prints it
	Owner   string // user:group
	Size    int64
	Digest  string // sha256 of the file's bytes; "" when sudo -n was refused
}

// Listener is one row of `ss -H -ltn`.
type Listener struct {
	Addr string
	Port int
}

// ParseGuestProbe reads the script's key=value lines plus the marked `ss`
// block. Unknown keys are ignored so a newer script against an older parse
// is a missing check rather than a crash — the parsePreflight discipline.
func ParseGuestProbe(out string) GuestProbe {
	g := GuestProbe{Ran: true}
	inSS := false
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimRight(raw, "\r")
		switch strings.TrimSpace(line) {
		case "ss-begin":
			inSS = true
			continue
		case "ss-end":
			inSS = false
			continue
		}
		if inSS {
			if l, ok := parseSSLine(line); ok {
				g.Listeners = append(g.Listeners, l)
			}
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		yes := v == "yes"
		switch k {
		case "kernel":
			g.Kernel = v
		case "btf":
			g.BTF = yes
		case "cgroup2":
			g.CGroup2 = yes
		case "systemd":
			g.Systemd = yes
		case "sudo":
			g.Sudo = yes
		case "oci":
			g.OCI = yes
		case "runc":
			g.Runc = v
		case "crun":
			g.Crun = v
		case "agent-active":
			g.AgentActive = v
		case "agent-enabled":
			g.AgentEnabled = v
		case "agent-transient":
			g.AgentTransient = yes
		case "agent-version":
			g.AgentVersion = v
		case "guest-ips":
			g.GuestIPs = strings.Fields(v)
		case "secret":
			g.Secret.Present = v == "present"
		case "secret-mode":
			g.Secret.Mode = v
		case "secret-owner":
			g.Secret.Owner = v
		case "secret-size":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				g.Secret.Size = n
			}
		case "secret-digest":
			g.Secret.Digest = v
		}
	}
	return g
}

// parseSSLine reads one `ss -H -ltn` row. The local address is the fourth
// column and carries every spelling a listener can have — `0.0.0.0:4777`,
// `127.0.0.1:4777`, `[::]:22`, `*:4777`.
func parseSSLine(line string) (Listener, bool) {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.EqualFold(f[0], "LISTEN") {
		return Listener{}, false
	}
	local := f[3]
	i := strings.LastIndex(local, ":")
	if i < 0 {
		return Listener{}, false
	}
	port, err := strconv.Atoi(local[i+1:])
	if err != nil {
		return Listener{}, false
	}
	addr := strings.TrimSuffix(strings.TrimPrefix(local[:i], "["), "]")
	if addr == "%" {
		return Listener{}, false
	}
	return Listener{Addr: addr, Port: port}, true
}

// ---------------------------------------------------------------------------
// 2. guest-prereqs
// ---------------------------------------------------------------------------

// minKernel is the seccomp listenerPath contract's floor, same value `up`'s
// preflight enforces.
var minKernel = [2]int{5, 7}

// minRunc is the oldest runc whose OCI seccomp config carries listenerPath.
var minRunc = [3]int{1, 1, 0}

// CheckGuestPrereqs classifies BTF, cgroup v2, systemd, the kernel version
// and — only when the guest was provisioned `--oci` — the runtime version.
func CheckGuestPrereqs(g GuestProbe, skip string) Finding {
	f := Finding{ID: IDGuestPrereqs, Title: "guest prerequisites"}
	if skip != "" {
		f.Status = StatusSkip
		f.Title = "guest prerequisites — not checked"
		f.Evidence = append(f.Evidence, skip)
		return f
	}
	if !g.Ran {
		f.Status = StatusSkip
		f.Title = "guest prerequisites — the guest did not answer"
		f.Evidence = append(f.Evidence, g.Err)
		return f
	}

	f.Evidence = append(f.Evidence, fmt.Sprintf("kernel %s, btf=%v cgroup2=%v systemd=%v sudo=%v", g.Kernel, g.BTF, g.CGroup2, g.Systemd, g.Sudo))

	switch {
	case !g.Systemd:
		f.Status = StatusFail
		f.Title = "guest prerequisites — no systemd"
		f.Remedy = "drawbridge supervises its agent with systemd; Alpine/OpenRC guests (colima's legacy image) are not supported in v1 —\n" +
			"recreate the VM with an Ubuntu image: `colima start --vm-type vz` on a current colima"
		return f
	case !g.BTF:
		f.Status = StatusFail
		f.Title = "guest prerequisites — no BTF"
		f.Remedy = "the agent's BPF programs are CO-RE and need /sys/kernel/btf/vmlinux; Ubuntu LTS kernels ship it,\n" +
			"a custom or minimal kernel needs CONFIG_DEBUG_INFO_BTF=y"
		return f
	case !g.CGroup2:
		f.Status = StatusFail
		f.Title = "guest prerequisites — not on cgroup v2"
		f.Remedy = "the agent's cgroup-attached programs need the unified hierarchy: boot the guest with\n" +
			"systemd.unified_cgroup_hierarchy=1, or use a current Ubuntu image"
		return f
	case !g.Sudo:
		f.Status = StatusFail
		f.Title = "guest prerequisites — no passwordless sudo"
		f.Remedy = "`drawbridge up` installs a root-owned binary inside the VM and cannot prompt through the provider shell;\n" +
			"check /etc/sudoers.d in the guest (Lima and Colima images grant it by default)"
		return f
	}

	maj, min, ok := parseKernel(g.Kernel)
	if !ok || maj < minKernel[0] || (maj == minKernel[0] && min < minKernel[1]) {
		f.Status = StatusWarn
		f.Title = fmt.Sprintf("guest prerequisites — kernel %s", g.Kernel)
		f.Evidence = append(f.Evidence, fmt.Sprintf("cannot confirm kernel >= %d.%d, which the runc wrapper's seccomp listenerPath contract needs", minKernel[0], minKernel[1]))
		f.Remedy = "containerized bind arbitration needs a newer guest kernel; mirroring, outbound and host-process EADDRINUSE are unaffected"
		return f
	}

	if g.OCI {
		f.Evidence = append(f.Evidence, "provisioned --oci: "+runtimeLine(g))
		if v, ok := parseRuncVersion(g.Runc); ok && olderThan(v, minRunc) && g.Crun == "" {
			f.Status = StatusWarn
			f.Title = fmt.Sprintf("guest prerequisites — runc %d.%d.%d", v[0], v[1], v[2])
			f.Remedy = fmt.Sprintf("the runc wrapper arbitrates container binds through seccomp user-notify (listenerPath), which needs runc >= %d.%d.%d or crun;\n"+
				"upgrade runc in the guest, or re-run `drawbridge down` to remove the wrapper", minRunc[0], minRunc[1], minRunc[2])
			return f
		}
	}

	f.Status = StatusOK
	f.Title = fmt.Sprintf("guest prerequisites — kernel %s, BTF, cgroup v2, systemd", g.Kernel)
	return f
}

func runtimeLine(g GuestProbe) string {
	var parts []string
	if g.Runc != "" {
		parts = append(parts, g.Runc)
	}
	if g.Crun != "" {
		parts = append(parts, g.Crun)
	}
	if len(parts) == 0 {
		return "no runc or crun on the guest PATH"
	}
	return strings.Join(parts, "; ")
}

// parseKernel reads the leading major.minor of a `uname -r` string, stopping
// at the first thing that is not a digit or a dot — "6.8.0-51-generic",
// "5.15.0" and "6.1" all parse. A numeric compare, never a string one.
func parseKernel(rel string) (maj, min int, ok bool) {
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

// parseRuncVersion reads "runc version 1.1.12" into its three numbers.
func parseRuncVersion(line string) ([3]int, bool) {
	fields := strings.Fields(line)
	for _, f := range fields {
		f = strings.TrimPrefix(f, "v")
		parts := strings.Split(f, ".")
		if len(parts) < 2 {
			continue
		}
		var v [3]int
		ok := true
		for i := 0; i < 3 && i < len(parts); i++ {
			n, err := strconv.Atoi(strings.Split(parts[i], "-")[0])
			if err != nil {
				ok = false
				break
			}
			v[i] = n
		}
		if ok {
			return v, true
		}
	}
	return [3]int{}, false
}

func olderThan(v, min [3]int) bool {
	for i := range v {
		if v[i] != min[i] {
			return v[i] < min[i]
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 3. agent
// ---------------------------------------------------------------------------

// AgentBind is how the agent's transport is bound, as `ss` reported it.
type AgentBind struct {
	Loopback bool // 127.0.0.1
	VZNAT    bool // the guest's own vmnet address
	Wildcard bool // 0.0.0.0 / [::] / *
	Any      bool // anything at all on the control port
	Addrs    []string
}

// BindOf classifies the control-port listeners. Retained as cross-evidence
// for checks 4 and 6: an agent listening in-guest refutes
// limaaddr.NoteAgentNotListening when the Mac-side probe still fails.
func BindOf(listeners []Listener, guestIPs []string) AgentBind {
	guest := map[string]bool{}
	for _, ip := range guestIPs {
		guest[ip] = true
	}
	var b AgentBind
	for _, l := range listeners {
		if l.Port != ControlPort {
			continue
		}
		b.Any = true
		b.Addrs = append(b.Addrs, l.Addr)
		switch {
		case l.Addr == "127.0.0.1" || l.Addr == "::1":
			b.Loopback = true
		case l.Addr == "0.0.0.0" || l.Addr == "::" || l.Addr == "*":
			b.Wildcard = true
		case guest[l.Addr]:
			b.VZNAT = true
		}
	}
	return b
}

// Reachable is the cross-evidence question checks 4 and 6 ask: is there an
// agent listening on an address this Mac could dial?
func (b AgentBind) Reachable() bool { return b.VZNAT || b.Wildcard }

// CheckAgent classifies the guest agent: unit active, version matched,
// transport bound where the Mac can reach it.
func CheckAgent(g GuestProbe, bind AgentBind, cliVersion, skip string) Finding {
	f := Finding{ID: IDAgent, Title: "guest agent"}
	if skip != "" {
		f.Status = StatusSkip
		f.Title = "guest agent — not checked"
		f.Evidence = append(f.Evidence, skip)
		return f
	}
	if !g.Ran {
		f.Status = StatusSkip
		f.Title = "guest agent — the guest did not answer"
		f.Evidence = append(f.Evidence, g.Err)
		return f
	}

	unit := g.AgentActive
	if unit == "" {
		unit = "unknown"
	}
	line := fmt.Sprintf("%s is %s", AgentUnit, unit)
	if g.AgentTransient {
		line += " (transient — the `just agent-up` unit holds the name)"
	}
	f.Evidence = append(f.Evidence, line)
	if len(bind.Addrs) > 0 {
		addrs := make([]string, 0, len(bind.Addrs))
		for _, a := range bind.Addrs {
			addrs = append(addrs, fmt.Sprintf("%s:%d", a, ControlPort))
		}
		f.Evidence = append(f.Evidence, "ss: listening on "+strings.Join(addrs, ", "))
	} else {
		f.Evidence = append(f.Evidence, fmt.Sprintf("ss: nothing listening on :%d", ControlPort))
	}
	f.Data = map[string]any{"unit": unit, "version": g.AgentVersion, "bind": bind.Addrs}

	if g.AgentActive != "active" {
		f.Status = StatusFail
		f.Title = fmt.Sprintf("guest agent — %s is %s", AgentUnit, unit)
		f.Remedy = "no agent is running in the guest; `drawbridge up <vm>` installs and starts it\n" +
			"(`sudo journalctl -u " + AgentUnit + " -n 50` in the guest has the agent's own account)"
		return f
	}
	if g.AgentVersion != "" && g.AgentVersion != cliVersion {
		f.Status = StatusFail
		f.Title = fmt.Sprintf("guest agent — version %s, this CLI is %s", g.AgentVersion, cliVersion)
		f.Remedy = "the guest agent predates this CLI; `drawbridge up <vm>` re-pushes the embedded agent and heals the skew"
		return f
	}
	if !bind.Any {
		f.Status = StatusFail
		f.Title = fmt.Sprintf("guest agent — active but nothing on :%d", ControlPort)
		f.Remedy = "the unit is active and the transport is not bound; `sudo journalctl -u " + AgentUnit + " -n 50` in the guest,\n" +
			"then `drawbridge up <vm>` to reinstall"
		return f
	}
	if !bind.Reachable() {
		f.Status = StatusWarn
		f.Title = fmt.Sprintf("guest agent — bound to loopback only on :%d", ControlPort)
		f.Evidence = append(f.Evidence, "vznat-direct resolution is impossible while the transport is not on the guest's vmnet address")
		f.Remedy = "the agent predates the scoped bind or its -transport was overridden; `drawbridge up <vm>` re-pushes the current agent\n" +
			"(the transport's `auto` default binds 127.0.0.1 plus the vzNAT address, never the wildcard)"
		return f
	}

	f.Status = StatusOK
	v := g.AgentVersion
	if v == "" {
		v = "version unknown"
	}
	f.Title = fmt.Sprintf("guest agent — %s, active, listening on :%d", v, ControlPort)
	return f
}

// ---------------------------------------------------------------------------
// 4. resolution
// ---------------------------------------------------------------------------

// ResolutionInput carries the resolver's own answer plus the two
// cross-references §4 requires doctor to draw.
type ResolutionInput struct {
	Res            limaaddr.Resolution
	Ran            bool
	AgentListening bool // check 3's ss evidence
	RunningVMs     int
	Skip           string
}

// CheckResolution prints Endpoint/Source/Note verbatim and adds the
// cross-references. The resolver's logic is untouched — doctor calls it.
func CheckResolution(in ResolutionInput) Finding {
	f := Finding{ID: IDResolution, Title: "endpoint resolution"}
	if in.Skip != "" || !in.Ran {
		f.Status = StatusSkip
		f.Title = "endpoint resolution — not run"
		f.Evidence = append(f.Evidence, firstNonEmpty(in.Skip, "no target VM selected"))
		return f
	}
	f.Evidence = append(f.Evidence,
		"Endpoint: "+in.Res.Endpoint,
		"Source:   "+in.Res.Source,
	)
	if in.Res.Note != "" {
		f.Evidence = append(f.Evidence, "Note:     "+in.Res.Note)
	}
	f.Data = map[string]any{"endpoint": in.Res.Endpoint, "source": in.Res.Source, "note": in.Res.Note}

	// Both vznat sources are the direct path — the dial connected to the
	// guest's vmnet address; they differ only in where the address came from.
	// vznat-leases is not a fallback: it is the root daemon's only candidate
	// source (limactl refuses euid 0), and its one caveat — the lease name is
	// guest-chosen — is the resolver's own name-only warning, answered by
	// -vm-mac, not by anything checks 5/6 diagnose.
	if in.Res.Source == limaaddr.SourceVZNATDirect || in.Res.Source == limaaddr.SourceVZNATLeases {
		f.Status = StatusOK
		f.Title = "endpoint resolution — " + in.Res.Endpoint + " (" + in.Res.Source + ")"
		if in.Res.Source == limaaddr.SourceVZNATLeases {
			f.Evidence = append(f.Evidence,
				"direct vzNAT path; the address came from the DHCP lease db — pin `-vm-mac` to make the lease match attributable.")
		}
		return f
	}

	f.Status = StatusWarn
	f.Title = "endpoint resolution — fell back to " + in.Res.Source

	// The errno misclassification, named. classifyProbe files a silent
	// timeout under NoteAgentNotListening, and on macOS 27.0b4 that is
	// exactly how a Local Network denial presents.
	if in.AgentListening && strings.Contains(in.Res.Note, limaaddr.NoteAgentNotListening) {
		f.Evidence = append(f.Evidence, "the guest side is listening — the errno classification is known to misread host-side gates on macOS 27 "+
			"(silent-timeout Local Network denial, per-binary LS drops); check 6 discriminates.")
	}
	if in.Res.Source == limaaddr.SourceSSHForwarder && in.RunningVMs > 1 {
		f.Evidence = append(f.Evidence, fmt.Sprintf("%d VMs are running and the transport is on the forwarder's 127.0.0.1:%d — "+
			"the forwarded loopback port is not attributable to a VM, so this daemon can silently attach to a different VM's agent.", in.RunningVMs, ControlPort))
	}
	f.Remedy = "the forwarder works but is slower and shared; checks 5 and 6 say why the direct path was not taken"
	return f
}

// ---------------------------------------------------------------------------
// 5. vznat-route
// ---------------------------------------------------------------------------

// RouteInput is the parsed-in-place view of `netstat -rn -f inet` and `arp`.
type RouteInput struct {
	Subnet      netip.Prefix
	NetstatOut  string
	NetstatErr  string
	ARPOut      string
	ARPErr      string
	CandidateIP string
	GuestUp     bool

	// ProbeOK is check 6's dial result. A missing ARP entry is only
	// meaningful alongside a failing probe (§4): traffic populates the cache,
	// and a connection that just succeeded is better evidence than a cache
	// line that has since aged out.
	ProbeOK bool
}

// CheckVZNATRoute classifies the route-deletion pathology (finding 1) and
// the softer missing-ARP state.
func CheckVZNATRoute(in RouteInput) Finding {
	f := Finding{ID: IDVZNATRoute, Title: "vzNAT route"}
	subnet := in.Subnet
	if !subnet.IsValid() {
		subnet = netip.MustParsePrefix(limaaddr.DefaultSubnet)
	}
	if in.NetstatErr != "" {
		f.Status = StatusSkip
		f.Title = "vzNAT route — could not read the route table"
		f.Evidence = append(f.Evidence, in.NetstatErr)
		return f
	}

	gw := gatewayOf(subnet)
	if !RoutePresent(in.NetstatOut, subnet) {
		f.Status = StatusFail
		f.Title = fmt.Sprintf("vzNAT route — no route for %s", subnet)
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("`netstat -rn -f inet` has no entry for %s", subnet),
			"the connected route can be deleted while the interface still holds the gateway address — unscoped lookups then fall "+
				"through to the LAN default and are black-holed, for every app including root. Observed suspects: Tailscale route "+
				"management, and a Little Snitch uninstall queued across a reboot.")
		f.Remedy = fmt.Sprintf("sudo route -n add -net %s %s", subnet, gw)
		return f
	}
	f.Evidence = append(f.Evidence, fmt.Sprintf("route for %s present", subnet))

	if in.CandidateIP == "" {
		f.Status = StatusOK
		f.Title = fmt.Sprintf("vzNAT route — %s present", subnet)
		return f
	}
	if ARPPresent(in.ARPOut) {
		f.Evidence = append(f.Evidence, "arp: "+strings.TrimSpace(firstLine(in.ARPOut)))
		f.Status = StatusOK
		f.Title = fmt.Sprintf("vzNAT route — %s present, %s in the ARP cache", subnet, in.CandidateIP)
		return f
	}
	f.Evidence = append(f.Evidence, fmt.Sprintf("no ARP entry for %s", in.CandidateIP))
	if !in.GuestUp || in.ProbeOK {
		if in.ProbeOK {
			f.Evidence = append(f.Evidence, "the host reached the guest anyway (check 6), so the cache line had simply aged out")
		}
		f.Status = StatusOK
		f.Title = fmt.Sprintf("vzNAT route — %s present", subnet)
		return f
	}
	f.Status = StatusWarn
	f.Title = fmt.Sprintf("vzNAT route — %s present, no ARP entry for %s", subnet, in.CandidateIP)
	f.Remedy = "first traffic populates the cache; this is only meaningful alongside a failing probe (check 6)"
	return f
}

// gatewayOf is the vmnet gateway: the subnet's first host, which is the
// address bridge100 holds.
func gatewayOf(p netip.Prefix) netip.Addr { return p.Masked().Addr().Next() }

// RoutePresent looks for a destination covering the subnet in `netstat -rn`
// output. macOS abbreviates a classful destination — a /24 prints as
// "192.168.64" — so a plain string compare against the CIDR finds nothing.
func RoutePresent(netstat string, subnet netip.Prefix) bool {
	want := subnet.Masked()
	for _, line := range strings.Split(netstat, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		got, ok := parseRouteDest(fields[0])
		if !ok {
			continue
		}
		if got == want || (got.Bits() <= want.Bits() && got.Contains(want.Addr()) && got.Bits() > 0) {
			return true
		}
	}
	return false
}

// parseRouteDest reads a netstat destination column: "192.168.64",
// "192.168.64.0/24", "192.168.64.2". A bare dotted form with fewer than four
// octets is macOS's abbreviation and is zero-filled to its implied prefix.
func parseRouteDest(s string) (netip.Prefix, bool) {
	if s == "" || s == "default" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	octets := strings.Split(s, ".")
	if len(octets) == 0 || len(octets) > 4 {
		return netip.Prefix{}, false
	}
	bits := len(octets) * 8
	for len(octets) < 4 {
		octets = append(octets, "0")
	}
	addr, err := netip.ParseAddr(strings.Join(octets, "."))
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

// ARPPresent reads `arp -n <ip>` output. A resolved entry names a hardware
// address; "no entry" is the miss.
func ARPPresent(out string) bool {
	s := strings.ToLower(out)
	if s == "" || strings.Contains(s, "no entry") {
		return false
	}
	return strings.Contains(s, " at ") && !strings.Contains(s, "(incomplete)")
}

// ---------------------------------------------------------------------------
// 6. local-network — the sudo discriminator
// ---------------------------------------------------------------------------

// ProbeOutcome is one TCP dial's verdict.
type ProbeOutcome string

const (
	ProbeOK      ProbeOutcome = "ok"
	ProbeFail    ProbeOutcome = "fail"
	ProbeSkipped ProbeOutcome = "skipped"
)

// RootEvidence is the discriminator's root branch. Kind is "tier1" (the same
// binary run under sudo — conclusive), "tier2" (a running root daemon's
// introspection snapshot — suggestive, and per-binary-caveated), or
// "unknown". P1 produces "tier1" (under euid 0) and "unknown" only; the
// classifier already answers for "tier2" so P3 wires evidence, not logic.
type RootEvidence struct {
	Kind  string
	Probe ProbeOutcome
	Note  string
}

// LocalNetworkInput is the four-state table's inputs plus what the messages
// have to name.
type LocalNetworkInput struct {
	UserProbe       ProbeOutcome
	ProbeAddr       string
	ProbeNote       string
	Root            RootEvidence
	NEFilterPresent bool
	NEFilterNames   []string
	Subnet          netip.Prefix
	EUID0           bool
	AgentListening  bool
	Skip            string
}

// CheckLocalNetwork is §4 check 6: pure over (userProbe, rootEvidence,
// neFilterPresent), with the never-rules enforced structurally — a user-only
// probe cannot reach a "Local Network gate" verdict from here, because that
// verdict lives only on the branches that have root evidence.
func CheckLocalNetwork(in LocalNetworkInput) Finding {
	f := Finding{ID: IDLocalNetwork, Title: "Local Network permission"}
	subnet := in.Subnet
	if !subnet.IsValid() {
		subnet = netip.MustParsePrefix(limaaddr.DefaultSubnet)
	}

	if in.Skip != "" || in.UserProbe == ProbeSkipped || in.UserProbe == "" {
		f.Status = StatusSkip
		f.Title = "Local Network permission — not probed"
		f.Evidence = append(f.Evidence, firstNonEmpty(in.Skip, "no vzNAT candidate address to probe"))
		return f
	}

	// The euid-0 branch. What ran was the root probe, so this run can report
	// exactly one half of the discriminator and must say so.
	if in.EUID0 {
		f.Evidence = append(f.Evidence, fmt.Sprintf("root-probe: %s → %s", in.ProbeAddr, in.UserProbe))
		if in.UserProbe == ProbeOK {
			f.Status = StatusOK
			f.Title = "Local Network permission — the root vantage reaches the guest"
			f.Evidence = append(f.Evidence, "running as root; the unprivileged branch is not visible from here — "+
				"re-run `drawbridge doctor` as your own user to compare.")
			return f
		}
		f.Status = StatusFail
		f.Title = "Local Network permission — root cannot reach the guest either"
		f.Evidence = append(f.Evidence,
			"root is exempt from local network privacy (TN3179) and the dial still failed, so this is NOT the permission gate: "+
				"an NE content filter (check 7 — root is exempt from the permission but not from a filter) or a genuine network fault (check 5).",
			"running as root; the unprivileged branch is not visible from here.",
			lsMonitorCaveat)
		f.Remedy = "start with check 5's route and check 7's extensions; the Local Network remedies do not apply to this state"
		return f
	}

	f.Evidence = append(f.Evidence, fmt.Sprintf("user probe: %s → %s", in.ProbeAddr, in.UserProbe))
	if in.ProbeNote != "" {
		f.Evidence = append(f.Evidence, in.ProbeNote)
	}

	// Row 1.
	if in.UserProbe == ProbeOK {
		f.Status = StatusOK
		f.Title = "Local Network permission — not blocking this binary"
		return f
	}

	if in.AgentListening {
		f.Evidence = append(f.Evidence, "check 3 proved an agent listening in the guest, so this is a host-side gate, not a missing listener.")
	}

	switch {
	// Row 2 — the only conclusive positive.
	case in.Root.Kind == "tier1" && in.Root.Probe == ProbeOK:
		f.Status = StatusFail
		f.Title = "Local Network permission — GATE CONFIRMED (root reaches the guest, this binary does not)"
		f.Evidence = append(f.Evidence, "root-probe (tier 1, same binary): ok", lsMonitorCaveat)
		f.Remedy = lnRemedies(subnet)

	// Row 3 — same verdict, weaker evidence, and the per-binary caveat when
	// an NE filter is in the picture: a filter can allow the daemon binary
	// and drop this CLI.
	case in.Root.Kind == "tier2" && in.Root.Probe == ProbeOK:
		f.Status = StatusFail
		f.Title = "Local Network permission — gate indicated (a root daemon reaches the guest, this binary does not)"
		f.Evidence = append(f.Evidence, "root evidence (tier 2, daemon vantage): "+firstNonEmpty(in.Root.Note, "the root daemon resolved vznat-direct"))
		if in.NEFilterPresent {
			f.Evidence = append(f.Evidence, "check 7 found an NE content filter, and those are per-binary: the daemon binary being allowed does not "+
				"exonerate the filter for this CLI. Conclusive: `sudo drawbridge doctor`.")
		}
		f.Evidence = append(f.Evidence, lsMonitorCaveat)
		f.Remedy = lnRemedies(subnet)

	// Row 4 — both fail. Never mentions the LN remedies as the fix.
	case in.Root.Probe == ProbeFail && in.Root.Kind != "unknown" && in.Root.Kind != "":
		f.Status = StatusFail
		f.Title = "Local Network permission — not the gate alone (root fails too)"
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("root evidence (%s): fail", in.Root.Kind),
			"root is exempt from the permission but not from an NE content filter (check 7), and a deleted vmnet route (check 5) "+
				"black-holes every app including root.",
			lsMonitorCaveat)
		f.Remedy = "start with check 5's route and check 7's extensions; the Local Network remedies do not apply to this state"

	// Row 5 — never a conclusion.
	default:
		f.Status = StatusWarn
		f.Title = "Local Network permission — undetermined (no root evidence)"
		f.Evidence = append(f.Evidence,
			"a user-only probe cannot distinguish the Local Network gate from a content filter or a network fault.",
			discriminatorInstruction,
			lsMonitorCaveat)
		f.Remedy = "sudo drawbridge doctor"
	}
	return f
}

// lnRemedies is the TN3179-exemption order: the permanent posture first, the
// exempt-responsible-process second, the supported subnet exemption last.
func lnRemedies(subnet netip.Prefix) string {
	return fmt.Sprintf("in TN3179-exemption order:\n"+
		"  1. sudo drawbridge install                      # root launchd daemon — exempt twice over, and the permanent posture\n"+
		"  2. run drawbridge from Apple Terminal or over SSH  # those are exempt responsible processes\n"+
		"  3. sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses -array %q\n"+
		"     sudo defaults write com.apple.network.local-network AllowedWiFiLocalNetworkAddresses -array %q\n"+
		"     sudo reboot                                  # Apple-supported subnet exemption (macOS 15.5+)",
		subnet.String(), subnet.String())
}

// ---------------------------------------------------------------------------
// 7. ne-filter
// ---------------------------------------------------------------------------

// NEExtension is one activated system extension.
type NEExtension struct {
	TeamID   string
	BundleID string
	Name     string
	State    string
}

// ParseSystemExtensions reads `systemextensionsctl list`. Only the network
// extension category matters, and only entries the system reports as
// activated: a deactivated extension filters nothing.
//
// The rows are tab-separated, and that is load-bearing rather than
// convenient: a real version column reads `(6.5 nightly (7300)/7300)` —
// spaces and nested parentheses — so a whitespace split cannot tell the
// version from the name.
func ParseSystemExtensions(out string) []NEExtension {
	var exts []NEExtension
	inNetwork := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "---") {
			inNetwork = strings.Contains(trimmed, "network_extension")
			continue
		}
		if !inNetwork || trimmed == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < 6 {
			continue
		}
		state := strings.Trim(strings.TrimSpace(cols[len(cols)-1]), "[]")
		if !strings.Contains(state, "activated") {
			continue // also drops the `[state]` column header
		}
		bundle, _, _ := strings.Cut(strings.TrimSpace(cols[3]), " ")
		if bundle == "" {
			continue
		}
		exts = append(exts, NEExtension{
			TeamID:   strings.TrimSpace(cols[2]),
			BundleID: bundle,
			Name:     strings.TrimSpace(cols[4]),
			State:    state,
		})
	}
	return exts
}

// CheckNEFilter is passive detection only (§4 check 7): no active DPI timing
// probe in v1.
func CheckNEFilter(exts []NEExtension, probeErr string) Finding {
	f := Finding{ID: IDNEFilter, Title: "network content filters"}
	if probeErr != "" {
		f.Status = StatusSkip
		f.Title = "network content filters — could not enumerate"
		f.Evidence = append(f.Evidence, probeErr)
		return f
	}
	if len(exts) == 0 {
		f.Status = StatusOK
		f.Title = "network content filters — none activated"
		return f
	}
	names := make([]string, 0, len(exts))
	for _, e := range exts {
		names = append(names, e.BundleID)
		f.Evidence = append(f.Evidence, fmt.Sprintf("%s (%s) [%s]", firstNonEmpty(e.Name, e.BundleID), e.BundleID, e.State))
	}
	f.Status = StatusWarn
	f.Title = fmt.Sprintf("network content filters — %d activated network extension(s)", len(exts))
	f.Evidence = append(f.Evidence,
		"three signatures observed live with a Little Snitch-class filter active:",
		"  1. first-payload DPI stall — an ambiguous HTTP-method prefix in the first segment is held ~2 s",
		"  2. TCP half-close kill — after shutdown(SHUT_WR) inbound bytes are ACKed by the kernel and never delivered to the process (non-loopback only)",
		"  3. per-binary connect-then-die for binaries the filter has no rule for",
		"all three persisted with the filter \"disabled\" — only deactivating the network extension stopped them.",
		"benchmark numbers taken while one of these is active are invalid.")
	f.Remedy = "System Settings → General → Login Items & Extensions → Network Extensions, and deactivate it (not just \"disable the filter\")\n" +
		"— loopback flows are exempt from both bugs, so `DRAWBRIDGE_AGENT=tcp://127.0.0.1:" + strconv.Itoa(ControlPort) + "` is the interim pin"
	f.Data = map[string]any{"extensions": names}
	return f
}

// ---------------------------------------------------------------------------
// 8. half-close-probe (opt-in, `-probe`)
// ---------------------------------------------------------------------------
//
// CheckHalfClose and its live client both live in probe.go: the classifier is
// unreadable apart from the wire behaviour it classifies, and the two are one
// subject.

// ---------------------------------------------------------------------------
// 9. daemon
// ---------------------------------------------------------------------------

// DaemonInput is what the Mac side can be asked without talking to the
// daemon at all — which is the whole point: doctor must diagnose the
// no-daemon state. The snapshot fields are the enrichment tier (§3.3): every
// one of them may be empty, and an empty set is the ordinary posture, not a
// problem to report.
type DaemonInput struct {
	Status           install.Status
	InstalledVersion string
	VersionErr       string
	CLIVersion       string

	// Snapshots is every introspection socket that answered — gather dials,
	// this file only reads. Both flavors answering is itself the finding
	// (§D3), so the whole set arrives rather than a pick.
	Snapshots []*introspect.Snapshot
	// SnapshotProblems are sockets that answered unreadably: a warn line
	// each (§3.3), never silence.
	SnapshotProblems []string
}

// CheckDaemon classifies install state, version skew and liveness.
func CheckDaemon(in DaemonInput) Finding {
	f := Finding{ID: IDDaemon, Title: "Mac daemon"}
	st := in.Status

	switch {
	case st.PlistInstalled || st.BinaryInstalled || st.Loaded:
		f.Evidence = append(f.Evidence, fmt.Sprintf("plist %s, binary %s, launchd %s",
			presence(st.PlistInstalled), presence(st.BinaryInstalled), launchdState(st)))
	default:
		f.Evidence = append(f.Evidence, "drawbridged is not installed")
	}
	if in.InstalledVersion != "" {
		f.Evidence = append(f.Evidence, "installed drawbridged reports "+in.InstalledVersion)
	} else if in.VersionErr != "" && st.BinaryInstalled {
		f.Evidence = append(f.Evidence, "could not read the installed daemon's version: "+in.VersionErr)
	}
	if st.AgentLine != "" {
		f.Evidence = append(f.Evidence, "log: "+strings.TrimSpace(st.AgentLine))
	}
	for _, l := range logHighlights(st.LogTail) {
		f.Evidence = append(f.Evidence, "log: "+l)
	}
	if st.LogNote != "" {
		f.Evidence = append(f.Evidence, "log: "+st.LogNote)
	}
	f.Evidence = append(f.Evidence, snapshotEvidence(in.Snapshots)...)
	for _, p := range in.SnapshotProblems {
		f.Evidence = append(f.Evidence, "warning: an introspection socket answered with something that is not a snapshot: "+p)
	}
	f.Data = map[string]any{"installed": st.Installed(), "loaded": st.Loaded, "state": st.State, "pid": st.PID, "version": in.InstalledVersion,
		"snapshots": len(in.Snapshots)}

	skewed := snapshotVersionSkew(in.Snapshots, in.CLIVersion)
	root, user, fighting := fightingDaemons(in.Snapshots)
	live := liveSnapshot(in.Snapshots)

	switch {
	case in.InstalledVersion != "" && in.InstalledVersion != in.CLIVersion:
		f.Status = StatusFail
		f.Title = fmt.Sprintf("Mac daemon — installed %s, this CLI is %s", in.InstalledVersion, in.CLIVersion)
		f.Remedy = "sudo drawbridge install    # after a brew upgrade, run `drawbridge up && sudo drawbridge install`"

	// The running daemon's own word about its version, which the installed
	// binary's -version cannot give: a daemon started before an upgrade keeps
	// serving the old build until it is restarted.
	case skewed != nil:
		f.Status = StatusFail
		f.Title = fmt.Sprintf("Mac daemon — the running daemon reports %s, this CLI is %s", skewed.State.Version, in.CLIVersion)
		f.Remedy = "sudo drawbridge install    # after a brew upgrade, run `drawbridge up && sudo drawbridge install`"

	// §D3: the documented dev-posture pathology, detectable for the first
	// time now that both flavors name themselves.
	case fighting:
		f.Status = StatusWarn
		f.Title = "Mac daemon — a root daemon and a foreground daemon are both running"
		f.Evidence = append(f.Evidence,
			"two daemons mirror the same guest onto the same Mac localhost: whichever binds a port first wins it, and the other logs a bind failure.")
		f.Remedy = fmt.Sprintf("stop one of them: `sudo drawbridge uninstall` for the root daemon (%s), or kill the foreground one (%s)",
			daemonWho(root), daemonWho(user))

	case !st.Installed() && !st.Loaded && live != nil:
		f.Status = StatusOK
		f.Title = fmt.Sprintf("Mac daemon — a foreground drawbridged is running (pid %d), nothing installed", live.State.PID)
		f.Evidence = append(f.Evidence,
			"a foreground daemon mirrors ports >= 1024 for as long as it runs; `sudo drawbridge install` is the <1024 and survives-reboot posture.")

	case !st.Installed() && !st.Loaded:
		f.Status = StatusWarn
		f.Title = "Mac daemon — not installed"
		f.Remedy = "nothing is mirroring guest listeners onto this Mac. Either:\n" +
			"  sudo drawbridge install    # root LaunchDaemon: ports <1024, survives reboot, exempt from the Local Network gate\n" +
			"  drawbridged -vm <vm>       # unprivileged and foreground, ports >= 1024 only"
	case st.Installed() && !st.Loaded:
		f.Status = StatusWarn
		f.Title = "Mac daemon — installed but not loaded"
		f.Remedy = "launchd does not know the job (booted out by hand?); `sudo drawbridge install` re-bootstraps it"
	case st.Loaded && !st.Running():
		f.Status = StatusWarn
		f.Title = fmt.Sprintf("Mac daemon — loaded, state=%s", firstNonEmpty(st.State, "unknown"))
		f.Remedy = "the job is loaded and not running; " + install.LogPath + " has its last words"
	default:
		f.Status = StatusOK
		f.Title = fmt.Sprintf("Mac daemon — %s running (pid %d)", firstNonEmpty(in.InstalledVersion, "installed"), st.PID)
	}
	return f
}

// snapshotEvidence renders what each answering daemon said about itself. It
// is the vantage `status` could never reconstruct from launchctl and a log
// file, so it is printed even when the verdict does not depend on it.
func snapshotEvidence(snaps []*introspect.Snapshot) []string {
	var out []string
	for _, s := range snaps {
		if s == nil {
			continue
		}
		st := s.State
		if !s.Usable {
			// D4: the two frozen fields still mean something, everything else
			// does not. Version skew is still reportable; nothing else is.
			out = append(out, fmt.Sprintf("daemon at %s speaks introspection schema %d and this CLI knows %d — "+
				"it reports version %s; every other field falls back to inference.",
				s.Path, st.Schema, introspect.Schema, firstNonEmpty(st.Version, "unknown")))
			continue
		}
		out = append(out, fmt.Sprintf("daemon at %s: %s, pid %d, euid %d, vm %s", s.Path, st.Version, st.PID, st.EUID, firstNonEmpty(st.VM.Ref, "unknown")))
		line := fmt.Sprintf("  endpoint %s (source=%s)", st.Resolution.Endpoint, st.Resolution.Source)
		out = append(out, line)
		if st.Resolution.Note != "" {
			out = append(out, "  note: "+st.Resolution.Note)
		}
		out = append(out, fmt.Sprintf("  auth %s, secret %s", firstNonEmpty(st.Auth.Mode, "unknown"), firstNonEmpty(st.Auth.SecretState, "unknown")))
		out = append(out, fmt.Sprintf("  mirror session %s, %d entries (%d bound); sync session %s, %d advertised, %d parked",
			upDown(st.Mirror.SessionUp), len(st.Mirror.Entries), countEntries(st.Mirror.Entries, introspect.EntryBound),
			upDown(st.Sync.SessionUp), len(st.Sync.Advertised), st.Sync.PoolParked))
		// The refusal ring's non-auth alarm rows (transport-auth §7 rows 7
		// and 9, plus the advertised-set-emptied transition) have no check
		// ID of their own: presence is the alarm, here.
		for _, r := range st.RecentRefusals {
			switch r.ID {
			case introspect.IDReverseDialRefused, introspect.IDActivationReserved,
				introspect.IDAdvertisedEmptied, introspect.IDAdvertisedNone:
				out = append(out, "  refusal ["+r.ID+"]: "+strings.TrimSpace(r.Line))
			}
		}
		// The adv-0 state itself, independent of the ring (a daemon predating
		// the ring entry still shows it): a live sync session advertising
		// nothing is never natural — a Mac always has LISTEN sockets.
		if st.Sync.SessionUp && len(st.Sync.Advertised) == 0 && len(st.Sync.UDPPorts) == 0 {
			line := "  sync session is up but advertises nothing — a Mac never legitimately has zero LISTEN sockets"
			if st.EUID != 0 {
				line += "; a terminal-launched daemon on macOS 27.0b4 gets a per-responsible-app-filtered pcblist " +
					"(local-network-permission.md finding 5) — `sudo drawbridge install` runs exempt"
			}
			out = append(out, line)
		}
	}
	return out
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func countEntries(entries []introspect.MirrorEntry, state string) int {
	n := 0
	for _, e := range entries {
		if e.State == state {
			n++
		}
	}
	return n
}

// snapshotVersionSkew returns the first answering daemon whose own version
// differs from this CLI's (§3.3). A daemon that reported no version at all
// is not evidence of skew — only a stated difference is.
func snapshotVersionSkew(snaps []*introspect.Snapshot, cliVersion string) *introspect.Snapshot {
	for _, s := range snaps {
		if s == nil || s.State.Version == "" || cliVersion == "" {
			continue
		}
		if s.State.Version != cliVersion {
			return s
		}
	}
	return nil
}

// fightingDaemons reports the §D3 posture: the root socket and a user socket
// both answering. Kind comes from the path — the root socket is a fixed
// singleton — with the payload's euid as the corroborating field.
func fightingDaemons(snaps []*introspect.Snapshot) (root, user *introspect.Snapshot, ok bool) {
	for _, s := range snaps {
		if s == nil {
			continue
		}
		if isRootSnapshot(s) {
			if root == nil {
				root = s
			}
			continue
		}
		if user == nil {
			user = s
		}
	}
	return root, user, root != nil && user != nil
}

func isRootSnapshot(s *introspect.Snapshot) bool {
	return s.Path == introspect.RootSocketPath || (s.Usable && s.State.EUID == 0)
}

// liveSnapshot is any answering daemon this build understands.
func liveSnapshot(snaps []*introspect.Snapshot) *introspect.Snapshot {
	for _, s := range snaps {
		if s != nil && s.Usable {
			return s
		}
	}
	return nil
}

// daemonWho names one daemon the way a user can act on it.
func daemonWho(s *introspect.Snapshot) string {
	if s == nil {
		return "unknown"
	}
	if s.Usable && s.State.PID > 0 {
		return fmt.Sprintf("pid %d, %s", s.State.PID, s.Path)
	}
	return "pid unknown, " + s.Path
}

func presence(ok bool) string {
	if ok {
		return "present"
	}
	return "missing"
}

func launchdState(st install.Status) string {
	if !st.Loaded {
		return "not loaded"
	}
	if st.PID > 0 {
		return fmt.Sprintf("state=%s pid=%d", st.State, st.PID)
	}
	return "state=" + st.State
}

// logHighlights pulls the runtime alarms that have no check ID of their own
// (transport-auth §7 rows 7 and 9): presence in the tail is the alarm.
func logHighlights(tail []string) []string {
	var out []string
	for _, l := range tail {
		switch {
		case strings.Contains(l, "refused reverse dial to"),
			strings.Contains(l, "nonzero reserved byte in activation header"):
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 10. coexistence
// ---------------------------------------------------------------------------

// CoexistenceInput is the provider forwarder's live state.
type CoexistenceInput struct {
	Known bool // the provider answered
	Fwd   vmprovider.Forwarding
	Err   string
	Skip  string

	// BindFailed is the daemon's own `bind-failed` mirror entries: the live
	// evidence that a forwarder won the race for a port, rather than the
	// hypothetical this check otherwise describes.
	BindFailed []introspect.MirrorEntry
}

// CheckCoexistence prints the §3.4 tradeoff honestly and never suggests
// auto-disabling the provider's forwarder.
func CheckCoexistence(in CoexistenceInput) Finding {
	f := Finding{ID: IDCoexistence, Title: "provider forwarder coexistence"}
	// The daemon's own bind failures are evidence in every state, including
	// the ones where the provider would not say what it forwards: a port the
	// mirror could not take is the thing this check is about.
	bf := bindFailedLines(in.BindFailed)
	switch {
	case in.Skip != "":
		f.Status = StatusSkip
		f.Title = "provider forwarder coexistence — not checked"
		f.Evidence = append(f.Evidence, in.Skip)
		f.Evidence = append(f.Evidence, bf...)
		return f
	case in.Err != "":
		f.Status = StatusSkip
		f.Title = "provider forwarder coexistence — could not read the forwarder state"
		f.Evidence = append(f.Evidence, in.Err)
		f.Evidence = append(f.Evidence, bf...)
		return f
	case !in.Known:
		f.Status = StatusSkip
		f.Title = "provider forwarder coexistence — this provider reports no forwarder"
		f.Evidence = append(f.Evidence, bf...)
		return f
	}

	f.Evidence = append(f.Evidence, fmt.Sprintf("hostagent=%v, guest loopback %s, guest wildcard %s",
		in.Fwd.HostAgent, in.Fwd.Loopback, in.Fwd.Wildcard))
	f.Evidence = append(f.Evidence, bf...)
	if !in.Fwd.Active() {
		f.Status = StatusOK
		f.Title = "provider forwarder coexistence — the provider forwards nothing"
		return f
	}
	// The control port is drawbridge's own deliberate forward (the
	// loopback-tunnel transport fallback pinned in the dev template) — a
	// forwarder claiming only it is the correct baseline, not coexistence.
	if !coverageBeyondControl(in.Fwd.Loopback) && !coverageBeyondControl(in.Fwd.Wildcard) {
		f.Status = StatusOK
		f.Title = "provider forwarder coexistence — only the agent control port is forwarded"
		f.Evidence = append(f.Evidence,
			fmt.Sprintf("guest :%d is drawbridge's own forward (the loopback transport fallback); no mirrorable port is claimed.", ControlPort))
		return f
	}
	f.Status = StatusWarn
	f.Title = "provider forwarder coexistence — this VM's own forwarder is active"
	f.Evidence = append(f.Evidence,
		"mirror binds that lose the race to the forwarder degrade to it: the guest listener is still reachable on Mac localhost, "+
			"but without drawbridge's synchronous EADDRINUSE arbitration on those ports, and on a slower path.",
		"the reverse path (guest → Mac services) and in-guest bind arbitration are unaffected.")
	f.Remedy = "for full semantics, add an ignore rule to the instance's config with all three keys and restart the VM:\n" +
		"  portForwards:\n" +
		"    - guestIP: \"0.0.0.0\"\n" +
		"      guestIPMustBeZero: false\n" +
		"      proto: any\n" +
		"      ignore: true\n" +
		"a bare `ignore: true` matches guest loopback binds only (lima#4403) — verify after the restart"
	f.Data = map[string]any{"loopback": in.Fwd.Loopback.String(), "wildcard": in.Fwd.Wildcard.String()}
	return f
}

// bindFailedLines renders the daemon's `bind-failed` mirror entries — the
// logBindError path, which is a forwarder (or any other holder) winning the
// race for that port on Mac localhost.
func bindFailedLines(entries []introspect.MirrorEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, fmt.Sprintf("the daemon could not bind %s/%d on this Mac (since %s) — something else holds it",
			e.Proto, e.Port, e.Since.Format(time.RFC3339)))
	}
	return out
}

// coverageBeyondControl reports whether the set claims any port other than
// the agent control port.
func coverageBeyondControl(s vmprovider.PortSet) bool {
	for _, r := range s {
		if r.Lo < ControlPort || r.Hi > ControlPort {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 11. skip-visibility
// ---------------------------------------------------------------------------

// SkipInput is check 11's two vantages. Known means a daemon answered with
// its own skip set, which makes the report exact; the log tail is the
// fallback for the no-daemon case, and stays because doctor must work with
// no daemon at all.
type SkipInput struct {
	LogTail []string

	Known   bool     // a usable snapshot supplied the daemon's live state
	Daemon  string   // the socket it came from, so the evidence names it
	Skip    []uint16 // the daemon's configured skip-list
	Skipped []introspect.MirrorEntry
}

// CheckSkipVisibility puts the default exclusion where a confused user will
// look. It is never a health verdict.
func CheckSkipVisibility(in SkipInput) Finding {
	f := Finding{
		ID:     IDSkipVisible,
		Title:  "skip-list — guest :22 is not mirrored by default",
		Status: StatusInfo,
	}
	if in.Known {
		// Exact, from the daemon's own table: which ports it is configured to
		// skip, and which guest listeners it actually declined.
		f.Evidence = append(f.Evidence, fmt.Sprintf("the running daemon (%s) skips %s", in.Daemon, portList(in.Skip)))
		for _, e := range in.Skipped {
			f.Evidence = append(f.Evidence, fmt.Sprintf("guest %s/%d is listening and not mirrored (skip-list, since %s)",
				e.Proto, e.Port, e.Since.Format(time.RFC3339)))
		}
		f.Data = map[string]any{"skip": in.Skip, "skipped": len(in.Skipped)}
	}
	for _, l := range in.LogTail {
		if strings.Contains(l, "skip-list") {
			f.Evidence = append(f.Evidence, "log: "+strings.TrimSpace(l))
		}
	}
	f.Evidence = append(f.Evidence,
		fmt.Sprintf("the default skip-list is %q: those ports are left alone in both directions.", install.DefaultSkip),
		"override with -skip on drawbridged or `sudo drawbridge install -skip \"…\"`; -skip \"\" skips nothing.")
	return f
}

// portList spells a skip set for a human, including the empty one — a daemon
// installed with -skip "" skips nothing, and that is the interesting case to
// see stated.
func portList(ports []uint16) string {
	if len(ports) == 0 {
		return "nothing (-skip \"\")"
	}
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(int(p)))
	}
	return strings.Join(out, ",")
}

// ---------------------------------------------------------------------------

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
