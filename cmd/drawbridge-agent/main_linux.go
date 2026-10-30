//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/archcorsair/drawbridge/internal/agent"
	"github.com/archcorsair/drawbridge/internal/benchtool"
	"github.com/archcorsair/drawbridge/internal/buildinfo"
	"github.com/archcorsair/drawbridge/internal/kernelfeat"
	"github.com/archcorsair/drawbridge/internal/seccomp"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// versionFile is where the Mac side reads this agent's version back out of
// the guest for the skew check (docs/ergonomics.md §5 check 3). /run is a
// tmpfs, so the file is per-boot by construction.
const versionFile = "/run/drawbridge-agent.version"

func main() {
	// Helper subcommands (no BPF, no root): bench tools and the Phase 4
	// bind probe (stand-in for a container process under the OCI hook), and
	// the kernel feature probe.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "benchserve":
			if err := benchtool.ServeMain(os.Args[2:]); err != nil {
				log.Fatalf("benchserve: %v", err)
			}
			return
		case "benchclient":
			if err := benchtool.ClientMain(os.Args[2:], os.Stdout); err != nil {
				log.Fatalf("benchclient: %v", err)
			}
			return
		case "bindtry":
			// The uncooperative container workload for OCI tests: a plain
			// bind with zero seccomp machinery — if arbitration happens,
			// the filter came from the runtime, or the test proves nothing.
			fs := flag.NewFlagSet("bindtry", flag.ExitOnError)
			network := fs.String("network", "tcp4", "listen network")
			address := fs.String("addr", "", "listen address, e.g. 127.0.0.1:8080")
			hold := fs.Duration("hold", 0, "keep a successful listener open this long")
			fs.Parse(os.Args[2:])
			res := struct {
				Errno int    `json:"errno"`
				Error string `json:"error,omitempty"`
			}{}
			ln, err := net.Listen(*network, *address)
			if err != nil {
				var errno syscall.Errno
				if !errors.As(err, &errno) {
					log.Fatalf("bindtry: bind failed without errno: %v", err)
				}
				res.Errno = int(errno)
				res.Error = errno.Error()
			}
			if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
				log.Fatalf("bindtry: %v", err)
			}
			if res.Errno == 0 {
				if *hold > 0 {
					time.Sleep(*hold)
				}
				ln.Close()
			}
			return
		case "bindprobe":
			fs := flag.NewFlagSet("bindprobe", flag.ExitOnError)
			network := fs.String("network", "tcp4", "listen network")
			addr := fs.String("addr", "", "listen address, e.g. 127.0.0.1:8080")
			nsock := fs.String("notify-sock", "/run/drawbridge-notify.sock", "agent notify socket (root-only unless the agent runs with -notify-sock-unprivileged)")
			hold := fs.Duration("hold", 2*time.Second, "keep a successful listener open this long")
			offThread := fs.Bool("off-thread", false, "bind from a non-leader thread (the notification then carries a TID, not the PID)")
			fs.Parse(os.Args[2:])
			if err := seccomp.RunBindProbe(*network, *addr, *nsock, *hold, *offThread, os.Stdout); err != nil {
				log.Fatalf("bindprobe: %v", err)
			}
			return
		case kernelfeat.Subcommand:
			// The kernel feature probe (`up` preflight, doctor check 2).
			// Takes no flags; a stray argument is a caller bug, said loudly
			// rather than ignored.
			if len(os.Args) > 2 {
				log.Fatalf("%s: takes no arguments, got %q", kernelfeat.Subcommand, os.Args[2:])
			}
			if err := runFeatures(os.Stdout); err != nil {
				log.Fatalf("%s: %v", kernelfeat.Subcommand, err)
			}
			return
		}
	}

	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 mount to attach the gateway to")
	sock := flag.String("socket", "/run/drawbridge-agent.sock", "control socket path")
	transportEP := flag.String("transport", agent.TransportAuto,
		"transport listen endpoints (events + streams, reached from the Mac): \"auto\" = guest loopback + the vzNAT address, or a comma-separated list of endpoints (bare host:port is tcp)")
	transportAllow := flag.String("transport-allow", "",
		"extra CIDRs allowed to open transport conns, comma-separated (built-in: guest loopback + the Mac's address on the vzNAT subnet)")
	secretFile := flag.String("secret-file", transportauth.GuestPath,
		"transport secret file (64 hex characters, mode 0600), written by `drawbridge up`; when it is absent the transport is unauthenticated")
	gvproxyPublish := flag.String("gvproxy-publish", "",
		"Mac-side host:port to publish the transport on through gvproxy's in-guest API (podman machines; empty disables it). "+
			"The publish is re-established on every agent start, which is what brings the forward back after `podman machine stop`")
	gvproxyGateway := flag.String("gvproxy-gateway", agent.DefaultGvproxyGateway,
		"gvproxy's in-guest forwarding API base URL, used by -gvproxy-publish")
	notifySock := flag.String("notify-sock", "/run/drawbridge-notify.sock", "seccomp notify-fd handoff socket for bindprobe (Phase 4), mode 0600 root-only")
	notifySockUnprivileged := flag.Bool("notify-sock-unprivileged", false,
		"make the notify socket 0666 so unprivileged processes can hand over notify fds. For tests and smoke legs only; "+
			"`drawbridge up` never sets it. Container runtimes use -oci-sock and are unaffected")
	ociSock := flag.String("oci-sock", "/run/drawbridge-oci.sock", "OCI seccomp-agent listenerPath socket (runc/crun handoffs)")
	ociSockOwner := flag.String("oci-sock-owner", "",
		"local user to give the OCI socket to, mode unchanged at 0600 (empty: root only). "+
			"Set by `drawbridge up --oci` on a rootless podman machine, where the engine, conmon and crun all run as that user "+
			"and a root-owned socket would leave the wrapper unable to connect, which is a silent loss of containerized bind arbitration, not an error")
	flag.Parse()

	log.Printf("drawbridge-agent: version %s", buildinfo.Version)
	// Best-effort by design: an unwritable /run is worth a warning, never a
	// dead agent — the version file is a diagnostic, not a dependency.
	if err := os.WriteFile(versionFile, []byte(buildinfo.Version+"\n"), 0o644); err != nil {
		log.Printf("drawbridge-agent: warning: %s: %v", versionFile, err)
	}

	// Transport auth mode, decided from our own file and never from the wire
	// (docs/transport-auth.md §6). Malformed is fatal at boot: a configured
	// secret that cannot be read must never degrade into trusting everyone.
	// The boot read latches (transportauth.LoadLatched): a secret present
	// now keeps this agent authenticated for life, so a file deleted under
	// it (down's best-effort agent stop failing before `rm -rf StateDir`)
	// refuses conns instead of accepting auth=0. An explicit -secret-file
	// latches before the read: it states intent, like drawbridged's.
	explicitSecret := false
	flag.Visit(func(f *flag.Flag) { explicitSecret = explicitSecret || f.Name == "secret-file" })
	if explicitSecret {
		transportauth.Require(*secretFile)
	}
	secret, err := transportauth.LoadLatched(*secretFile)
	switch {
	case errors.Is(err, transportauth.ErrConfiguredMissing):
		// Not fatal: the default path is absent-tolerant at boot, and an
		// explicit one only changes what absence means. Every conn is
		// refused until `up` writes the file, then the next conn heals.
		log.Printf("drawbridge-agent: transport auth: required by -secret-file %s, but no file is there yet — every conn is refused until `drawbridge up <vm>` writes one", *secretFile)
	case err != nil:
		log.Fatalf("drawbridge-agent: %v — the transport secret must be 64 hex characters, mode 0600; re-run `drawbridge up <vm>` to reprovision", err)
	case secret != nil:
		log.Printf("drawbridge-agent: transport auth: enabled (%s)", *secretFile)
	default:
		log.Printf("drawbridge-agent: transport auth: no secret configured (looked for %s) — transport is UNAUTHENTICATED; any process that reaches it is trusted. Run `drawbridge up` to provision one", *secretFile)
	}

	a, err := agent.New(*cgroup)
	if err != nil {
		log.Fatalf("drawbridge-agent: %v", err)
	}
	defer a.Close()
	a.SecretFile = *secretFile // re-read per conn; rotation heals live

	// Notify fds parked by the previous agent process come back through
	// systemd's fd store; adopting them before the sockets open means a
	// container's bind that has been blocking since the old agent went
	// away is answered before any new handoff is accepted.
	if a.FdStoreAvailable() {
		log.Printf("drawbridge-agent: fd store: enabled (notify fds survive agent restarts)")
	} else {
		log.Printf("drawbridge-agent: fd store: no NOTIFY_SOCKET — notify fds die with this process; a restart turns bind() into ENOSYS in running host-network containers (docs/oci-hook.md)")
	}
	if n, err := a.AdoptStoredFds(); err != nil {
		log.Printf("drawbridge-agent: fd store: %v", err)
	} else if n > 0 {
		log.Printf("drawbridge-agent: fd store: re-adopted %d notify fd(s) from the previous agent", n)
	}

	os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatalf("drawbridge-agent: control socket: %v", err)
	}
	defer os.Remove(*sock)
	os.Chmod(*sock, 0o600) // root-only: it edits the decision maps (audit finding 17)
	go a.ServeControl(ln)

	// The gvproxy publish is a startup side effect behind a flag, not a wire
	// change: it points a forward at the listener the agent already binds
	// (docs/podman.md §3.2). Close() unexposes it on the way out.
	var topts []agent.Option
	if *gvproxyPublish != "" {
		topts = append(topts, agent.WithPublisher(&agent.Publisher{
			Gateway: *gvproxyGateway,
			Local:   *gvproxyPublish,
			Logf:    log.Printf,
		}))
	}
	tset, err := agent.ListenTransport(*transportEP, *transportAllow, a.ServeTransport, log.Printf, topts...)
	if err != nil {
		log.Fatalf("drawbridge-agent: transport: %v", err)
	}
	defer tset.Close()

	nln, err := listenNotify(*notifySock, *notifySockUnprivileged)
	if err != nil {
		log.Fatalf("drawbridge-agent: notify socket: %v", err)
	}
	defer os.Remove(*notifySock)
	if *notifySockUnprivileged {
		log.Printf("drawbridge-agent: %s is mode %o (-notify-sock-unprivileged): any guest process can hand over notify fds; tests and smoke legs only",
			*notifySock, notifySockModeUnprivileged)
	}
	go a.ServeNotify(nln)

	os.Remove(*ociSock)
	oln, err := net.ListenUnix("unix", &net.UnixAddr{Name: *ociSock, Net: "unix"})
	if err != nil {
		log.Fatalf("drawbridge-agent: oci socket: %v", err)
	}
	defer os.Remove(*ociSock)
	os.Chmod(*ociSock, 0o600) // root runtimes, plus -oci-sock-owner's one named user
	// Fatal rather than a warning: an agent that kept running with a
	// configured-but-unapplied owner looks healthy and arbitrates nothing
	// (docs/podman.md §6.3).
	if err := agent.OwnOCISocket(*ociSock, *ociSockOwner); err != nil {
		log.Fatalf("drawbridge-agent: oci socket: %v", err)
	}
	if *ociSockOwner != "" {
		log.Printf("drawbridge-agent: %s owned by %s (rootless runtime handoffs), mode 0600", *ociSock, *ociSockOwner)
	}
	go a.ServeOCISeccomp(oln)
	log.Printf("drawbridge-agent: gateway+tracker attached (cgroup=%s), control %s, transport %s %v",
		*cgroup, *sock, *transportEP, tset.Addrs())

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ln.Close()
}
