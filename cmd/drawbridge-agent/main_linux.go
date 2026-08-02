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
	"github.com/archcorsair/drawbridge/internal/seccomp"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// versionFile is where the Mac side reads this agent's version back out of
// the guest for the skew check (docs/ergonomics.md §5 check 3). /run is a
// tmpfs, so the file is per-boot by construction.
const versionFile = "/run/drawbridge-agent.version"

func main() {
	// Helper subcommands (no BPF, no root): bench tools and the Phase 4
	// bind probe (stand-in for a container process under the OCI hook).
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
			nsock := fs.String("notify-sock", "/run/drawbridge-notify.sock", "agent notify socket")
			hold := fs.Duration("hold", 2*time.Second, "keep a successful listener open this long")
			fs.Parse(os.Args[2:])
			if err := seccomp.RunBindProbe(*network, *addr, *nsock, *hold, os.Stdout); err != nil {
				log.Fatalf("bindprobe: %v", err)
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
	notifySock := flag.String("notify-sock", "/run/drawbridge-notify.sock", "seccomp notify-fd handoff socket (Phase 4)")
	ociSock := flag.String("oci-sock", "/run/drawbridge-oci.sock", "OCI seccomp-agent listenerPath socket (runc/crun handoffs)")
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
	secret, err := transportauth.LoadOptional(*secretFile)
	if err != nil {
		log.Fatalf("drawbridge-agent: %v — the transport secret must be 64 hex characters, mode 0600; re-run `drawbridge up <vm>` to reprovision", err)
	}
	if secret != nil {
		log.Printf("drawbridge-agent: transport auth: enabled (%s)", *secretFile)
	} else {
		log.Printf("drawbridge-agent: transport auth: no secret configured (looked for %s) — transport is UNAUTHENTICATED; any process that reaches it is trusted. Run `drawbridge up` to provision one", *secretFile)
	}

	a, err := agent.New(*cgroup)
	if err != nil {
		log.Fatalf("drawbridge-agent: %v", err)
	}
	defer a.Close()
	a.SecretFile = *secretFile // re-read per conn; rotation heals live

	os.Remove(*sock)
	ln, err := net.Listen("unix", *sock)
	if err != nil {
		log.Fatalf("drawbridge-agent: control socket: %v", err)
	}
	defer os.Remove(*sock)
	go a.ServeControl(ln)

	tset, err := agent.ListenTransport(*transportEP, *transportAllow, a.ServeTransport, log.Printf)
	if err != nil {
		log.Fatalf("drawbridge-agent: transport: %v", err)
	}
	defer tset.Close()

	os.Remove(*notifySock)
	nln, err := net.ListenUnix("unix", &net.UnixAddr{Name: *notifySock, Net: "unix"})
	if err != nil {
		log.Fatalf("drawbridge-agent: notify socket: %v", err)
	}
	defer os.Remove(*notifySock)
	os.Chmod(*notifySock, 0o666) // hooked container processes are not root
	go a.ServeNotify(nln)

	os.Remove(*ociSock)
	oln, err := net.ListenUnix("unix", &net.UnixAddr{Name: *ociSock, Net: "unix"})
	if err != nil {
		log.Fatalf("drawbridge-agent: oci socket: %v", err)
	}
	defer os.Remove(*ociSock)
	os.Chmod(*ociSock, 0o600) // only root runtimes send here (rootless is out of scope)
	go a.ServeOCISeccomp(oln)
	log.Printf("drawbridge-agent: gateway+tracker attached (cgroup=%s), control %s, transport %s %v",
		*cgroup, *sock, *transportEP, tset.Addrs())

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ln.Close()
}
