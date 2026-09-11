# Phase 7: Podman machine + crun

Design for the last phase of the adoption-ergonomics roadmap
([ergonomics.md](ergonomics.md) §8 "Phase 7"). Status: designed 2026-09-11,
nothing built. Results sections at the end are empty until each phase runs;
the spike verdict (§7.0) is written there first.

Scope, restated as hard constraints: no `internal/bpf/` change, no
wire-protocol change (the 4-byte conn-type frame, the static-HMAC proof, the
activation headers and the v1 UDP frame are frozen); spike first, contract
second; the wrapper stays engine-neutral; mirrors bind `127.0.0.1` only;
user-space only on the Mac. Every ClawVault decision already taken stays
taken: attach-only, coexist+warn, vsock reserved, `--oci` opt-in.

---

## 1. Shape of the proposal, in one screen

A podman machine user runs the same three commands as a Colima user:

```
podman machine init && podman machine start        # theirs, not ours
drawbridge up podman:podman-machine-default [--oci]
sudo drawbridge install -vm podman:podman-machine-default
```

and gets the same three semantics. What has to be different is invisible to
them:

1. **Transport.** A podman machine has no host-dialable guest IP (gvproxy is
   user-mode) and, on macOS, gvproxy is started by podman with **no host-side
   control socket at all** (`pkg/machine/shim/networking.go` passes only
   `-ssh-port`, `-forward-sock/-dest/-user/-identity` and the provider's
   `-listen-vfkit`; never `-listen` or `-services`). The only port-forwarding
   API that exists is the one inside the guest, `http://192.168.127.1:80`
   (the `gateway.containers.internal` endpoint podman itself POSTs to for
   `-p`). So the design is: **the guest agent publishes its own transport
   port through gvproxy at every start**, and the Mac dials
   `tcp://127.0.0.1:<port>`. That is branch A, `gvproxy-publish`. It needs
   gvproxy's forwarder to propagate TCP half-close, which is the spike
   (§7.0). If it fails, branch B: **drawbridged supervises
   `/usr/bin/ssh -N -L <unix socket>:127.0.0.1:4777`** built from the
   machine's SSH port and identity, and dials `unix://<socket>`; source
   `ssh-tunnel`, the contingency §3.1 already designed. Neither branch adds
   a scheme to the endpoint grammar.
2. **Provider.** `vmprovider.Podman` (`podman machine list --format json
   --all-providers`, `podman machine inspect`, shell via `podman machine
   ssh`), user-scoped exactly like the limactl driver. `ParseRef` learns
   `podman:`; `LeaseName("podman", …)` is empty because there is no lease.
3. **Guest.** Fedora CoreOS is rpm-ostree with SELinux enforcing: binaries
   still go to `/usr/local/bin` (that is `/var/usrlocal/bin`, writable),
   the unit to `/etc/systemd/system`, and every staged file gets a
   `restorecon`. The Docker provisioning script never runs there.
4. **`--oci`.** The embedded wrapper binary is installed as
   `/usr/local/bin/drawbridge-crun` and dispatches on `argv[0]` to the real
   crun. Registration is a **drop-in file**
   `/etc/containers/containers.conf.d/50-drawbridge.conf` that shadows the
   `crun` entry of the `[engine.runtimes]` table with the wrapper path, so
   `down` deletes one file it created and never merges into a file it does
   not own. No daemon restart dance: the podman CLI reads config per
   invocation; only the socket-activated API service needs a restart, done
   with the same `reset-failed` + marker discipline as docker.
5. **Doctor.** The provider, prerequisite, agent, resolution and coexistence
   checks grow podman branches; the vzNAT route and Local Network checks
   `skip` (loopback is not gated); check 8's loopback result becomes real
   evidence when loopback *is* the path.

What this buys: one command surface across Lima, Colima and Podman; the
root daemon never touches a user-session socket or process; the guest
agent, not the Mac, owns the forward's lifetime (it comes back with every
machine start because the systemd unit does); and every new state is one
file that `down` deletes.

### Alternatives rejected (and what would revive them)

| Alternative | Why rejected | What would revive it |
|---|---|---|
| Mac-side POST to gvproxy's control socket (the roadmap's candidate (a) as written) | On macOS podman starts gvproxy without `-listen`/`-services`; the socket does not exist. Even if it did, root writing to a user-session control socket is the trust boundary this plan refuses. | podman adding a host API socket on applehv **and** the user asking for Mac-side control of forwards. Then it is a `Forwarder` detail, not a transport source. |
| vfkit `virtio-vsock` device to a Mac unix socket | Devices are fixed at `podman machine start` by podman; nothing post-start can add one, and `vsock://` stays reserved by decision. | podman exposing a per-machine vsock device knob. Then `unix://` to that socket, zero call-site change (transport.md §1 corollary 1). |
| Go-native SSH client in drawbridged (`golang.org/x/crypto/ssh`, one channel per conn) | Adds a dependency and, to be configurable, an `ssh://` endpoint scheme that could never be taken back. The supervised `/usr/bin/ssh` process keeps the grammar unchanged and is what §3.1 designed. | Branch B ships and `just bench` shows the per-conn channel-open latency or the supervisor's reconnect gap hurting; or `/usr/bin/ssh` proving unusable under launchd. Then the client replaces the supervisor behind the same `ssh-tunnel` source name. |
| Register a new runtime name (`drawbridge`) + `[engine] runtime = "drawbridge"` in `containers.conf` | Podman keys feature detection on the runtime *name* (`runtime_supports_json`, `runtime_supports_nocgroups`, `runtime_supports_kvm`); a new name needs those lists edited too, and each list is replaced wholesale by TOML, not merged. Shadowing the `crun` key keeps every list truthful because the wrapper execs crun. | Podman growing a per-runtime capability declaration, or a second engine in the same guest needing its own name. |
| Editing `containers.conf` in place with a Go merge (the daemon.json pattern) | Drop-ins exist for exactly this; a merge/revert pair for TOML is a second formatter and a diff nobody asked for. | `containers.conf.d` disappearing upstream (it will not; it is documented in `containers.conf(5)`). |
| Rootless as the first-class `--oci` path | The `:80` demo cannot work rootless without a sysctl the user sets (`net.ipv4.ip_unprivileged_port_start`, FCOS default 1024), and the OCI socket needs an ownership widening. Rootful matches the Lima/docker path byte for byte. | Nothing has to; rootless is supported in the same phase for ports ≥ 1024 with the socket-owner flag (§6.3). |
| libkrun as a supported provider | Untested; the transport is identical (gvproxy) so it probably works, but "probably" is not a matrix row. | Someone running the §7.6 recipe on a libkrun machine and pasting the transcript; then it is a one-line allowlist change (§4.2). |

---

## 2. Facts established while designing (sources, not memory)

Read these before assuming anything about the guest. Each was checked
against upstream source on 2026-09-11; "verify live" marks the ones the
spike must still measure.

**gvproxy and half-close.** `pkg/services/forwarder/ports.go` implements
`/services/forwarder/expose` by `tcpproxy.Proxy.AddRoute(local,
&tcpproxy.DialProxy{Addr: remote, DialContext: <netstack dial>})`.
`github.com/inetaf/tcpproxy`'s `HandleConn` runs `proxyCopy` in both
directions and waits for **both** (`errc` sized 2, two receives), and
`proxyCopy` does `defer closeRead(src); defer closeWrite(dst)`, preferring
the `CloseWrite` interface "for compatibility with e.g. gvisor/netstack".
History: half-close dance `2862066` (2023-11-02, #38); gvisor conns `48c7e53`
(2025-01-21, #46). gvproxy `main` pins `inetaf/tcpproxy
v0.0.0-20260515…`. So a current gvproxy should **propagate** half-close in
both directions; a gvproxy built before 2025-01-21 would swallow the FIN
(neither propagate nor kill: the guest never sees EOF, upload-then-ack
hangs, but the reverse direction survives). That second signature is
**invisible to doctor check 8** (the agent's `serveEvents` never reads its
conn, so streaming past a FIN it never received looks healthy). The spike
therefore tests propagation explicitly (§7.0 leg 1), and the recipe runs
`TestForwarderHalfClose`. Verify live: which gvproxy the installed podman
bundles.

**gvproxy API from inside the guest.** README: "Dynamic port forwarding is
supported over the host HTTP API when gvproxy was started with `--listen`
or `--services`, but also in the VM over `http://192.168.127.1:80`."
`libpod/networking_machine.go` (`machineGvproxyEndpoint =
"gateway.containers.internal"`, struct `machineExpose{local, remote,
protocol}`) is podman using exactly that. `Expose` returns `"proxy already
running for tcp on <local>"` for a duplicate key, so a re-publish must
`/unexpose` first. Bind on the Mac side is done by the user's gvproxy
process, unprivileged: ports < 1024 are out (podman documents the same for
`-p`). The forwarded connection arrives in the guest from the gateway
address `192.168.127.1`.

**Guest addressing.** gvproxy's subnet is `192.168.127.0/24`, gateway `.1`,
guest `.2`. The agent's `-transport auto` (`internal/agent/listen.go`
`pickVZNAT`) selects "a private IPv4 that is not in Lima's usernet subnet
and is not its subnet's first host": `192.168.127.2` qualifies, so the agent
binds `192.168.127.2:4777` unchanged, and `sourceAllow` adds the subnet's
first host, `192.168.127.1`, which is precisely where gvproxy's forwarded
conns come from. Nothing in the agent's bind scope changes; only the log
label "vzNAT" is now a misnomer on podman (cosmetic; rename to "guest NIC"
in passing, no behavior change).

**podman machine CLI surface.** `podman machine list --format json`
(`entities.ListReporter`): `Name, Default, Running, Starting, VMType
("applehv" | "libkrun" | "qemu" | …), Port, RemoteUsername, IdentityPath,
UserModeNetworking`. `podman machine inspect NAME` (`machine.InspectInfo`):
`ConfigDir, ConnectionInfo{PodmanSocket…}, SSHConfig{IdentityPath, Port,
RemoteUsername}, State, Rootful, Rosetta`. `podman machine ssh NAME -- …`
execs `/usr/bin/ssh -i <identity> -p <port> -o UserKnownHostsFile=/dev/null
-o StrictHostKeyChecking=no … core@localhost` with the remote command
built by `strings.Join(inputArgs, " ")` and stdin inherited: **the same
single-space-free-word argv rule as limactl** (AGENTS.md), and the
stdin-script + `dd of=` staging convention carries over unchanged. Default
machine name `podman-machine-default`. Machines of a non-default provider
need `CONTAINERS_MACHINE_PROVIDER=<vmtype>` in the environment for `ssh`
and `inspect`; `list --all-providers` sees them all.

**Machine state on the Mac.** Config `~/.config/containers/podman/machine/<vmtype>/<name>.json`
(SSH port and identity path live here; the port is chosen at `init` and is
stable across stop/start), identity default
`~/.local/share/containers/podman/machine/machine`, runtime dir
`$TMPDIR/podman/` (`gvproxy.pid`, `gvproxy.log`, `<name>-gvproxy.sock` is
the **vfkit datagram socket**, not a control socket). gvproxy runs as a
detached child of the user's session; when the session ends the VM's
networking ends with it, so "user session gone" is indistinguishable from
"machine stopped" for every transport branch.

**Guest image (FCOS via ignition, `pkg/machine/ignition/ignition.go`).**
User `core`, uid 1000, passwordless sudo, linger enabled, `podman.socket`
enabled as a **user** unit (rootless default) with `/usr/local/bin/docker`
symlinked to podman (so `command -v docker` succeeds: the preflight must
not read that as Docker Engine). Marker file `/etc/podman-machine` holds
the vmtype. Rootful machines (`init --rootful` / `set --rootful`) use the
root `podman.socket` and forward user `root`. Nothing in the ignition
lowers `net.ipv4.ip_unprivileged_port_start`; verify live (`sysctl` in the
guest), assume 1024. `/usr/local` is `/var/usrlocal` (writable), `/etc` is
a writable overlay, SELinux is enforcing (verify live: `getenforce`),
`ss`, `sha256sum`, `dd`, `bash`, `restorecon` present (verify live).

**crun and the OCI contract.** `crun` NEWS: "support OCI seccomp notify
listener" landed in **crun 0.19** (listenerPath/listenerMetadata); FCOS
ships crun ≥ 1.x. The OCI e2e image and `bindtry` exercise the contract
without engine assumptions. Verify live, rootless only: which process
connects to `listenerPath` (crun's parent in the host mount namespace, as
runc does, or the container init) and as which uid, because that decides
the socket-ownership contract in §6.3. Podman's default seccomp profile
allows `bind` with no args, so `ociruntime.MutateConfig`'s provable-allow
gate passes and injection happens; a `--security-opt seccomp=…` profile
that restricts bind is refused untouched, exactly as with docker.

**containers.conf.** `containers.conf(5)`: engines read
`/usr/share/containers/containers.conf`, `/etc/containers/containers.conf`,
`/etc/containers/containers.conf.d/*.conf` (global, **all users including
rootless**), then the user's `$XDG_CONFIG_HOME/containers/…`. `[engine]
runtime` selects a member of the `[engine.runtimes]` table; each member is
a list of paths, first existing wins. The CLI reads config per process; the
API service (`podman system service`, socket-activated) holds a libpod
runtime for its lifetime and must be restarted to see a new runtime path.
Containers survive an API-service restart (conmon is their parent).

---

## 3. Transport

### 3.1 The spike (Phase 7.0), designed to need no drawbridge code

A standalone probe, `scripts/halfclose-probe/main.go` (one file, stdlib
only, no imports from this module; `GOOS=linux GOARCH=arm64` build for the
guest, native build for the Mac). Two roles: `-listen ADDR` (server) and
`-dial ENDPOINT` (client, `tcp://host:port` or `unix:///path`). Four legs,
each a subcommand so a failure names itself:

| Leg | Client | Server | Pass |
|---|---|---|---|
| 1 `fin-propagates` | write 1 MiB, `CloseWrite`, read | read to EOF, write `ack <bytes>`, close | ack with the right count within 5 s. Fails when the forwarder swallows the FIN (server never sees EOF). This is the upload-then-ack flow `TestForwarderHalfClose` guards. |
| 2 `survives-fin` | write `hold`, `CloseWrite`, read for 45 s | on EOF, write a heartbeat every 5 s for 45 s, then close | ≥ 2 heartbeats received **after** t+15 s and the last ≥ 30 s after the FIN. Outlasts the agent's 15 s liveness ping twice; the check-8 killer signature is zero heartbeats. |
| 3 `reverse-fin` | read until EOF, then write 64 KiB, close | write `x`, `CloseWrite`, read to EOF, print count | client sees EOF within 1 s and the server reports 65536 bytes. Half-close in the other direction. |
| 4 `bulk` | 256 MiB each way, concurrently | echo | no read stalls > 5 s; report MB/s (not a gate; the forwarder is a single user-mode proxy and will be slower than vzNAT-direct; this number seeds the bench expectation). |

Run the four legs through each path, in this order, and fill the table in
§"7.0 results":

- **Control, Mac loopback**: client and server both on the Mac. Proves the
  probe.
- **Control, guest loopback**: both in the guest via `podman machine ssh`.
- **gvproxy expose** (branch A candidate): server in the guest on
  `192.168.127.2:47790`; from inside the guest
  `curl -sS -X POST http://192.168.127.1/services/forwarder/expose -d
  '{"local":"127.0.0.1:47790","remote":"192.168.127.2:47790","protocol":"tcp"}'`;
  client on the Mac dials `tcp://127.0.0.1:47790`. Afterwards `GET
  …/services/forwarder/all` to record the entry and `POST …/unexpose`.
- **ssh unix-socket forward** (branch B candidate):
  `ssh -i <IdentityPath> -p <Port> -N -o ExitOnForwardFailure=yes -o
  StreamLocalBindUnlink=yes -L /tmp/dbp.sock:127.0.0.1:47790
  core@127.0.0.1`; client dials `unix:///tmp/dbp.sock`.
- **ssh TCP forward**, `-L 127.0.0.1:47791:127.0.0.1:47790`, for the
  record only (the unix form is the one branch B uses).

Also recorded by the spike, because §4 to §6 depend on them: `podman
--version`, the bundled gvproxy's version (`$(podman info --format
'{{.Host.…}}'` does not report it; run the helper binary directly, e.g.
`/opt/podman/bin/gvproxy -version`, path per §10 Q1), `podman machine
inspect` JSON verbatim, and from inside the guest: `uname -r`, `cat
/etc/os-release`, `getenforce`, `sysctl net.ipv4.ip_unprivileged_port_start`,
`crun --version`, `podman --version`, `readlink -f /usr/local/bin/docker`,
`command -v ss sha256sum dd restorecon`, `sudo -n true && echo sudo-ok`,
`test -w /usr/local/bin && echo usrlocal-ok`, `ls -Z /usr/local/bin /etc/systemd/system | head`,
and a staging round trip: `head -c 3000000 /dev/urandom | podman machine
ssh NAME -- dd of=/tmp/dbp.bin status=none` followed by `sha256sum` on both
sides, plus a 4 KiB script on stdin (`podman machine ssh NAME -- bash -s <
script.sh`) to prove the argv/stdin convention holds through podman's ssh.

**Exit criterion (written, in §"7.0 results"):** for the gvproxy path, legs
1, 2 and 3 all pass on the installed podman ⇒ **branch A**, source
`gvproxy-publish`. Any of 1, 2, 3 fails ⇒ **branch B**, source
`ssh-tunnel`, and the verdict records the gvproxy version so doctor can
name it. The ssh unix path must pass all three regardless (it is the
fallback in both branches' failure stories); if it does not, stop and
re-examine before building anything. Either way the verdict names the
tcpproxy commit boundary (2025-01-21) and the first podman release that
bundles a gvproxy past it, so the support matrix can say "podman ≥ X"
rather than "recent".

### 3.2 Branch A: `gvproxy-publish`

**Guest side.** New agent flag `-gvproxy-publish 127.0.0.1:<port>` (and
`-gvproxy-gateway http://192.168.127.1` for the record; podman never
changes the subnet, but the URL is a flag and not a constant so a
non-podman gvproxy user can point it elsewhere). At transport start, once
the guest NIC listener is up (the existing `autoVZNAT` retry loop; the
publish hangs off the same success path), the agent POSTs `/unexpose`
(errors ignored) then `/expose` with `local` = the flag value, `remote` =
`<bound NIC address>:4777`, `protocol` `tcp`. Failure is logged and
retried on the same schedule as the NIC bind (2 s × 30, then 30 s); a
success is logged once with both addresses. On clean shutdown the agent
POSTs `/unexpose` (best effort, 1 s budget). The HTTP client is
`net/http` with a 2 s timeout and no redirects; the body is the three-key
JSON podman sends; nothing is read back except the status. This is an
agent startup side effect behind a flag, not a wire change: the transport
protocol on the forwarded conn is byte-identical, and `Dial` on the Mac
still writes nothing before the conn-type frame.

Why the agent and not `up`: `up` runs once; gvproxy's exposes die with
gvproxy on every `podman machine stop`. The agent restarts with the
machine (systemd unit), so the forward comes back without the user doing
anything, which is the whole ergonomics claim. It is also what podman
itself does for `-p` (in-guest publish), so the API surface used is the
one podman keeps working.

**Mac side.** `up` chooses the port once per VM: first free port on
`127.0.0.1` in `4778..4799` (bind-probed on the Mac at `up` time; 4777 is
deliberately excluded because a Lima dev VM's SSH forward may hold it),
records it, renders it into the unit's `ExecStart`, and verifies by
dialing `tcp://127.0.0.1:<port>` with the same retry budget the ready
script gives the agent. Re-running `up` reuses the recorded port
(idempotent, unit unchanged, no restart).

**Resolution.** New package `internal/podmanaddr` (§3.3 of ergonomics.md:
"Podman gets its own resolution source"): `Resolve(ref vmprovider.Ref)
limaaddr.Resolution` returns `Endpoint: tcp://127.0.0.1:<port>, Source:
"gvproxy-publish"` from the Mac-side record (§3.4), probes it with the
same 800 ms dial and the same `Note` discipline (`ECONNREFUSED` ⇒ "the
agent has not published its port: is the machine running? `podman machine
ssh NAME -- sudo journalctl -u drawbridge-agent -n 30`"). It reuses
`limaaddr.Resolution` as the type: it is the daemon's and doctor's
contract, and moving it to a neutral package is a rename with no behavior
change, deferred. No changes inside `limaaddr`.

**Root daemon.** `sudo drawbridge install -vm podman:NAME` reads the record
(SUDO_USER-derived home, the `SecretFile` precedent) and renders
`-agent tcp://127.0.0.1:<port>` into the plist instead of `-agent auto`.
Pinning `-agent` was rejected for Lima (privileged-daemon.md §4 option 1)
because vzNAT addresses change with the VM's MAC; here the endpoint is a
loopback port *we* chose and the agent re-publishes it on every start, so
there is nothing for `ReResolve` to re-resolve. The daemon's reconnect
loop redials the pinned endpoint unchanged. Trust posture: root dials a
loopback port that a user-session process (gvproxy) binds. That is exactly
today's `ssh-forwarder` posture (root dialing Lima's user-session loopback
forward), and the per-VM static-HMAC proof is what makes a squatter or a
wrong VM a refusal, not a peer (transport-auth.md, verified live in the
wrong-VM replay). Failure modes: machine stopped or user logged out ⇒
`ECONNREFUSED` ⇒ the daemon's existing reconnect backoff, idle until the
next `podman machine start` brings the agent and its publish back; port
squatted ⇒ dial succeeds, auth refuses with the row-4 wording naming the
source, doctor's auth block names it.

### 3.3 Branch B: `ssh-tunnel`

**Mac side.** New package `internal/sshtunnel`: `Start(cfg) (*Tunnel,
error)` spawns
`/usr/bin/ssh -N -F /dev/null -i <identity> -p <port> -o BatchMode=yes -o
ExitOnForwardFailure=yes -o StreamLocalBindUnlink=yes -o
ServerAliveInterval=15 -o ServerAliveCountMax=2 -o StrictHostKeyChecking=no
-o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -L <sock>:127.0.0.1:4777
<user>@127.0.0.1`, waits for `<sock>` to appear (2 s), and supervises:
exit ⇒ restart with backoff 1 s → 2 s → … → 30 s, forever; `Stop()` kills
the process and unlinks the socket. The socket lives in a directory only
the daemon can enter: root `/var/run/drawbridge/` (0700), unprivileged
`$TMPDIR/drawbridge-<uid>/` (0700), name `podman-<instance>.sock`. A unix
socket rather than a loopback port so that no other local process can
squat or connect to it: `unix://` is already in the grammar and already
asserted to carry half-close (`*net.UnixConn.CloseWrite`; sshd does the
`shutdown(SHUT_WR)` on the guest side on channel EOF, the same mechanism
Lima's pinned SSH forwarder uses and `TestForwarderHalfClose` proves).
`StrictHostKeyChecking=no` is podman's own setting for this connection;
the tunnel is loopback-to-gvproxy-to-guest and the transport authenticates
its peer independently, so host-key pinning is a later hardening
(`-ssh-known-hosts`), not a Phase 7 gate.

**Resolution.** `podmanaddr.Resolve` returns `unix://<sock>`, source
`ssh-tunnel`, after asking the daemon-owned supervisor for the socket
(the resolver gets a `TunnelFor(ref)` hook injected by `drawbridged`;
doctor and `up` inject a short-lived tunnel of their own and stop it).

**Root daemon.** New `drawbridged` flags `-ssh-port N`, `-ssh-identity
PATH`, `-ssh-user NAME`, rendered by `install` from the record and
validated like `-secret-file` (absolute path, exists, regular file, mode
0600, no whitespace or shell metacharacters; user name through the same
allowlist as instance names). Root reads a user-owned 0600 key file; the
posture is the `SecretFile` one, stated in plist.go: the user is this
system's trust root and the key grants `core` on a VM the user owns and
root could read the file regardless. `-agent auto` stays. Failure modes:
machine stopped ⇒ `ssh` exits with connection refused ⇒ supervisor
backoff; identity rotated by `podman machine init` of a new machine with
the same name ⇒ auth failure ⇒ backoff plus a log line naming
`sudo drawbridge install -vm podman:NAME` as the fix; doctor check 4
compares the record with `podman machine inspect` and says "re-run
install" when they differ.

### 3.4 The Mac-side per-VM record (both branches)

New package `internal/vmrecord`: `Path(ref)` =
`~/Library/Application Support/drawbridge/vm-<provider>-<instance>.json`
(sibling of the transport secret, same `transportauth.Dir()` and the same
SUDO_USER-aware `HomeDir`), mode 0600, schema

```json
{"version":1,"provider":"podman","instance":"podman-machine-default",
 "transport":"gvproxy-publish","endpoint":"tcp://127.0.0.1:4778",
 "ssh":{"port":51234,"identity":"/Users/u/.local/share/containers/podman/machine/machine","user":"core"},
 "rootful":false,"vmtype":"applehv","written_by":"v0.2.0","written_at":"…"}
```

Written by `up` (from `podman machine inspect` plus its own port choice),
read by `drawbridged` when unprivileged (`-agent auto`), by `install` when
rendering the plist, and by doctor for evidence. Never read by the root
daemon at run time: root gets everything it needs in argv at install time,
which keeps "the root daemon may touch only `ParseRef`" true in spirit
(root exec's no provider tooling and parses no user-writable file while
running). Contains no secret bytes: an endpoint, a port, a key *path*.
Deleting the file and re-running `up` is the reset. For Lima/Colima the
record is not written (nothing to record; their resolution stays
lease-based), so nothing changes for existing installs.

### 3.5 What `up`'s hand-off prints for podman

Branch A: `drawbridge: transport tcp://127.0.0.1:4778 (source
gvproxy-publish; the guest agent re-publishes it on every machine start)`.
Branch B: `drawbridge: transport unix://… (source ssh-tunnel; drawbridged
supervises /usr/bin/ssh to core@127.0.0.1:<port>)`. Then the same single
next step as today: `sudo drawbridge install -vm podman:NAME` or the
foreground `drawbridged -vm podman:NAME`.

---

## 4. Provider: `vmprovider.Podman`

### 4.1 Driver

`internal/vmprovider/podman.go`, the second `Provider` implementation:

- `ProviderPodman = "podman"`. `Detect()` appends it when `podman` is on
  `PATH` **and** `~/.config/containers/podman/machine/` exists (the
  directory test mirrors the Lima/Colima existence gate; the binary test
  is new because a leftover machine directory without podman would
  otherwise list instances no command can reach).
- `List()`: `podman machine list --format json --all-providers`, decoded
  into a named subset of `ListReporter` (unknown fields ignored, the
  limaJSON rule). Maps to `Instance{Provider: "podman", Name, VMType
  (applehv|libkrun|qemu|…), Running: Running && !Starting, LeaseName: "",
  MACAddress: ""}` plus two new fields, see §4.2.
- `Inspect(inst)`: `podman machine inspect --format json NAME` → the
  subset `{Rootful, SSHConfig{IdentityPath, Port, RemoteUsername}, State}`.
  Only `up` and doctor call it (the record is written from it).
- `Shell(inst, stdin, argv...)`: `podman machine ssh NAME -- argv…`, stdin
  wired through, `CONTAINERS_MACHINE_PROVIDER=<vmtype>` set when the
  instance's VMType is not the default provider's (learned from `List`).
  Same `ErrRootScoped` guard on euid 0: podman machine state is per-user
  and `podman machine` under root would look in `/var/root`.
- `GuestArch`: `uname -m` via `Shell`, unchanged.
- `Forwarding(inst)` (the `Forwarder` interface, §3.4 coexistence): reads
  `GET http://192.168.127.1/services/forwarder/all` **from inside the
  guest** via `Shell` (`curl -sS`, read-only), parses the `local` ports,
  drops the SSH port and drawbridge's own publish port, and reports them
  as `Forwarding{HostAgent: <machine running>, Loopback: <ports whose
  local host is 127.0.0.1>, Wildcard: <ports whose local host is empty or
  0.0.0.0>}`. Podman forwards nothing by default: this set is the user's
  `-p` publications, which only collide with a mirror when a *host-netns*
  process also listens on that port (the published container is bridged
  and never mirrored). The warning text says so.

### 4.2 `Instance` gains an attachability verdict

Today `eligible()` in `cmd/drawbridge/guest.go` is `Running && isVZ`. VZ
is a Lima fact. Add to `Instance`:

```go
Attachable bool   // the provider's own verdict for this VMType
AttachNote string // why not, in the user's terms (empty when Attachable)
```

Lima/Colima: `vz` ⇒ true; `qemu` ⇒ false with the existing vz-switch hint
(text unchanged). Podman: `applehv` ⇒ true; `libkrun` ⇒ false, note
"libkrun machines are untested in this release; the transport is the same
(gvproxy) so it likely works: run docs/verify-podman.md and report, or
recreate with `podman machine init --provider applehv`"; anything else ⇒
false with "not a macOS provider". `eligible()` becomes `Running &&
Attachable`, `noCandidateError` prints `AttachNote` per rejected instance,
and the creation hint gains a third line: `podman machine init --now
[--rootful]`. Flipping libkrun is one line in `podman.go` and a recipe run.

### 4.3 `Ref`, `ParseRef`, `LeaseName`

`ParseRef` accepts `podman:<name>`; the bare-name rule still means Lima.
`Ref` for podman: `Instance: name`, `LeaseName: ""`, `LimaHome: ""`.
`LeaseName(ProviderPodman, x)` returns `""`, documented: a podman machine
has no vmnet lease, and an empty lease name must make `limaaddr` refuse to
match anything (today `Target.leaseName()` fills an empty name with
`lima-<VM>`; `drawbridged`'s dispatch never hands a podman ref to
`limaaddr`, and a unit test pins that `ResolveTarget` is not called for
podman refs, so the default-filling stays as is). `matchNamed` in
`guest.go` learns nothing new: bare names resolve across all three
providers with the existing ambiguity error.

`transportauth.FileName(ref)` is provider-qualified already
(`transport-secret-podman-<name>`), so per-VM secrets work unchanged.

---

## 5. Guest provisioning on Fedora CoreOS

### 5.1 Preflight (`probeScript`) additions

Emit `engine=podman|docker|none`, `rootful=yes|no` (from
`/etc/podman-machine` presence plus whether `/run/podman/podman.sock`
exists), `selinux=Enforcing|Permissive|Disabled|none`, `crun=<version>`,
`unpriv_port=<sysctl>`, `restorecon=yes|no`, `ostree=yes|no`
(`/run/ostree-booted`). Engine detection must not trust `command -v
docker`: it is `docker=yes` only when `docker` resolves to something other
than podman (`readlink -f "$(command -v docker)"` not ending in `/podman`)
**and** `dockerd` or `docker.service` exists. `checkPreflight` keeps every
current message; `--oci` on a podman guest requires `engine=podman`,
`crun` ≥ 0.19 (the notify listener floor from crun NEWS), kernel ≥ 5.7 as
before, and prints the SELinux mode as information.

### 5.2 Paths and labels

Binaries `/usr/local/bin/drawbridge-agent` and `…/drawbridge-crun`, unit
`/etc/systemd/system/drawbridge-agent.service`, state
`/etc/drawbridge/`, secret `/etc/drawbridge/transport-secret`: all
unchanged, all writable on FCOS. The install-beside-then-`mv` staging is
kept (same directory, so the new file inherits the directory's SELinux
type). Add to `pushBinary`, `installUnit`, `writeFile` and the drop-in
write: `command -v restorecon >/dev/null && restorecon -F <path>` after
the `mv`, unconditional and silent on Ubuntu (no `restorecon` there). The
recipe records `ls -Z` for every path and `ausearch -m avc -ts recent`
after the first container start; a denial is a §10 question, never a
`setenforce` remedy.

### 5.3 What must not run

`guestbin.ProvisionScript()` (`provision-docker.sh`) is Docker's and stays
Docker's; `provisionOCI` dispatches on the preflight's `engine` and the
podman path never stages it. The `readyScript` and `enableAgent` are
engine-neutral and run unchanged. `down` on a podman guest never calls
`restartDockerScript`.

### 5.4 Unit rendering

`guestbin.Unit(execStart string)` takes the whole `ExecStart` line (today
it takes a path and the template substitutes only that). `up` builds it:
Lima/Colima ⇒ the path alone, byte-identical to today, so existing guests
see no unit change and no restart; podman ⇒ the path plus
`-gvproxy-publish 127.0.0.1:<port>` (branch A only) and
`-oci-sock-owner core` (rootless machines only, §6.3). The unit still has
no user-configurable supervision policy; `systemctl edit` remains the
override.

---

## 6. `--oci` on podman: crun wrapper, drop-in, socket ownership

### 6.1 Wrapper dispatch (engine-neutral, argv[0])

Pure logic moves to `internal/ociruntime/dispatch.go` (no build tag, tested
on the Mac by `go test ./internal/...`):

```go
type Runtime struct {
    Name        string            // "runc" | "crun"
    EnvOverride []string          // DRAWBRIDGE_RUNTIME, then the legacy DRAWBRIDGE_RUNC for runc
    Probe       []string          // real-runtime candidate paths, in order
    ValueFlags  map[string]bool   // global flags that take a separate value
}
func RuntimeFor(argv0 string) Runtime   // basename "drawbridge-crun" ⇒ crun; anything else ⇒ runc
func Subcommand(rt Runtime, args []string) (sub string, rest []string)
```

runc keeps today's table (`--log --log-format --root --criu --rootless`)
and probe list. crun: value flags `--root --log --log-format --log-level
--cgroup-manager`; `--debug --systemd-cgroup --no-pivot --version --help`
are boolean; `--flag=value` needs no entry (one argv word). Probe
`/usr/bin/crun`, `/usr/local/sbin/crun`, `/usr/sbin/crun`,
`/usr/local/bin/crun`, skipping a candidate that is the wrapper itself
after `filepath.EvalSymlinks` (a symlinked wrapper must not exec itself).
`cmd/drawbridge-runc/main_linux.go` becomes a thin caller; the binary is
still built once and embedded once (`guestbin.NameRunc` keeps naming the
artifact); `up --oci` installs it under the engine's name
(`guestbin.WrapperPath(engine)`). The `create`/`run` bundle detection and
`tryInject` are unchanged: podman invokes the runtime through conmon as
`<runtime> --root … --systemd-cgroup --log … [--log-format json] create
--bundle <dir> --pid-file … <id>`, which the existing parser already
handles once crun's value flags are known.

### 6.2 Registration: one drop-in, shadowing `crun`

`up --oci` on a podman guest writes exactly this file (bytes fixed by a
Go constant, so the state file's sha256 is checkable without a VM):

```toml
# written by drawbridge up --oci; removed by drawbridge down. Do not edit.
[engine.runtimes]
crun = ["/usr/local/bin/drawbridge-crun", "/usr/bin/crun"]
```

at `/etc/containers/containers.conf.d/50-drawbridge.conf`, mode 0644. It
applies to rootful and rootless podman alike (global drop-ins are read for
every user), the default runtime name stays `crun` so every
`runtime_supports_*` list stays truthful, and the second path is the
fallback podman uses if the wrapper vanishes (which is also why `down`'s
ordering is safe here even if it were wrong). Ordering in `up`: wrapper
installed first, drop-in second, API-service restart third. `podman info
--format '{{.Host.OCIRuntime.Path}}'` reading the wrapper path is the
acceptance line.

**API-service restart**, needed only because `podman system service`
caches the runtime path: rootful ⇒ `systemctl reset-failed podman.service;
systemctl try-restart podman.service` (restart only if active; the socket
unit stays); rootless ⇒ the same through `systemctl --user -M core@`
(`sudo systemctl --user -M core@.host …` on FCOS's systemd). Reported by a
`drawbridge-podman=restarted|idle|absent|failed` marker with an
`is-active` confirmation, never an exit status, exactly like
`restartDockerScript`; `idle` (socket-activated service not running) is
the common case and needs nothing. AGENTS.md's "always `reset-failed`
before restarting a container engine" applies verbatim.

**State file** `/etc/drawbridge/provision.json` version 2 for podman:

```json
{"version":2,"engine":"podman","runtime_path":"/usr/local/bin/drawbridge-crun",
 "dropin_path":"/etc/containers/containers.conf.d/50-drawbridge.conf",
 "dropin_sha256":"…","rootful":false,"oci_sock_owner":"core"}
```

Docker guests keep writing version 1 unchanged. `down` reading version 2
with `engine=podman`: `sha256sum` the drop-in; equal ⇒ delete; different
⇒ leave it, print the path and "edited since `up`; not removed" (never
guess); absent ⇒ nothing; then the API-service restart with the marker;
then remove the wrapper; then the unit and state dir as today. An older
`down` reading a version-2 file refuses with "newer `up`", the existing
rule. `internal/guestbin/provision.go` gains `DropinBytes()` and
`RevertDropin(state, current []byte) (delete bool, reason string)` as pure
functions with fixtures.

### 6.3 Rootful first, rootless supported: the socket-ownership contract

Ranked by what the quickstart demo needs (`podman run --network host
nginx` → `curl localhost:80`):

- **Rootful machine** (`podman machine init --rootful`, or `podman machine
  set --rootful` on a stopped machine): in-guest podman runs as root, crun
  as root, the OCI socket stays `0600 root`, `:80` binds because the
  container is root in the init user namespace, the netns is the init
  netns. This is the Lima/docker path with a different engine and the one
  the recipe's `:80` transcript uses. First-class.
- **Rootless machine** (the default): mirroring, the reverse path and
  host-process `EADDRINUSE` are fully there (the agent is root via systemd
  regardless; `--network host` under rootless podman shares the init
  netns, so the tracker's `host_netns_inum` check passes). Containerized
  bind arbitration needs the wrapper (running as `core`) to reach the OCI
  socket: `tryInject` probes the socket first and, unable to connect,
  execs crun untouched, so the failure posture is silent stock behavior.
  To enable it: agent flag `-oci-sock-owner <user>` chowns
  `/run/drawbridge-oci.sock` to that uid (mode stays 0600; root still
  connects, as does a rootful runtime), set by `up` on rootless machines
  only. This widens the socket to one named local user, not the world,
  and is one `chown` to reverse. `:80` still fails under rootless at the
  kernel (`ip_unprivileged_port_start`, 1024 on FCOS unless the user sets
  it) before drawbridge is involved; doctor says so and names `--rootful`
  or the sysctl as *the user's* choice, and the recipe's rootless leg uses
  `:8080`. Verify live in 7.4: which process performs the `listenerPath`
  connect under rootless crun and as which uid; if it is the container
  init inside the user namespace, the chown still works (the kuid is
  1000) but the socket path must be visible from the container's mount
  namespace, which would make rootless arbitration a §10 question rather
  than a phase deliverable.

Both `--oci` variants keep every wrapper invariant: injection only when
the profile provably allows bind, bridged containers skipped by the wrapper
and backstopped by the agent's netns check, agent down ⇒ stock behavior.

---

## 7. Doctor

Catalog numbering unchanged (doctor.md §4); podman branches inside checks,
plus the resolution source names. Every classifier stays pure over injected
probe results; `gather.go` grows the podman gathering.

1. `providers`: podman machines listed; `applehv` running ⇒ ok with
   `Rootful` and the SSH port as evidence; `libkrun` ⇒ warn with the
   `AttachNote`; stopped ⇒ warn `podman machine start NAME`; podman on
   PATH but no machine dir ⇒ the creation hint.
2. `guest-prereqs`: the §5.1 keys; crun < 0.19 ⇒ fail (with `--oci`),
   `selinux=Enforcing` ⇒ info line, `unpriv_port` > 80 on a rootless
   machine ⇒ info naming the `:80` consequence.
3. `agent`: unchanged, plus (branch A) the publish evidence: the agent's
   journal line and an in-guest `GET …/services/forwarder/all` showing
   `local 127.0.0.1:<port> remote 192.168.127.2:4777`; missing ⇒ fail
   "agent up but not published" with the journal command.
4. `resolution`: prints `podmanaddr.Resolve` verbatim; `gvproxy-publish`
   or `ssh-tunnel` reachable ⇒ ok (these are the direct path for podman,
   not a fallback: no `warn` for being on loopback); record vs `podman
   machine inspect` mismatch (port, identity, rootful) ⇒ fail "re-run
   `drawbridge up` then `sudo drawbridge install`"; under euid 0 the
   record is not read and the check reports the plist's pinned value.
5. `vznat-route`, 6. `local-network`: `skip` for podman ("no vmnet
   route; loopback is not subject to the Local Network gate"). Check 6's
   sudo discriminator is not printed.
7. `ne-filter`: unchanged (loopback is exempt from the two LS bugs, which
   the check already states).
8. `half-close-probe`: when the provider's real path *is* loopback
   (podman), the loopback result is real evidence: starve ⇒ fail naming
   gvproxy's forwarder and the tcpproxy boundary (2025-01-21) with "check
   your podman's bundled gvproxy version; branch B (`ssh-tunnel`) is the
   remedy". The Lima/Colima wording is untouched.
9. `daemon`: unchanged; branch B adds "tunnel: running/backoff (last
   error)" from the introspection snapshot (one additive field,
   `resolution.tunnel`, schema-1 additive like the counters were).
10. `coexistence`: podman's `Forwarding` (§4.1); non-empty ⇒ warn with the
    podman-specific tradeoff (published ports are bridged containers, so
    the overlap is only with host-netns listeners on the same port).
11. `skip-visibility`: unchanged.

Auth block: unchanged (per-VM secret path is provider-qualified).

---

## 8. Affected files

Concrete paths. **Nothing under `internal/bpf/`** and no struct shared
across BPF collections is touched; `just gen` is never needed.

| Area | Files | Change |
|---|---|---|
| Spike | `scripts/halfclose-probe/main.go` (new, stdlib only), `justfile` (`spike-halfclose` recipe: builds both arches) | §3.1 |
| Provider | `internal/vmprovider/podman.go` (new), `podman_test.go` + `testdata/podman-list.json`, `podman-inspect.json`; `vmprovider.go` (`ProviderPodman`, `Instance.Attachable/AttachNote`, `ParseRef`, `LeaseName`, `Detect`); `lima.go` (fill `Attachable` for vz/qemu) | §4 |
| Record | `internal/vmrecord/{vmrecord.go,vmrecord_test.go}` (new) | §3.4 |
| Resolution | `internal/podmanaddr/{podmanaddr.go,podmanaddr_test.go}` (new); `internal/sshtunnel/{tunnel.go,tunnel_test.go}` (new, branch B only) | §3.2 / §3.3 |
| Agent | `internal/agent/listen.go` (publish hook after the NIC bind; "vzNAT" label ⇒ "guest NIC"), `internal/agent/gvproxy.go` (new: expose/unexpose client), `cmd/drawbridge-agent/main_linux.go` (`-gvproxy-publish`, `-gvproxy-gateway`, `-oci-sock-owner`) | §3.2, §6.3 |
| Wrapper | `internal/ociruntime/dispatch.go` + `dispatch_test.go` (new, pure); `cmd/drawbridge-runc/main_linux.go` (thin) | §6.1 |
| Guest bin | `internal/guestbin/guestbin.go` (`WrapperPath(engine)`, `Unit(execStart)`), `provision.go` (`DropinBytes`, `RevertDropin`, state v2), `provision_test.go` + `testdata/` fixtures, `assets/drawbridge-agent.service` (ExecStart line only) | §5.4, §6.2 |
| CLI | `cmd/drawbridge/guest.go` (preflight keys, `eligible`, hints, `restorecon`), `up.go` (podman branch: record, port choice, unit args, verify via `podmanaddr`), `down.go` (podman revert + API-service restart marker), `main.go` (`install -vm podman:` reads the record, renders `-agent` or `-ssh-*`), `doctor.go`; `fakeguest_test.go` (FCOS fixture answers), `up_test.go`, `down_test.go` | §5, §6 |
| Daemon | `cmd/drawbridged/main.go` (dispatch on `ref.Provider`; branch B flags and tunnel lifetime), `internal/install/plist.go` (`Agent` pin or `SSH*` fields with validation, `Args`), `plist_test.go`, `internal/introspect` (additive `resolution.tunnel`, branch B) | §3.2 / §3.3 |
| Doctor | `internal/doctor/gather.go`, `checks.go`, `checks_test.go` fixtures | §7 |
| e2e | `internal/e2e/e2e_test.go` (`DRAWBRIDGE_VM=podman:…` parses; `resolveAgent` dispatches on provider), no new legs | §9 |
| Docs | `docs/verify-podman.md` (new), `docs/podman.md` (this file: results), `docs/ergonomics.md` (§3.1 row, §8 Phase 7 pointer), `docs/transport.md` §2.2 (two new sources), `docs/doctor.md` §4 (podman branches), `docs/oci-hook.md` (crun landed), `README.md` quickstart, `docs/HANDOFF.md`, `AGENTS.md` (§11 below) | §9 |

Not touched: `internal/limaaddr` (no podman logic goes in; §3.3 of
ergonomics.md), `internal/transport` (no scheme added), `internal/mirror`,
`internal/macsync`, `internal/proxy`, `internal/seccomp`, `internal/udpframe`,
`internal/bpf`.

---

## 9. Phases, in order

Each phase lands on its own, leaves Lima/Colima behavior byte-identical,
and is verified by the named commands. Branch points are explicit; later
phases are written for both outcomes of 7.0.

### 7.0 Transport spike and environment facts

Build: `scripts/halfclose-probe/main.go`; `just spike-halfclose` builds
`bin/halfclose-probe` (Mac) and `bin/halfclose-probe-linux-arm64`. Install
podman per §10 Q1 (blocking: nothing else in this phase can run without
it). `podman machine init --now spike` (rootless default), then run every
path in §3.1 and record every fact in §2 marked "verify live".

Deliverable: §"7.0 results" filled in, with the verdict line
**"transport branch: A (gvproxy-publish)"** or **"B (ssh-tunnel)"**, the
gvproxy version, the tcpproxy boundary reasoning, and the FCOS facts table
(SELinux mode, unprivileged-port sysctl, crun version, `ss`/`restorecon`
presence, staging round trip OK, argv-joining observation).

Verify: the probe's own control runs pass on Mac loopback and guest
loopback (otherwise the probe, not the path, is wrong). `go vet
./scripts/...` and nothing else; no drawbridge package is touched.

### 7.1 Provider + record + `up`/`down` for the agent (no `--oci`)

Build: §4 (`vmprovider.Podman`, `Attachable`), §3.4 (`vmrecord`), §5.1,
§5.2, §5.4, `up`/`down` podman branches without the OCI step, and the
unprivileged half of the transport branch chosen in 7.0: branch A ⇒ the
agent's `-gvproxy-publish` plus `podmanaddr.Resolve` reading the record;
branch B ⇒ `internal/sshtunnel` plus `podmanaddr.Resolve` with the
injected tunnel, and `up` running a short-lived tunnel for its verify
dial. `drawbridged -vm podman:NAME` (unprivileged, `-agent auto`)
dispatches on provider and works end to end.

Verify: `go test ./internal/... ./cmd/...` (fixtures: podman list/inspect
JSON, FCOS fake-guest answers, the record round trip, dispatch of
`eligible` over all three providers, `ParseRef("podman:x")`, unit
rendering byte-identical for Lima). Live: `drawbridge up podman:spike`
twice (second run: "already current", no restart, record unchanged);
`podman machine ssh spike -- sudo journalctl -u drawbridge-agent -n 30`
shows the transport listeners and (A) the publish line; `drawbridged -vm
podman:spike` prints `source=gvproxy-publish` (or `ssh-tunnel`); then the
e2e subset with `DRAWBRIDGE_VM=podman:spike DRAWBRIDGE_AGENT=<endpoint>
go test -count=1 -run 'TestGuestListenerReachableOnMacLocalhost|TestReverse|TestForwarderHalfClose|TestSyncEADDRINUSE' ./internal/e2e/`
(the installed root daemon must be booted out first, AGENTS.md).
`TestForwarderHalfClose` green is the propagation gate on the real
transport code, not just the probe. Then `drawbridge down podman:spike`,
and `podman machine ssh spike -- ls /usr/local/bin /etc/drawbridge
/etc/systemd/system | grep drawbridge` prints nothing. Dev VM regression:
`just e2e` at its baseline (14 pass / 2 root-gated skips).

### 7.2 Root daemon: `install` for podman

Build: `install -vm podman:NAME` reads the record via the SUDO_USER home,
renders branch A's `-agent tcp://127.0.0.1:<port>` or branch B's
`-ssh-port/-ssh-identity/-ssh-user` (with validation), refuses with a
named remedy when the record is absent ("run `drawbridge up podman:NAME`
first") or disagrees with `podman machine inspect` (run as the user before
sudo hands off: `install` already runs user-scoped discovery before the
privileged step, the same way it finds the secret path). Branch B:
`drawbridged` owns one tunnel per process, started before the first
resolve, stopped on exit; the supervisor's state rides the introspection
snapshot additively.

Verify: `go test ./internal/install/ ./cmd/drawbridged/` (plist fixtures
for both branches; injection legs for every new argument). Live: `sudo
drawbridge install -vm podman:spike`; `drawbridge status` shows the
daemon on the podman endpoint; the `:80` legs need a rootful machine, so
this phase's live check is `podman machine ssh spike -- python3 -m
http.server 8080 --bind 0.0.0.0` reachable at Mac `127.0.0.1:8080` with
the daemon installed, then `sudo drawbridge uninstall`. `just bench` with
`DRAWBRIDGE_AGENT=<podman endpoint>` records the podman transport table
in §"7.2 results" (the dial path changed for this provider; the Lima
table is unaffected and not re-run).

### 7.3 Wrapper dispatch

Build: §6.1. No guest-facing change yet: the embedded binary gains the
crun branch and keeps runc behavior identical.

Verify: `go test ./internal/ociruntime/` (table tests: argv0 basenames,
symlinked self exclusion, crun's value flags, podman/conmon's exact
`create` argv shape, `--flag=value` forms). `just test-guest` and `just
e2e` unchanged and green on the dev VM (the docker path executes the same
code through the runc branch, which is the regression check for "byte
identical"). `just vm-docker` after a rebuild to prove the dev flow's
`DRAWBRIDGE_RUNC` override still resolves.

### 7.4 `--oci` on podman

Build: §5.1's engine detection, §6.2 (drop-in, state v2, API-service
marker), §6.3 (`-oci-sock-owner`, set on rootless machines), `down`'s
podman revert. `provisionOCI` dispatches on `engine`; the docker path is
untouched.

Verify: `go test ./internal/guestbin/ ./cmd/drawbridge/` (drop-in bytes,
`RevertDropin` table: unchanged/edited/absent, state v2 encode/decode,
`down` refusing v2 with an old reader). Live, rootful first: `podman
machine init --rootful --now spike-root`; `drawbridge up podman:spike-root
--oci`; `podman machine ssh spike-root -- sudo podman info --format
'{{.Host.OCIRuntime.Path}}'` prints the wrapper; `podman run -d
--network host --name web docker.io/library/nginx` then Mac `curl -sI
localhost:80` (daemon installed) and a second `podman run --network host
… nginx` failing synchronously with `EADDRINUSE` while the Mac holds
`:80` (the docs/plan.md acceptance leg, podman edition); `drawbridge down
podman:spike-root` deletes the drop-in, restarts the API service (marker
`restarted` or `idle`), removes the wrapper, and `podman run` still works
on stock crun. Rootless: the same on `spike` at `:8080`, plus the §6.3
live question (which process connects to `listenerPath`, as which uid;
`ausearch -m avc` clean). The OCI e2e legs run against podman where the
harness's docker assumptions allow; where they do not, the recipe carries
the manual equivalent and says so, rather than porting the harness in
this phase.

### 7.5 Doctor

Build: §7. Verify: `go test ./internal/doctor/` (fixtures for every new
branch, including the check-8 loopback-is-evidence flip gated on
provider), then live `drawbridge doctor -vm podman:spike` and `-probe`,
and `sudo drawbridge doctor -vm podman:spike` (the root run must not read
the record). Agent stopped ⇒ check 3 names it; record port changed by hand
⇒ check 4 names the re-run; `-p 8080:80` container running ⇒ check 10
warns with the podman wording.

### 7.6 Recipe, docs, release

Build: `docs/verify-podman.md` mirroring verify-colima.md's shape (what it
proves, prerequisites incl. the podman install choice, machine creation
both rootless and rootful, `up`, the resolution line to look for, the
pinned e2e subset with `DRAWBRIDGE_AGENT`, the `--oci` legs, `down` with
the "prints nothing" assertion, clean-up); README quickstart gains the
podman column; ergonomics.md §3.1 row flips to "Supported (applehv;
rootful for `:80`)", §8 Phase 7 points here; transport.md §2.2 gains the
two sources; doctor.md §4 the branches; HANDOFF.md; AGENTS.md §11 below.
Release as v0.2.0 (new provider, new agent flags: a minor bump, no wire
change).

Verify: the recipe run end to end on this Mac with the transcript pasted
into §"7.6 results"; `just release-check`-style goreleaser validation
(`.goreleaser.yaml` needs no change: the same four guest binaries are
embedded); CI green.

---

## 10. Open questions for the user, ranked by how much the answer changes the plan

**Decided 2026-09-11 (user):** Q1 official `.pkg`, installed by the user
(reference install for verify-podman.md; mise/brew not used). Q2 stricter
gate accepted: a swallowed FIN disqualifies a path, not only a killed
connection. Q3 rootful first-class, rootless supported for ≥ 1024 with the
socket-owner widening. Q4 branch A's root posture accepted: the
LaunchDaemon dials the gvproxy-bound loopback port pinned in the plist,
authenticated by the per-VM HMAC. Q5 to Q7 take the recommendations below
unless the user says otherwise (libkrun verdict-only; refuse a pre-boundary
gvproxy; v0.2.0).

**Q1: How is podman installed on the dev Mac?** Options: (a) the official
`.pkg` (`/opt/podman/bin/{podman,gvproxy,vfkit}`, `helper_binaries_dir`
preconfigured; the version the most users have; `brew` not involved; but
outside `mise`); (b) `mise use podman@latest` (podman only: vfkit and
gvproxy are not in mise's registry, so they must come from somewhere and
be named in `~/.config/containers/containers.conf` `[engine]
helper_binaries_dir = [...]`); (c) brew, ruled out by the tooling rule.
Recommendation: (a) for the spike and the recipe, recorded in
verify-podman.md as the reference install, with (b) noted as unsupported
until vfkit/gvproxy have a mise source. Impact: gates 7.0 entirely and
decides which gvproxy version the verdict is about.

**Q2: Accept the transport verdict procedure as written (§3.1), including
the rule that a swallowed FIN, not just a killed connection, disqualifies
a path?** Impact: the whole branch structure. Saying "check 8 alone is the
gate" would let a FIN-swallowing gvproxy pass and break upload-then-ack
flows in the field.

**Q3: Rootful as the first-class `--oci` path and rootless supported for
≥ 1024 with the `-oci-sock-owner` widening (§6.3)?** The alternative
(rootless first-class) needs the user to set a sysctl for `:80` and makes
the quickstart's headline demo conditional. Impact: recipe shape and
README wording; the code is the same either way.

**Q4: Branch A's root posture: the LaunchDaemon dials a loopback port
bound by the user's gvproxy, pinned into the plist, authenticated by the
per-VM HMAC (§3.2).** This is today's `ssh-forwarder` posture applied
deliberately. The stricter alternative (root only ever dials a socket it
owns) is branch B's unix socket, at the cost of a supervised ssh process
even when gvproxy passes. Impact: if you prefer the stricter posture,
branch B becomes unconditional and 7.0 shrinks to a facts run.

**Q5: libkrun: verdict-only (recommended, §4.2) or attempt the recipe on
it in 7.6?** Impact: one recipe run and a one-line allowlist flip; no
design change.

**Q6: Should `up` refuse a machine whose bundled gvproxy predates the
tcpproxy half-close boundary (branch A only)?** Options: refuse with the
version and the `--transport ssh` escape (a per-VM record field that
forces branch B), or warn and proceed. Recommendation: refuse; a
half-close-swallowing transport is a silent hang later. Impact: 7.1's
preflight needs the gvproxy version, which lives on the Mac side (Q1's
install path decides where).

**Q7: Version bump: v0.2.0 (recommended: new provider and new agent
flags) or v0.1.x?** Impact: none on the code.

---

## 11. AGENTS.md invariant amendments (apply in 7.6; wording proposed)

- Generalize: "**`vmprovider`'s exec half (limactl *and* `podman
  machine`) is user-scoped; the root daemon may touch only `ParseRef` and
  the values `install` pinned into its argv.** Root never runs `podman`,
  never reads the user's machine config or `vmrecord`, and never talks to
  a user-session control socket; for podman it dials the loopback endpoint
  (branch A) or supervises its own `ssh` (branch B) from pinned arguments."
- Add: "**A podman guest's port forward is owned by the guest agent**
  (`-gvproxy-publish`, re-established on every agent start through the
  in-guest gateway API podman itself uses). Never create exposes from the
  Mac side: on macOS podman starts gvproxy with no host control socket, and
  a Mac-side expose would die with every `podman machine stop`."
- Add: "**`--oci` on podman is one drop-in file** that shadows the `crun`
  entry of `[engine.runtimes]`; never edit `containers.conf` itself and
  never register a new runtime name (podman keys feature lists on the
  name). `down` deletes the drop-in only when its sha256 matches
  `provision.json`."
- Extend the docker restart invariant: "…before restarting a container
  engine **or its API service** (`podman.service`, system or `--user -M
  core@`); report through the `drawbridge-podman=` marker."
- Extend the seccomp-socket note: "The OCI socket is `0600`; on a rootless
  podman machine it is chowned to the machine user (`-oci-sock-owner`),
  never chmodded wider."
- Add to the argv rule: "`podman machine ssh NAME -- a b c` joins argv with
  spaces exactly as limactl does; the single-space-free-word convention is
  provider-independent by design and the fake guest enforces it for every
  provider."

---

## 7.0 results (2026-09-11)

**Verdict: `transport branch: A (gvproxy-publish)`.** Every path passed
every leg, including the strict FIN-propagation gate (Q2). Branch B stays
designed, not built; its fallback story is intact because the ssh unix
path passed 4/4 too.

| Path | leg 1 fin-propagates | leg 2 survives-fin | leg 3 reverse-fin | leg 4 bulk |
|---|---|---|---|---|
| Mac loopback (control) | PASS, ack 0 ms | PASS, 8 hb, last +40 s | PASS, EOF 0 ms, 65536 | PASS, 2121 MB/s |
| guest loopback (control) | PASS, ack 0 ms | PASS, 8 hb, last +40 s | PASS, EOF 0 ms, 65536 | PASS, 3923 MB/s |
| gvproxy expose (127.0.0.1:47790 → 192.168.127.2:47790) | PASS, ack 5 ms | PASS, 8 hb, last +40 s | PASS, EOF 0 ms, 65536 | PASS, 223 MB/s |
| ssh `-L` unix socket | PASS, ack 6 ms | PASS, 8 hb, last +40 s | PASS, EOF 1 ms, 65536 | PASS, 186 MB/s |
| ssh `-L` tcp (127.0.0.1:47791) | PASS, ack 5 ms | PASS, 8 hb, last +40 s | PASS, EOF 1 ms, 65536 | PASS, 217 MB/s |

Leg 2 ran with `-hold 45s` on all paths concurrently against one guest
server; the server log shows every EOF and every "done". The gvproxy
expose was created from inside the guest exactly as §3.1 prescribes and
removed with `/services/forwarder/unexpose` afterwards (`/all` then showed
only podman's own `:22` forward). Leg 4's number seeds the bench
expectation: the user-mode forwarder is ~10× slower than guest loopback
and about 15× slower than vzNAT-direct; ssh is in the same band.

**gvproxy version and the tcpproxy boundary.** The bundled gvproxy is
v0.8.9 (`/opt/podman/bin/gvproxy -version`), and `go version -m` on the
binary shows `github.com/inetaf/tcpproxy v0.0.0-20250222171855-c4b9df066048`,
after the 2025-01-21 gvisor-conn half-close commit, which is why leg 1
propagates. podman 6.0.2 (`BuildOrigin: pkginstaller`) pins gvisor-tap-vsock
v0.8.9 in its own module graph, so the CLI and the helper agree. The first
podman release bundling a post-boundary gvproxy is a 7.1 preflight fact to
pin from release notes; for now the support line is "podman ≥ 6.0 with
gvproxy ≥ v0.8.x built after 2025-02-22", and Q6's refuse-with-version
check reads gvproxy's version the same way (`gvproxy -version`, path from
the pkg's `/etc/paths.d/podman-pkg` → `/opt/podman/bin`).

**Environment facts (everything §2 marked "verify live").**

| Fact | Observed |
|---|---|
| podman (Mac) | 6.0.2, `/opt/podman/bin`, official pkg (Podman Desktop's Podman extension ran the same pkg); helpers `gvproxy v0.8.9`, `vfkit v0.6.4`, `krunkit 1.3.2`, `podman-mac-helper` |
| **default provider** | **`libkrun`**, not applehv: `podman machine info` reports `VMType: libkrun`, config under `~/.config/containers/podman/machine/libkrun`, process is `krunkit` (with `--device virtio-vsock,port=1025,socketURL=…/spike.sock,listen` for podman's ready socket). No `CONTAINERS_MACHINE_PROVIDER`, no user `containers.conf`. §4.2 is amended below. |
| gvproxy argv (libkrun) | `-mtu 1500 -ssh-port 57446 -listen-vfkit unixgram://…/spike-gvproxy.sock -forward-identity …/machine -forward-sock …/spike-api.sock -forward-dest /run/user/501/podman/podman.sock -forward-user core -pid-file …` — **no `-listen`, no `-services`**, as §1 predicted. The in-guest API at `http://192.168.127.1/services/forwarder/{all,expose,unexpose}` is the only control surface and answered on first try. |
| `podman machine list` | `--format json` works; **`--all-providers` does not exist in 6.0.2** (§2 assumed it). `podman machine inspect` JSON keys: `ConfigDir, ConnectionInfo, Created, LastUp, Name, Resources, SSHConfig{IdentityPath, Port, RemoteUsername}, State, UserModeNetworking, Rootful, Rosetta`. Identity `~/.local/share/containers/podman/machine/machine`, user `core`, port 57446 (dynamic). |
| guest | Fedora CoreOS 44.20260707.3.1 stable, kernel 7.1.3-200.fc44.aarch64, `/sys/kernel/btf/vmlinux` present, cgroup v2, SELinux **Enforcing**, `net.ipv4.ip_unprivileged_port_start = 1024`, crun 1.28 (`+SECCOMP +EBPF +SYSTEMD +SELINUX`), podman 6.0.2 in the guest, **no runc**, `/usr/local/bin/docker → /usr/bin/podman` |
| tools | `ss sha256sum dd restorecon curl systemctl chcon` all present; `sudo -n true` ok for `core` (uid 501, groups wheel/sudo); `/usr/local` → `/var/usrlocal`, `/usr/local/bin` **not writable as core, writable as root**, label `bin_t`; `/etc/systemd/system` label `systemd_unit_file_t` |
| containers.conf | `/etc/containers/containers.conf.d/` **does not exist** (drop-in dir must be created by `up`); vendor drop-ins live in `/usr/share/containers/containers.conf.d/{00-vendor.conf,999-podman-machine.conf}`; `podman info` runtime `crun /usr/bin/crun`, rootless=true |
| staging round trip | 3,000,000 random bytes via `podman machine ssh spike -- dd of=/tmp/dbp.bin status=none` on stdin: sha256 identical both sides; the 3.6 MB probe binary staged the same way and ran |
| **argv joining** | `podman machine ssh spike -- bash -s a b "c d" < script` reached the guest as **4 arguments `a b c d`**: podman joins argv into one remote command string unquoted, exactly like `limactl shell`. The AGENTS.md single-word-argv rule applies to the podman driver verbatim; stdin scripts + `dd of=` are the mechanism. |
| ssh forward gotchas | Without `-o IdentitiesOnly=yes` the Mac's agent offers its keys first and sshd disconnects with "Too many authentication failures" before the machine identity is tried; branch B's command line must carry it. `ExitOnForwardFailure=yes` and `StreamLocalBindUnlink=yes` behaved. ssh logs `setsockopt TCP_NODELAY: Operation not supported on socket` once per unix-socket client (cosmetic). |
| Mac side effects of the install | `podman machine start` prints "API forwarding listening on: /var/run/docker.sock" — `podman-mac-helper` now owns the Docker socket path on this Mac, so the `docker` CLI's default context talks to podman. Doctor's coexistence check should name this when it sees it; it does not affect the transport. |

**§4.2 amendment (libkrun).** libkrun is podman 6's default macOS provider
and the entire spike ran on it, so `Attachable` is **true for both
`libkrun` and `applehv`**; the AttachNote text proposed for libkrun is
dropped. The transport is provider-independent by construction (gvproxy
either way); the recipe in 7.6 runs on the default (libkrun) and repeats
the three semantics on an applehv machine (`podman machine init
--provider applehv`). Q5 is therefore moot in the direction the plan
assumed: applehv, not libkrun, is the "also verify" provider.

**applehv cross-check (same session).** `podman machine init --provider
applehv spike-hv` then start: gvproxy argv has the same shape (`-mtu
-ssh-port 65054 -listen-vfkit … -forward-sock/-dest/-user/-identity`, no
`-listen`), the in-guest `/services/forwarder/all` answers with the `:22`
forward, same FCOS build and SELinux mode, same identity file
`~/.local/share/containers/podman/machine/machine` (one key for all
machines), a fresh dynamic SSH port. The guest NIC is **not `eth0`** on
applehv (`ip -4 addr show eth0` fails; libkrun names it `eth0`), so
nothing in 7.1 may assume an interface name: derive the guest address from
`ip -4 route get 192.168.127.1` or simply bind the transport on
`192.168.127.2`, gvproxy's fixed DHCP lease for the machine.

**Only one machine runs at a time**, across providers: starting `spike-hv`
while `spike` ran failed with "spike already starting or running on the
libkrun provider: only one VM can be active at a time" (exit 125). Design
consequence for §4.1's `List()` and the TUI's multi-VM switcher: at most
one podman instance is ever `Running`, and the daemon's per-VM record for a
stopped machine is stale-by-definition; doctor's "machine not running"
branch is the common case, not an edge. The verify-podman recipe must
stop the default machine before the applehv leg.

Cleanup state after the spike: machine `spike` (rootless, libkrun) left
running for 7.1, `spike-hv` (applehv) created and stopped;
`/tmp/halfclose-probe` and `/tmp/dbp.bin` in the `spike` guest; no gvproxy
forward left behind; ssh forwards killed.

## 7.1 results (2026-09-11)

**Landed and verified live on `podman:spike` (libkrun, rootless, podman
6.0.2).** Branch A works end to end: a guest listener is reachable on Mac
localhost through the agent's own gvproxy publish, `up` is idempotent, `down`
leaves nothing, and the machine is left provisioned for 7.2.

### What landed

| Commit | Files |
|---|---|
| `d8c2b19` provider | `internal/vmprovider/podman.go` (new), `podman_test.go` + `testdata/podman-list.json`, `testdata/podman-inspect.json` (both captured verbatim from podman 6.0.2, home and $TMPDIR anonymised); `vmprovider.go` (`ProviderPodman`, `Instance.Attachable/AttachNote`, `Attachability`, `ParseRef`, `LeaseName`, `Detect`, `ForRef` moved here and returning `Provider`); `lima.go` (`checkArgv`, `Attachable` filled); `internal/e2e/e2e_test.go` (`Forwarder` type assertion) |
| `ff56e72` record | `internal/vmrecord/{vmrecord.go,vmrecord_test.go}` (new) |
| `dc88387` agent | `internal/agent/gvproxy.go` + `gvproxy_test.go` (new), `listen.go` (`Option`, `WithPublisher`, `publish`, `Close` unexposes, "vzNAT" label ⇒ "guest NIC"), `cmd/drawbridge-agent/main_linux.go` (`-gvproxy-publish`, `-gvproxy-gateway`) |
| `4ca4b7b` resolution | `internal/podmanaddr/{podmanaddr.go,podmanaddr_test.go}` (new); `cmd/drawbridged/main.go` (`leaseResolvable`, `resolveAuto`, no re-resolve hook for podman, lease-free log line) + `main_test.go` |
| `2b53a5a` CLI | `cmd/drawbridge/{guest.go,up.go,down.go,main.go}` and their tests, `fakeguest_test.go` (FCOS fixture, `Inspect`, restorecon modelling); `internal/guestbin/guestbin.go` (`Unit` takes the whole ExecStart line) + test; `internal/install/plist.go` (`Config.Agent`, `agentRE`) + test |

Scope held: no `internal/bpf/` change, no wire-protocol change, no `--oci`
(`up --oci podman:…` refuses before touching the guest, naming 7.4).

### Verified live

```
$ mise exec -- just build                       # guest binaries first, then the Mac CLI
$ ./bin/drawbridge up podman:spike
drawbridge: podman:spike — linux/arm64, kernel 7.1.3-200.fc44.aarch64, SELinux Enforcing, rpm-ostree
drawbridge: chose transport port 4778, recorded in ~/Library/Application Support/drawbridge/vm-podman-spike.json
drawbridge: installed /usr/local/bin/drawbridge-agent (v0.1.1-10-g2b53a5a)
drawbridge: wrote /etc/drawbridge/transport-secret (transport auth enabled)
drawbridge: drawbridge-agent.service is active
drawbridge: transport tcp://127.0.0.1:4778 (source gvproxy-publish; the guest agent re-publishes it on every machine start)

$ ./bin/drawbridge up podman:spike              # second run: idempotent
drawbridge: transport port 4778 (recorded in …/vm-podman-spike.json)
drawbridge: /usr/local/bin/drawbridge-agent already current
  (no unit rewrite, no restart, record unchanged)

$ podman machine ssh spike -- sudo journalctl -u drawbridge-agent -n 30
… transport listening on 192.168.127.2:4777 (guest NIC; sources: loopback,192.168.127.1/32)
… gvproxy: published 127.0.0.1:4778 -> 192.168.127.2:4777 (the Mac dials tcp://127.0.0.1:4778)
… (on the restart) gvproxy: unexposed 127.0.0.1:4778   ← Close's best-effort unexpose, then a fresh publish

$ podman machine ssh spike -- curl -sS http://192.168.127.1/services/forwarder/all
[{"local":"127.0.0.1:4778","remote":"192.168.127.2:4777","protocol":"tcp"},
 {"local":"127.0.0.1:57446","remote":"192.168.127.2:22","protocol":"tcp"}]
$ lsof -nP -iTCP:4778 -sTCP:LISTEN
gvproxy 83078 nxc 16u IPv4 … TCP 127.0.0.1:4778 (LISTEN)

$ podman machine ssh spike -- ls -Z /usr/local/bin/drawbridge-agent /etc/systemd/system/drawbridge-agent.service
system_u:object_r:bin_t:s0                  /usr/local/bin/drawbridge-agent
system_u:object_r:systemd_unit_file_t:s0    /etc/systemd/system/drawbridge-agent.service

$ ./bin/drawbridged -vm podman:spike -introspect off
drawbridged: -vm podman:spike → podman machine spike (no DHCP lease: gvproxy is user-mode, so the endpoint comes from the per-VM record)
drawbridged: agent tcp://127.0.0.1:4778 (source=gvproxy-publish); mirroring guest listeners onto 127.0.0.1; …
drawbridged: mirroring guest :8099 on 127.0.0.1:8099
$ curl -o /dev/null -w '%{http_code}' http://127.0.0.1:8099/     # guest `python3 -m http.server 8099`
200

$ ./bin/drawbridge down podman:spike
drawbridge: removed /etc/systemd/system/drawbridge-agent.service
drawbridge: removed /usr/local/bin/drawbridge-agent
drawbridge: removed ~/Library/Application Support/drawbridge/vm-podman-spike.json
drawbridge: kept the Mac-side transport secret …   (down is guest-scoped)
$ podman machine ssh spike -- ls /usr/local/bin /etc/drawbridge /etc/systemd/system | grep drawbridge
   (prints nothing; /etc/drawbridge does not exist, the gvproxy forward is gone, Mac :4778 free)

$ ./bin/drawbridge up podman:spike               # left provisioned for 7.2 (secret reused, port 4778 again)
$ ./bin/drawbridge install -vm podman:spike -print
   <string>-agent</string><string>tcp://127.0.0.1:4778</string><string>-vm</string><string>podman:spike</string>
$ ./bin/drawbridge install -vm podman:spike -vm-mac 52:55:55:a5:de:d2 -print
drawbridge install: -vm-mac does not apply to a podman machine: … (refused, exit 2)
```

Cross-provider selection was exercised with the Lima dev VM stopped: bare
`drawbridge up` picks `podman:spike` on its own, and `drawbridge up
lima:drawbridge` still answers `is not running — limactl start drawbridge`.

Unit tests: `go test ./internal/... ./cmd/...` green, and `-race` green on
every package touched (`vmprovider`, `vmrecord`, `agent`, `podmanaddr`,
`install`, `guestbin`, `cmd/drawbridge`, `cmd/drawbridged`). `go vet ./...`
clean.

### What the plan got wrong, and the correction

1. **`Instance.AttachNote` cannot carry the whole refusal.** §4.2 says the
   qemu note is "the existing vz-switch hint (text unchanged)", but that text
   is rendered two different ways (a named instance gets "runs on qemu, not
   vz" plus a remediation; the candidate list gets a shorter sentence) and the
   remediation is per-provider *and* per-instance (`limactl edit <name>` vs
   `colima start -p <profile>`). Correction: `AttachNote` is the provider's
   *reason* only, and the CLI keeps `vzSwitchError`/`vzSwitchHint` for
   lima/colima so their wording is byte-identical, with `attachRefusal` and
   `notAttachableError` dispatching. Podman's note is printed as given plus a
   `podman machine rm/init` hint.
2. **`up`'s port choice must not bind-probe a port it is reusing.** §3.2 says
   "first free port in `4778..4799` (bind-probed at `up` time)… re-running
   `up` reuses the recorded port". Those two collide: on the second run the
   agent is already publishing, so gvproxy *holds* the recorded port and a
   probe finds it busy, moves the endpoint, rewrites the unit and restarts a
   healthy agent. Correction: a recorded port is reused unconditionally (it is
   ours); the probe only ever chooses a *new* one. Pinned by
   `TestUpPodmanIsIdempotent`, which holds the port while the second `up` runs.
3. **`restorecon` cannot be a link in `installFile`'s `&&` chain.** §5.2 says
   to append `command -v restorecon && restorecon -F <path>` after the `mv`.
   Appending it makes the chain end in a tolerant clause, and the fake guest's
   shell model (correctly) applies a trailing `|| true` to the whole chain,
   so a failed `install` would have been swallowed. Correction: a separate
   `g.try` call, gated on the preflight's `restorecon=yes`, so an Ubuntu guest
   spends no round trip at all and the install's own failure stays fatal.
4. **`-vm-mac` had to become an error on podman, not a no-op.** Not addressed
   by the plan. Accepting it and ignoring it would leave an operator believing
   the root daemon is pinned when nothing is; there is no lease to pin, and
   what refuses a squatter on the loopback port is the per-VM HMAC.
5. **`Instance.MACAddress`/`LeaseName` for podman.** §4.1 has them empty,
   which is right, but `limaaddr.Target.leaseName()` still fills an empty name
   with `lima-<VM>`. The plan's answer ("a unit test pins that `ResolveTarget`
   is not called for podman refs") is what shipped, as the `leaseResolvable`
   predicate plus `TestPodmanRefsNeverReachTheLeaseDb`, worth restating
   because the empty lease name is *not* self-enforcing.
6. **`Forwarding` for podman is a stub in this phase**, as permitted: it
   reports nothing forwarded, so `up` prints no coexistence warning. The real
   detector reads gvproxy's `/services/forwarder/all` from inside the guest and
   needs its own wording (a published container is bridged and was never a
   mirror candidate), which is doctor check 10's job in 7.5.

### Not done here, and why

- **Doctor still speaks Lima.** `internal/doctor`'s own `VMType == "vz"` tests
  are untouched, so `drawbridge doctor` describes a running podman machine as
  "running on libkrun — no host-reachable guest IP". That is §7's work, phase
  7.5, and nothing in 7.1 depends on it.
- **`drawbridged` mirrors the guest's own `:4777`** onto Mac `127.0.0.1:4777`
  on a podman machine. Pre-existing behaviour (the mirror direction has never
  excluded the guest's transport listener; on Lima the port is simply already
  held by the SSH forward, so the bind loses and is logged), newly *visible*
  because podman's transport is on 4778. Harmless (`newExclude` keeps the
  syncer off mirrored ports), but it is noise worth a decision in 7.5.
- **A flaky pre-existing data race in `internal/mirror`'s test harness**
  (`fakeAgent.handshake` in `udp_test.go` reads a field
  `TestSpliceGatesClientBytesOnProof` writes). Unrelated to this phase, seen
  once in a `-race` full-suite run and not reproducible in four re-runs of the
  package. Not fixed here.

### Left for the user (needs sudo, or the root daemon booted out)

The released root `drawbridged` LaunchDaemon is installed and running on this
Mac, and this session could not `sudo`.

```
# the e2e subset, which needs the installed daemon out of the way first
sudo launchctl bootout system/com.archcorsair.drawbridged
DRAWBRIDGE_VM=podman:spike DRAWBRIDGE_AGENT=tcp://127.0.0.1:4778 \
  go test -count=1 -run 'TestGuestListenerReachableOnMacLocalhost|TestReverse|TestForwarderHalfClose|TestSyncEADDRINUSE' ./internal/e2e/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.archcorsair.drawbridged.plist

# the root install against podman (7.2's live leg, rendering verified by -print here)
sudo drawbridge install -vm podman:spike
drawbridge status
sudo drawbridge uninstall

# dev-VM regression, once the Lima dev VM is started (it is stopped on this Mac)
limactl start drawbridge && just e2e      # baseline 14 pass / 2 root-gated skips
```


**User-run acceptance (2026-09-11, later the same day).** The e2e subset
(`DRAWBRIDGE_E2E=1 DRAWBRIDGE_VM=podman:spike DRAWBRIDGE_AGENT=tcp://127.0.0.1:4778`,
four legs incl. `TestForwarderHalfClose`) passed. `sudo ./bin/drawbridge
install -vm podman:spike` then `status` showed the daemon at
`tcp://127.0.0.1:4778 (flag)`, auth ok, mirror and sync sessions up.
Note the e2e gate: the 7.1 hand-off command omitted `DRAWBRIDGE_E2E=1`,
without which every leg skips green; the recipe must carry it.
Dev-VM regression the same session: `just vm-up && just agent-up && just
e2e` at baseline, 14 pass / 2 root-gated skips / 0 fail, on the 7.1 agent
build (`v0.1.1-14-g4f378a3`), so the Lima path is unchanged by the podman
work. (A `just e2e` against a stopped VM prints `ok` in 0.4 s with every
leg skipped; read the `-v` output, not the exit status.)

**Lesson for 7.2 (single launchd identity).** `install` writes one plist,
`com.archcorsair.drawbridged`, whatever `-vm` says, and `uninstall`
removes it. Installing for `podman:spike` on a Mac that already had the
released daemon for `colima:default` therefore replaced that install in
place, and the subsequent `uninstall` removed it, so the "restore with
`launchctl bootstrap`" step in the hand-off failed (`Bootstrap failed: 5`,
the plist was gone). Recovery is `sudo drawbridge install -vm
colima:default` from the brew CLI. This is the existing single-daemon
posture, not new, but 7.2 must make it visible: `install` should print
the VM it is replacing when the plist already exists with a different
`-vm`, `status` already names the VM, and verify-podman.md must tell a
Lima/Colima user that `install -vm podman:…` switches the daemon rather
than adding one. Also observed: the installed daemon was still the v0.0.1
binary from August although the cask had been upgraded to v0.1.1 (the
cask caveat about re-running `install` after upgrades is doing real work;
doctor's skew check is the backstop).

## 7.2 results (2026-09-11)

**Landed: `install` for podman, the single-daemon warning, and a bench that
speaks every provider.** The full bench ran green on `podman:spike`, 13 legs
including both UDP directions.

### What landed

| Commit | Files |
|---|---|
| `de25a9c` record check | `internal/vmprovider/podman.go` (`MachineConfig`, `ReadPodmanMachineConfig`, `ErrNoMachine`, `PodmanMachineDirIn`) + test; `internal/vmrecord/vmrecord.go` (`Record.Disagreements`) + test; `cmd/drawbridge/main.go` (`checkPodmanRecord`) |
| `ff368e6` one daemon | `internal/install/plist.go` (`InstalledVM`, `vmFromPlist`) + test; `cmd/drawbridge/main.go` (the replacement line, help text) |
| `39cb660` bench | `internal/bench/bench_test.go` (provider dispatch, stdin scripts, provider-aware guest binary), `wedge_test.go` (same gate), `provider_test.go` (new) |

### The record check reads a file, it does not run podman

§7.2 says to compare the record against `podman machine inspect` "run as the
user before sudo hands off". There is no such moment: `sudo drawbridge
install` runs as root from its first instruction to its last, and the podman
driver refuses euid 0 by design (machine state is per-user; under root podman
looks in /var/root and truthfully reports nothing).

What does work, and is the same move `install` already makes for the secret
path, is reading a *file* under the invoking user's home:
`~/.config/containers/podman/machine/<vmtype>/<name>.json`. It carries
`Name`, `HostUser.Rootful` and `SSH.{Port,IdentityPath,RemoteUsername}`, and
the directory it sits in is the machine type. So `ReadPodmanMachineConfig`
parses those four fields and nothing else, and `Record.Disagreements` compares
machine type, rootful and ssh port. The identity path and remote user are
recorded but not compared: one key file serves every machine of a user, so it
moves for reasons that have nothing to do with this VM.

The ssh port is the sharp one. It is assigned at `podman machine init` and is
stable across stop and start, so a new one means the machine was destroyed and
recreated under the same name, which is also when the transport secret and the
published port stopped meaning anything.

Live, against a record edited to claim `rootful: true` and ssh port 12345:

```
$ drawbridge install -vm podman:spike -print
drawbridge install: …/vm-podman-spike.json no longer describes podman machine "spike":
    rootful: recorded true, now false
    ssh port: recorded 12345, now 57446 (the port is assigned at `podman machine init`, so a new one means the machine was recreated)
  The recorded endpoint tcp://127.0.0.1:4778, the published port and the transport secret all belong to the
  machine as it was. Re-run `drawbridge up podman:spike` (it re-reads the machine, rewrites the record and
  reinstalls the agent), then re-run this install.
  Read from /Users/…/.config/containers/podman/machine/libkrun/spike.json; nothing was changed.
  (exit 2)
```

A machine that is gone gets its own refusal (no drawbridge command brings it
back). An unreadable or unparsable config is a warning and never a refusal:
the file is podman's private format, and a podman release that changes it must
not be able to block an install that would have worked. Nothing rewrites the
record.

### One daemon, said out loud

`install.InstalledVM()` reads the `-vm` back out of the plist on disk (0644,
no root needed) and `install` prints one line when it differs:

```
drawbridge: replacing the installed daemon for colima:default with podman:spike; the old VM's mirror and sync sessions stop
```

Verified without root against the plist actually installed on this Mac:
`InstalledVM()` returns `colima:default`, so the user-run leg below will
print exactly that line. The same fact is now in `install`'s help text. It is
printed, not prompted: `install` has to stay scriptable. `uninstall` is
unchanged, and the parser takes "whatever follows `-vm`" so a reordered or
hand-edited plist still reads.

### Bench: the podman transport table

`DRAWBRIDGE_BENCH=1 DRAWBRIDGE_VM=podman:spike
DRAWBRIDGE_AGENT=tcp://127.0.0.1:4778 go test -count=1 -v -timeout 15m
./internal/bench/` runs 13/13 legs green, zero drops, zero failures, no port
collision with the installed colima daemon. Lima numbers are the Phase 5
record in plan.md and were NOT re-run.

| path | podman (gvproxy-publish, loopback) | lima (vznat-direct, plan.md) |
|---|---|---|
| guest→Mac outbound, connect p50 | 93 µs | 37 µs |
| guest→Mac outbound, first-byte p50 / p95 | 1.76 / 2.02 ms | 1.67 / 1.82 ms |
| guest→Mac bulk (up / down) | 1904 / 260 MB/s | 2615 / 3488 MB/s |
| Mac→guest inbound, connect p50 | 93 µs | n/a (first-byte only) |
| Mac→guest inbound, first-byte p50 / p95 | 0.78 / 1.15 ms | 0.31 / 0.47 ms |
| Mac→guest bulk (up / down) | 250 / 2028 MB/s | 3316 / 3331 MB/s |
| outbound burst rtt p50, k = 4 / 8 / 16 / 32 | 1.50 / 2.10 / 3.34 / 4.41 ms | 2.01 / 2.43 / 2.67 / 3.93 ms |
| UDP outbound rtt p50 / p95 | 195 / 251 µs | 128 / 150 µs |
| UDP inbound rtt p50 / p95 | 251 / 389 µs | 152 / 369 µs |
| guest loopback baseline (native) | 63 µs | n/a |

Read it as: **latency is in the same band** (first-byte within a millisecond
of Lima's either way, UDP within ~100 µs), and **bulk in one direction is
ten-plus times slower**, which is the 7.0 spike's leg-4 number showing up in
the real transport: gvproxy's forwarder is a single user-mode proxy and every
byte crosses it. The asymmetry is the forwarder's, not drawbridge's: each
direction is fast when the data rides the direction the guest is *sending*
into the transport (1904 MB/s guest→Mac upload, 2028 MB/s Mac→guest download)
and ~250 MB/s when it rides the leg gvproxy has to pump. The 7.0 spike
measured 223 MB/s through a bare gvproxy expose with no drawbridge in the
path at all, so this is the path's ceiling and drawbridge is not adding to it.

### What the plan got wrong, and the correction

1. **"Run `podman machine inspect` as the user before sudo hands off"** has no
   moment to happen in (§7.2 above): the whole CLI runs as root under sudo.
   Corrected to reading podman's own machine config file under the SUDO_USER
   home, which is exec-free, keeps "root never runs `podman machine`" exactly
   true, and works identically privileged or not.
2. **The bench harness could not exec off the mount on podman.** Not
   anticipated by the plan, and it fails in the most misleading possible way:
   the virtiofs mount that carries the build tree is labelled
   `context=system_u:object_r:nfs_t:s0` wholesale, systemd (`init_t`) may not
   exec `nfs_t`, so `systemd-run <mount path> benchserve` dies with
   `status=203/EXEC` while an interactive `sudo <same path>` runs fine
   (unconfined_t). The inbound legs then fail as "guest echo :47801 never
   mirrored", which reads like a mirror bug. On podman the bench tools come
   from `/usr/local/bin/drawbridge-agent` instead, the same build `up`
   installed, labelled `bin_t`. Worth remembering for 7.4: anything that runs
   a guest binary under systemd on a podman machine must run it from
   `/usr/local/bin`, never from the mount.
3. **`just bench`'s recipe needs no change** and the Lima default is
   unchanged, but the suite is no longer limactl-shaped: `guest()` puts the
   script on stdin (the `bash -c <script>` argv it used before is precisely
   the shape AGENTS.md says provider shells mangle), and the running-gate is
   the provider's `List`.

### Left for the user (needs sudo)

The released root daemon is installed for `colima:default` and running, and
this session cannot `sudo`. Run these in order; the last one puts the Mac back
the way it was.

```
sudo ./bin/drawbridge install -vm podman:spike
   # expect: "replacing the installed daemon for colima:default with podman:spike"
   # then `drawbridge status` on the podman endpoint, tcp://127.0.0.1:4778

podman machine ssh spike -- python3 -m http.server 8080 --bind 0.0.0.0   # leave running
curl -sS http://127.0.0.1:8080/ | head -3                                # on the Mac

sudo ./bin/drawbridge uninstall
sudo drawbridge install -vm colima:default    # the brew CLI, restoring the previous daemon
```


**User-run acceptance (2026-09-11).** `sudo ./bin/drawbridge install -vm
podman:spike` booted out the colima daemon, installed, and came up on
`tcp://127.0.0.1:4778 (source=flag)` with auth from
`transport-secret-podman-spike`, mirror 3 bound of 4 entries (`:22`
skipped), sync 26 advertised. A `python3 -m http.server 8080` in the guest
(transient systemd unit) answered `curl http://127.0.0.1:8080/` on the Mac
through the root daemon. `uninstall` then `sudo drawbridge install -vm
colima:default` (brew CLI) restored the previous daemon on
`vznat-leases`. Caveat: the binary used was `v0.1.1-14-g4f378a3`, built
by `just e2e` before the 7.2 commits, so the replacement line was not
exercised live in that run; `bin/` was rebuilt at `f2c4367` and the
install re-run: both directions printed the notice ("replacing the
installed daemon for colima:default with podman:spike; the old VM's
mirror and sync sessions stop", and the converse on the way back), the
podman daemon came up on 4778 and the colima daemon on `vznat-leases`.
7.2 accepted. Two things the podman daemon mirrored that 7.5 must
rule on: the guest's own transport `:4777` onto Mac `:4777`, and chrony's
udp `:323`.

**Bug found by the first `just smoke-sudo` run (2026-09-11), fixed the same
day.** The run was 8/9: install, sessions, inbound mirror, outbound sync,
uninstall and the colima restore all passed; the supervised bind on the
Mac-held port returned errno 0. The agent journal had one line,
`notify: classify socket pid=10205 fd=8: pidfd_open: no such file or
directory`, and the daemon then tried to mirror the guest's now-successful
:48081 back onto the Mac. Cause, proven with a two-thread probe on both
guests: the seccomp notification carries the calling thread's TID, and
`pidfd_open` refuses a non-leader TID (ENOENT on FCOS 7.1, EINVAL on
Ubuntu 6.8), so `IsInetStream` failed and the supervisor took its
CONTINUE-on-doubt path. Go issues the bind from whichever OS thread the
goroutine is on, hence intermittent; the e2e leg had always passed because
the small probe usually binds on its main thread. Fix: `seccomp.openPidfd`
falls back to the thread group read from `/proc/<tid>/status`
(`internal/seccomp/tgid.go`); the probe gained `-off-thread`, which binds
from a deliberately non-leader thread, and both
`TestGuestBindGetsSynchronousEADDRINUSE` and the smoke run now exercise
both placements. Verified: `just test-guest` green, the e2e leg green in
both variants on the dev VM, and 10/10 probes (5 off-thread) refused with
EADDRINUSE on `podman:spike` through a foreground daemon, the agent
logging `-> inuse` for each. This was never podman-specific; it affected
every provider. AGENTS.md gained the invariant.
The second `just smoke-sudo podman:spike` run, on the fixed agent, was
10/10 (both bind placements refused), cleanup and colima restore included.

## 7.3 results (2026-09-11)

**Landed: the wrapper dispatches on argv[0].** One binary, built and embedded
once; installed as `drawbridge-runc` it stands in for runc, as
`drawbridge-crun` for crun. Both branches verified live, each on the guest
that has the runtime in question. No guest-facing change: `up --oci` is still
docker-only and installs at the path it always did, and the dev VM's whole
suite is at baseline.

### What landed

| Commit | Files |
|---|---|
| `e0e67d0` | `internal/ociruntime/dispatch.go` + `dispatch_test.go` (new); `cmd/drawbridge-runc/main_linux.go` (thin caller); `internal/guestbin/guestbin.go` (`WrapperPath`, the engine constants) + test; `cmd/drawbridge/guest.go` (engine constants now alias guestbin's), `up.go` (`provisionOCI` installs at `WrapperPath(engine)`) |

`Runtime` carries the four things that differ: the name, the environment
variables that pin the real runtime, the probe list, and the value-flag table.
`RuntimeFor`, `Subcommand`, `Override` and `Pick` are pure; `Real` is the one
seam that touches the filesystem, which is what keeps every table testable on
the Mac.

### Two decisions worth recording

**`RuntimeFor` requires the prefix.** §6.1 says "basename `drawbridge-crun`
implies crun; anything else implies runc", and the obvious implementation
(strip `drawbridge-`, compare) also answers "I am the crun wrapper" to a
binary named plain `crun`. That is the wrong answer for the one name a real
crun actually has, and it is how a probe list ends up pointing at us. The
prefix is now required, and a bare `crun` reads as runc, matching the
documented default.

**Self-exclusion compares canonical paths.** The wrapper shipped comparing
probe candidates against `os.Executable()` as literal strings, which is a
no-op against the case that matters: `up --oci` installs the wrapper in
`/usr/local/bin`, and a package or an administrator may well have pointed
`/usr/bin/crun` at it. Following that symlink execs ourselves, which is an
unkillable fork bomb holding a container start open. `Pick` now compares
`filepath.EvalSymlinks` results, and the test fixture pins that the old
literal comparison would have failed the case.

### Verified

Unit, on the Mac: `go test ./internal/ociruntime/` green, including both
engines' real `create` argv (containerd-shim's for runc, conmon's for crun),
`--flag=value` forms, crun's booleans not swallowing the subcommand, the
symlinked-self exclusion, runc's table and probe list pinned byte for byte,
and the `WrapperPath`/`RuntimeFor` name contract pinned from the guestbin
side. `go vet ./...` and the full `-race` suite clean.

Live, argv[0] dispatch on both guests, each missing the *other* runtime so the
probe lists are exercised in both directions:

```
# Lima dev VM: runc present, no crun
$ sudo ./drawbridge-crun --version
drawbridge-crun: no real crun found (tried /usr/bin/crun, /usr/local/sbin/crun, /usr/sbin/crun, /usr/local/bin/crun; set DRAWBRIDGE_RUNTIME)
$ sudo DRAWBRIDGE_RUNTIME=/usr/sbin/runc ./drawbridge-crun --version
runc version 1.3.4-0ubuntu1~24.04.1

# podman machine spike: crun present, no runc
$ sudo ./drawbridge-crun --version
crun version 1.28
$ sudo ./drawbridge-runc --version
drawbridge-runc: no real runc found (tried /usr/sbin/runc, /usr/bin/runc, /usr/local/sbin/runc; set DRAWBRIDGE_RUNTIME or DRAWBRIDGE_RUNC)
```

Both probe binaries were staged in `/tmp` and deleted; neither guest was
changed.

Dev VM, the regression that matters (the docker path runs the same code
through the runc branch):

| Check | Result |
|---|---|
| `just vm-up`, `just build`, `just agent-up` | clean, agent active |
| `just test-guest` | all green (Phases 1 to 4, OCI protocol, UDP sync) |
| `just vm-docker` | `provision-docker: ok (docker 29.1.3, wrapper 96b58c17d919)`, the `DRAWBRIDGE_RUNC` dev override still resolves |
| `just e2e` | **14 pass / 2 root-gated skips / 0 fail**, the baseline |

The three real-container legs (`TestContainerBindGetsSynchronousEADDRINUSE`,
`TestHostNetContainerListenerMirrored`, `TestBridgedContainerNotArbitrated`)
are the byte-identical check with teeth: containers really started through the
rebuilt wrapper, so the new dispatch code carried a live `create` argv from
containerd-shim into the injection decision and out to the real runc. No port
race with the released colima daemon, which was installed and running
throughout.

### Left for the user

Nothing. Every step of 7.3 ran without sudo. The dev VM is left running with
the agent and docker active, as 7.4 will want it.


## 7.4 results

## 7.5 results

## 7.6 results
