# drawbridge

Real `--network host` semantics for containers running in a macOS VM: a guest
listener shows up on Mac `localhost`, a guest connect to `127.0.0.1` reaches
your native Mac services, and a container bind that collides with a Mac-held
port fails with `EADDRINUSE` on the spot.

> **Alpha. A personal research project.** It works, and it is verified end to
> end on one Mac and two VM providers — but there is no release yet, no
> stability promise, and the wire protocol, CLI flags and on-disk state can all
> change without notice. Recent macOS betas actively fight parts of this (see
> [Common issues](#common-issues)). Run it on a dev machine you are happy to
> debug.

## Why this exists

On Linux, `--network host` puts a container in the host's network namespace and
everything just works. On macOS your containers live inside a Linux VM — Lima,
Colima, Docker Desktop, OrbStack, all of them — and macOS has no network
namespaces at all. So `--network host` still "works", it just shares the *VM's*
namespace, not your Mac's. The port you bound is not on your Mac, `curl
localhost:8080` gets nothing, and the container can't see the Postgres you have
running natively.

The commercial products solve this. OrbStack and Docker Desktop both merge the
guest's loopback with the Mac's, with ordinary user-space sockets on the Mac and
kernel-side help inside the VM they ship. It is a good approach. It is also
locked inside an all-in-one product — if you run the open stack (Lima, Colima,
Podman machine) there is nothing you can bolt on to get the same behavior.

drawbridge is that bolt-on component, at L4, for a VM you already run. eBPF
inside the guest watches listeners and arbitrates loopback connects; a plain
user-space daemon on the Mac mirrors and dials. Three semantics, no more:

1. **Guest listener → Mac `localhost`.** A container that binds `:8080` becomes
   a real listener on Mac `127.0.0.1:8080`.
2. **Guest `127.0.0.1` → Mac services.** A guest connect to loopback is steered
   to whatever your Mac holds on that port, same port number, transparently.
3. **Colliding bind → synchronous `EADDRINUSE`.** If your Mac already holds
   `:8080`, the container's `bind()` fails immediately, the way it would on
   Linux — not silently, not later. Nobody else does this one.

## How it fits together

```
                Mac                    │              Linux VM (guest)
  ─────────────────────────────────────┼──────────────────────────────────────

  1) guest listener ──► Mac localhost

      curl http://localhost:8080       │    nginx --network host :8080
                 │                     │                 ▲
                 ▼                     │                 │  seen by eBPF
      ┌──────────────────────────┐     │    ┌────────────┴───────────┐
      │  mirror  127.0.0.1:8080  │─'S'─┼───►│ agent ─ splice ─ :8080 │
      └──────────────────────────┘     │    └────────────────────────┘

  2) Mac listener ──► guest 127.0.0.1

      ┌──────────────────────────┐     │    ┌────────────────────────┐
      │ postgres 127.0.0.1:5432  │◄'D'─┼────│ gateway proxy 127.0.0.2│
      └──────────────────────────┘     │    └────────────▲───────────┘
                                       │                 │  eBPF rewrites
                                       │    psql -h 127.0.0.1 -p 5432

  3) colliding bind ──► synchronous EADDRINUSE

      ┌──────────────────────────┐     │    ┌────────────────────────┐
      │ reserve :8080 before ack │◄'R'─┼────│  seccomp supervisor    │
      └──────────────────────────┘     │    └────────────▲───────────┘
                                       │                 │  answer: EADDRINUSE
                                       │    container bind(:8080)
```

`drawbridged` on the Mac and `drawbridge-agent` in the guest hold one TCP
connection per purpose — events, sync, reservations, and one per data flow.
Only the IP is ever rewritten, never the port, which is why the un-rewrites are
stateless. Architecture in [docs/plan.md](docs/plan.md); the wire in
[docs/transport.md](docs/transport.md).

## Is this for you?

Probably yes if:

- You run containers in Lima or Colima on macOS and you miss `--network host`.
- You'd rather read the eBPF than file a ticket against a black box — when
  something in the path misbehaves you can tcpdump both sides of your own stack.
- You are fine with alpha software sitting in your dev networking path.

Probably not if:

- It's for production, or for anyone but you.
- You need supported behavior — Docker Desktop and OrbStack have this feature,
  finished and warrantied. Use theirs.
- A root LaunchDaemon is not acceptable in your setup. The unprivileged
  alternative is a foreground daemon that can only mirror ports ≥1024 (macOS
  reserves <1024 for root and has no sysctl to relax it), and it is subject to
  the macOS privacy gates that a launchd daemon is exempt from.

Also: Apple silicon only, macOS only, Lima and Colima only (Podman machine is
planned). Nothing is signed or notarized.

## Install

There is no release yet, so today this means building from source.

**Prerequisites**

- An Apple silicon Mac. Developed and verified on macOS 27; older versions are
  untested rather than unsupported.
- A **running** Lima or Colima VM with `vmType: vz` — drawbridge attaches to a
  VM you already have and never creates one. The guest needs a BTF kernel
  (≥ 5.7), cgroup v2 and systemd; Ubuntu 24.04, the Colima default, is fine.
- [mise](https://mise.jdx.dev) for the toolchain (Go, just, lima).

**Build**

```sh
git clone https://github.com/archcorsair/drawbridge
cd drawbridge
mise install && mise reshim
just build          # guest binaries first, then bin/drawbridge + bin/drawbridged
```

The guest binaries are embedded into the CLI, so `bin/drawbridge` alone can
provision a guest. That is also why the build order matters.

**Provision the guest**

```sh
bin/drawbridge up                 # one running vz VM: instance can be omitted
bin/drawbridge up colima          # or name it; lima:myvm / colima:default also work
bin/drawbridge up colima --oci    # additionally install the runc wrapper (see below)
```

No sudo on the Mac — the privileged half happens inside the guest. `up`
installs the agent as a systemd unit and writes a per-VM transport secret on
both sides. It is idempotent: re-run it to upgrade. `bin/drawbridge down`
reverses exactly what it did.

`--oci` is opt-in because it edits Docker's `daemon.json` in your guest to
register the wrapper runtime. Without it, mirroring, outbound and host-process
`EADDRINUSE` all still work — only *containerized* bind arbitration (semantic 3
above) needs the wrapper.

**Run the Mac daemon** — pick one posture:

```sh
sudo bin/drawbridge install -vm colima:default   # root LaunchDaemon (recommended)
```

Ports <1024, survives reboot, and exempt from the macOS Local Network gate and
the pcblist filtering that bite terminal-launched processes. Add `-vm-mac
<addr>` to pin which VM the root daemon will trust (`-print` previews
everything and tells you the exact command to read the address).

```sh
bin/drawbridged -vm colima:default               # foreground, no sudo
```

Ports ≥1024 only, dies with the terminal, and on macOS 27 betas it may see an
empty Mac listener set (see [Common issues](#common-issues)). Good for a quick
look; not the posture to live in.

Homebrew and tagged binaries are planned for v0.1.0. `brew install
archcorsair/drawbridge/drawbridge` does **not** work yet.

## Use it

The demo, with the root daemon installed:

```sh
# in the guest
docker run --rm --network host nginx

# on the Mac
curl http://localhost:80
```

With the foreground daemon, pick a port ≥1024 — run a container that listens on
`:8080`, then `curl http://localhost:8080`.

The reverse direction needs no setup at all: from inside a `--network host`
container, `127.0.0.1:5432` reaches the Postgres running natively on your Mac.

### `drawbridge status`

One compact block per running daemon, read from its introspection socket:

```
drawbridged  running · pid 63257 · 6d1a67e · installed (launchd)
  vm:        drawbridge
  endpoint:  tcp://192.168.64.2:4777 (vznat-leases)
  auth:      static-hmac-v1 (secret ok)
  mirror:    session up · 1 bound of 3 entries
  sync:      session up · 19 advertised · 8 parked
```

`-v` adds launchd state, artifact paths and the log tail — which also print by
default when no daemon answers, because there they are the only evidence. Exit
codes: 0 running, 1 installed but not running, 3 not installed.

### `drawbridge tui`

A live read-only dashboard over the same socket: the mirror table, the sync
set, endpoint resolution, auth posture, refusals, and doctor on demand. It
cannot command the daemon — the socket has no request grammar.

The footer advertises five keys and that is the whole surface:

```
tab next daemon · r refusals · d doctor · ? help · q quit
```

`←`/`→` and `h`/`l` also cycle daemons; `d` runs the full doctor catalog inside
the TUI (`enter` expands a finding, `R` re-runs, `p` re-runs with the probe);
`?` opens the complete key map. Full map: [docs/tui.md](docs/tui.md) §4.

### `drawbridge doctor`

The health check, and the first thing to run when something is off. It knows
every diagnosis this project has earned the hard way — providers, guest
prerequisites, agent liveness and version match, endpoint resolution, the vzNAT
route, the macOS Local Network gate, content filters, daemon state, forwarder
coexistence, transport auth.

```sh
drawbridge doctor            # ok checks print their title only
drawbridge doctor -v         # ...with evidence
drawbridge doctor -probe     # + the active half-close probe (~20s)
drawbridge doctor -json      # structured, for a bug report
sudo drawbridge doctor       # the root-vs-user discriminator for network gates
```

It is read-only: it prints remediations and never runs them, and never spawns
sudo. Exit 0 nothing failed, 1 something did, 2 doctor itself could not gather.

## Common issues

Every row ends in doctor or a one-liner. Doctor's output is the long version.

| Symptom | What it is | Fix |
|---|---|---|
| `sync: … 0 advertised` from a terminal-launched `drawbridged` | macOS 27 betas filter `net.inet.tcp.pcblist_n` per *responsible app* — a process launched from a terminal sees an empty listener list, no error. Mirroring still works; only Mac→guest goes dark. | `sudo drawbridge install` — a launchd daemon is exempt. |
| Guest unreachable; dials time out with no error | Either the vmnet route was deleted out from under you (Tailscale and Little Snitch are the observed suspects), or the Local Network permission is denying this binary. | `drawbridge doctor` checks 5 and 6; the route fix is one `route -n add`, the permission fix is `sudo drawbridge install`. |
| Connections stall ~2s, or a half-closed read never returns | A network-extension content filter (Little Snitch-class) doing first-payload DPI. Note that "disable filter" does *not* stop it — only deactivating the extension does. | `drawbridge doctor` check 7, and `-probe` for check 8. |
| Everything worked, then a rebuild broke it | Version skew between the CLI, the installed daemon and the guest agent. They are meant to move in lockstep. | `drawbridge up && sudo drawbridge install` |
| Guest `:22` never appears on the Mac | Deliberate: the VM's sshd is on the default skip list. | `-skip ""` (or your own list) on `drawbridged` / `drawbridge install`. |
| `just e2e` fails for contributors | An installed `drawbridged` holds the agent sessions the harness needs. | `sudo launchctl bootout system/com.archcorsair.drawbridged` first. |

If doctor says something you don't believe, `-json` output is designed to be
pasted into an issue. Background on the macOS-side pathologies:
[docs/notes/local-network-permission.md](docs/notes/local-network-permission.md).

## Status and roadmap

Working and verified end to end today: the kernel loopback gateway, guest
listener tracking and Mac mirrors, Mac listener sync with outbound dial,
synchronous binds via a seccomp-unotify OCI wrapper (Docker/runc), UDP in both
directions, the privileged LaunchDaemon for sub-1024 ports, per-VM transport
authentication, `up`/`down` provisioning for Lima and Colima, `doctor`, and the
TUI. `docker run --network host nginx` in the guest really does serve
`http://localhost:80` on the Mac.

Next: v0.1.0 — a tagged release through goreleaser, universal binaries, and a
Homebrew tap. After that: row detail in the TUI, and Podman machine + crun.
Current state always lives in [docs/HANDOFF.md](docs/HANDOFF.md).

## Development

Working on drawbridge itself is a different workflow from using it — the dev VM
and `just` tasks are in **[docs/dev.md](docs/dev.md)**. Conventions and the
non-obvious invariants are in [AGENTS.md](AGENTS.md); design notes live under
[docs/](docs/).

## About the scope of this

This is developer tooling in the same category as a port forwarder or a local
proxy, and it means no harm. Everything happens on the developer's own machine,
over loopback, between a VM they own and services they are already running.
There are no kernel extensions and no restricted entitlements on the Mac — the
Mac side is ordinary BSD sockets in user space. The eBPF programs run only
inside the developer's own Linux guest, loaded by an agent that developer
installed. Nothing intercepts anyone else's traffic, nothing escalates beyond
the privileges the OS grants normally, and nothing evades a security control.
It closes a well-known gap the same way the commercial products already do.

## License

Apache-2.0.
