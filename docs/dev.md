# Developing drawbridge

The workflow for working *on* drawbridge. Using it is the
[README](../README.md); the two flows are kept apart on purpose, because they
want different VMs and different daemons.

Conventions and the non-obvious invariants are in [AGENTS.md](../AGENTS.md).
Architecture is [plan.md](plan.md); current status is [HANDOFF.md](HANDOFF.md).

## Toolchain

Everything comes from [mise](https://mise.jdx.dev) (Go, just, lima — versions
pinned in `mise.toml`) and every task from `just`. Never `brew`, never `make`.

```sh
mise install && mise reshim
```

`go.mod`'s `go 1.25.0` is a deliberate downstream *minimum* (cilium/ebpf), not
the dev toolchain — CI proves the floor on {1.25.x, 1.26.x}.

clang/LLVM for BPF compilation lives **inside the guest**, not on the Mac.
Generated Go is committed, so a Mac-side `go build` never needs clang.

## The dev VM

```sh
just vm-up        # Ubuntu 24.04 via Lima, BPF toolchain provisioned
just vm-docker    # docker + drawbridge-runc + offline test image (alias: oci-up)
just vm-down      # stop
just vm-delete    # destroy
```

`vm-up` pins `LIMA_SSH_PORT_FORWARDER=true`: Lima's default gRPC tunnel drops
TCP half-close, which breaks upload-then-ack flows on the fallback transport
path. Lima's own port forwarding is otherwise disabled by the template — it
would duplicate drawbridge — and only the agent's control port is forwarded.

`vm-docker` is idempotent and restarts docker only when `daemon.json` actually
changes. Re-run it after a rebuild to refresh the wrapper runtime and the test
image.

## Build and generate

```sh
just gen          # bpf2go inside the guest; generated Go is committed
just build        # guest binaries first, then the Mac binaries
just clean-embeds # drop the embedded guest copies
```

`build`'s ordering is a real dependency, not tidiness: the CLI `//go:embed`s
the four guest binaries out of `internal/guestbin/bin/`, so they have to exist
— and be copied into the embed directory — before `go build ./cmd/drawbridge`
runs. Building the Mac side first would silently bundle whatever the previous
build left behind. `internal/guestbin/bin/` is gitignored apart from its
`.keep`; a fresh checkout compiles with an empty bundle and `drawbridge up`
says so (`ErrNotBundled`).

Kernel-hook changes need `just gen` **and** `just test-guest` — verifier and
attach errors only appear in the guest.

## Run the agent

```sh
just agent-up     # transient systemd unit in the guest
just agent-down
just agent-log    # journalctl -u drawbridge-agent
```

`just agent-up` and `drawbridge up` **replace each other**: `up` installs a
persistent unit under the same name, and systemd-run refuses a transient unit
while that file exists, so the dev recipe reclaims the name first.

## Tests

```sh
just test-guest   # gateway + tracker + macsync suites, as root in the guest
just e2e          # Mac-side end-to-end (needs agent-up)
just e2e-v        # ...streaming every leg
just e2e-root     # the <1024 legs only root can run
just bench        # latency/throughput, both directions (needs agent-up)
```

`e2e` is quiet by default — the tally is the answer and failures print
themselves.

**The e2e rule that will bite you:** the suite needs the agent sessions for
itself, so it must run with `just agent-up` and **no installed daemon**. If you
have one installed, boot it out first:

```sh
sudo launchctl bootout system/com.archcorsair.drawbridged
```

`sudo just e2e-root` is unreliable (mise shims are not on root's PATH), which
is why the recipe does its own `sudo -E env "PATH=$PATH"` passthrough.

Benchmark numbers taken while a Little Snitch-class network extension is active
are invalid — see [notes/local-network-permission.md](notes/local-network-permission.md).

## Layout

```
cmd/drawbridge         CLI: up / down / install / uninstall / status / doctor / tui
cmd/drawbridged        Mac-side daemon: mirrors, sync, reservations
cmd/drawbridge-agent   guest agent: BPF gateway + tracker + seccomp supervisor
cmd/drawbridge-runc    OCI wrapper runtime (bind arbitration for containers)
internal/bpf           BPF C + cilium/ebpf loaders (generated code committed)
internal/proxy         TCP splice / UDP flow relay on the gateway address
internal/agent         guest agent: maps, proxies, dial pool, transport dispatch
internal/mirror        Mac mirrors of guest listeners (TCP + UDP)
internal/macsync       Mac listener sync into the guest + reverse-dial pool
internal/ociruntime    runc-wrapper internals (profile inspection, spec rewrite)
internal/seccomp       pure-Go seccomp-unotify machinery
internal/transport     endpoint grammar and dial/listen seam (tcp/unix, vsock reserved)
internal/transportauth static-HMAC handshake, per-VM secrets
internal/limaaddr      agent endpoint resolution (limactl, DHCP leases as root)
internal/vmprovider    Lima / Colima detection, shell, leases, forwarding
internal/guestbin      embedded guest binaries + provision-state merge/revert
internal/install       LaunchDaemon install machinery
internal/introspect    read-only daemon state snapshot (status, tui, doctor)
internal/doctor        the check catalog
internal/tui           the live dashboard (charm deps live only here)
internal/udpframe      frozen v1 UDP frame codec
internal/buildinfo     the version stamped in at link time
internal/harness       in-guest acceptance tests
internal/benchtool     shared bench client/server logic (guest subcommands)
internal/e2e           Mac-side end-to-end tests
internal/bench         latency/throughput benchmark
lima/                  dev VM template
scripts/               guest provisioning for the dev flow
docs/                  plan, design notes, handoff
```

## Design notes

| Doc | What it covers |
|---|---|
| [plan.md](plan.md) | Architecture, the four core phases, results and numbers |
| [transport.md](transport.md) | Endpoint grammar, conn types, the wire |
| [transport-auth.md](transport-auth.md) | Per-VM static-HMAC transport auth |
| [oci-hook.md](oci-hook.md) | The runc wrapper and seccomp-unotify contract |
| [udp.md](udp.md) | The frozen v1 UDP frame |
| [privileged-daemon.md](privileged-daemon.md) | The root LaunchDaemon |
| [ergonomics.md](ergonomics.md) | Packaging, `up`/`down`, release phases |
| [doctor.md](doctor.md) | The check catalog and the introspection endpoint |
| [tui.md](tui.md) | The TUI; §4's keybinding map is a docs contract |
| [verify-colima.md](verify-colima.md) | The live Colima verification recipe |
| [notes/local-network-permission.md](notes/local-network-permission.md) | The macOS-side pathologies, wire-proven |

When reasoning about kernel behavior, prefer `bpftool map dump` / `bpftrace` in
the guest over memory. Hook ordering is where the bugs are.
