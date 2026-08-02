# drawbridge dev commands (tools via mise: go, lima, just)

vm := "drawbridge"

# stamped into internal/buildinfo at link time; no tags yet, so this is a
# short hash today. Releases pass a real vX.Y.Z through goreleaser instead.
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
ldflags := "-X github.com/archcorsair/drawbridge/internal/buildinfo.Version=" + version

# boot (or resume) the Ubuntu dev VM with the BPF toolchain.
# SSH forwarder pinned: Lima's default gRPC tunnel drops TCP half-close,
# which breaks upload-then-ack flows on the fallback transport path.
vm-up:
    LIMA_SSH_PORT_FORWARDER=true limactl start --name={{vm}} --tty=false lima/drawbridge-dev.yaml || LIMA_SSH_PORT_FORWARDER=true limactl start --tty=false {{vm}}

vm-down:
    limactl stop {{vm}}

vm-delete:
    limactl delete -f {{vm}}

# bpf2go runs in the guest (needs clang); generated Go files are committed
gen:
    limactl shell {{vm}} -- bash -c 'cd {{justfile_directory()}} && PATH=$PATH:/usr/local/go/bin go generate ./internal/bpf/'

# host-side binaries. The ordering is a real dependency, not tidiness: the
# CLI embeds the four guest binaries (internal/guestbin, docs/ergonomics.md
# §2.2), so they have to exist — and be copied into the embed directory —
# before `go build ./cmd/drawbridge` runs. Building the Mac side first would
# silently bundle whatever the previous build left behind.
#
# internal/guestbin/bin/ is gitignored apart from its .keep; a fresh checkout
# compiles with an empty bundle and `drawbridge up` says so (ErrNotBundled).
build:
    mkdir -p bin internal/guestbin/bin
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '{{ldflags}}' -o bin/drawbridge-agent-linux-arm64 ./cmd/drawbridge-agent
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '{{ldflags}}' -o bin/drawbridge-agent-linux-amd64 ./cmd/drawbridge-agent
    GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags '{{ldflags}}' -o bin/drawbridge-runc-linux-arm64 ./cmd/drawbridge-runc
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '{{ldflags}}' -o bin/drawbridge-runc-linux-amd64 ./cmd/drawbridge-runc
    cp bin/drawbridge-agent-linux-arm64 internal/guestbin/bin/agent_linux_arm64
    cp bin/drawbridge-agent-linux-amd64 internal/guestbin/bin/agent_linux_amd64
    cp bin/drawbridge-runc-linux-arm64 internal/guestbin/bin/runc_linux_arm64
    cp bin/drawbridge-runc-linux-amd64 internal/guestbin/bin/runc_linux_amd64
    go build -ldflags '{{ldflags}}' -o bin/ ./cmd/drawbridge ./cmd/drawbridged

# drop the embedded copies, so the next `go build` produces a CLI that
# reports ErrNotBundled instead of shipping a stale agent
clean-embeds:
    find internal/guestbin/bin -type f ! -name .keep -delete

# validate .goreleaser.yaml — schema plus deprecated properties. Cheap, no
# network, no build; run it after touching the release config.
release-check:
    goreleaser check

# the whole release, built locally into dist/ and uploaded nowhere: the
# before-hooks redo `build`'s guest-binaries-then-Mac ordering, the darwin
# builds are lipo'd universal, and the Homebrew cask is rendered but not
# pushed (--snapshot has no publish step, and skip_upload: auto belts it).
# Real releases come from a pushed vX.Y.Z tag via .github/workflows/release.yml.
release-snapshot:
    goreleaser release --snapshot --clean

# provision Docker Engine + drawbridge-runc + offline test image in the
# guest (idempotent; restarts docker only when daemon.json changes)
vm-docker: build
    limactl shell {{vm}} -- sudo bash {{justfile_directory()}}/scripts/provision-docker.sh {{justfile_directory()}}

# refresh the wrapper runtime + test image after a rebuild
alias oci-up := vm-docker

# guest test suite (Phase 1 gateway assertions + Phase 2 tracker), as root
test-guest:
    limactl shell {{vm}} -- bash -c 'cd {{justfile_directory()}} && sudo env PATH=$PATH:/usr/local/go/bin go test -count=1 -v -timeout 10m ./internal/harness/ ./internal/agent/'

alias test-phase1 := test-guest

# (re)start the agent inside the guest as a transient systemd unit.
# `drawbridge up` installs a persistent unit under the same name; systemd-run
# refuses to create a transient unit while that unit file exists, so the dev
# flow reclaims the name first (§8 Phase 4: "each stops the other").
agent-up: build
    limactl shell {{vm}} -- sudo bash -c 'systemctl disable --now drawbridge-agent 2>/dev/null; rm -f /etc/systemd/system/drawbridge-agent.service; systemctl daemon-reload; systemctl reset-failed drawbridge-agent 2>/dev/null; systemd-run --unit=drawbridge-agent --collect {{justfile_directory()}}/bin/drawbridge-agent-linux-arm64'

agent-down:
    limactl shell {{vm}} -- sudo systemctl stop drawbridge-agent

agent-log:
    limactl shell {{vm}} -- sudo journalctl -u drawbridge-agent -n 50 --no-pager

# Phase 2 end-to-end from the Mac: guest listener on Mac localhost.
# Quiet by default — the tally is the answer, and failures print themselves;
# `just e2e-v` streams every leg. Needs `just agent-up`; no installed daemon
# (an installed drawbridged holds the agent sessions the harness needs —
# `sudo launchctl bootout system/com.archcorsair.drawbridged` first).
e2e: build
    DRAWBRIDGE_E2E=1 go test -count=1 ./internal/e2e/

# every leg, verbosely
e2e-v: build
    DRAWBRIDGE_E2E=1 go test -count=1 -v ./internal/e2e/

# guest :80 mirrored on Mac loopback, and a Mac-held :80 refusing a guest bind
# with a synchronous EADDRINUSE. `sudo just e2e-root` is unreliable (mise
# shims are not on root's PATH), hence the explicit env passthrough. Needs
# `just agent-up`; no installed daemon — the suite runs its own mirror client.
# the <1024 e2e legs only root can run (docs/privileged-daemon.md §10 Phase 3)
e2e-root: build
    sudo -E env "PATH=$PATH" DRAWBRIDGE_E2E=1 go test -count=1 -v -run TestPrivileged ./internal/e2e/

# latency/throughput benchmark, both directions (needs agent-up)
bench: build
    DRAWBRIDGE_BENCH=1 go test -count=1 -v -timeout 15m ./internal/bench/
