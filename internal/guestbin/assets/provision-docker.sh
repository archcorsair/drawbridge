#!/usr/bin/env bash
# Guest-side provisioning for the OCI integration (docs/oci-hook.md Phase C,
# docs/ergonomics.md §4.1 step 5). Runs INSIDE the guest as root.
#
# ONE source, two callers:
#   - `just vm-docker` / `just oci-up`, via the thin dev wrapper
#     scripts/provision-docker.sh, which runs it off the virtiofs mount.
#   - `drawbridge up --oci`, which streams this file into the guest
#     (internal/guestbin embeds it) and runs it there.
#
# Deliberately a script and not a Lima template edit: template changes force
# a full VM rebuild, this can iterate.
#
# What this file deliberately does NOT do is edit /etc/docker/daemon.json.
# That merge is owned by the Mac side (internal/guestbin/provision.go), for
# two reasons that only became visible once `down` existed:
#   - `down` has to restore the pre-`--oci` bytes *exactly*, which means the
#     writer and the reverter must be the same implementation. A merge here
#     and a revert there is two formatters and a diff nobody asked for.
#   - the merge used to be python3, which the dev VM has and an arbitrary
#     user's guest need not. Nothing below needs anything outside coreutils,
#     systemd and docker.
# The caller writes daemon.json first and then tells us whether to restart.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: provision-docker.sh [options]
  --ensure-docker        install Docker Engine when absent (dev flow only)
  --runc PATH            install PATH as the drawbridge runc wrapper
  --restart-docker       restart docker (caller changed daemon.json)
  --test-image PATH      import PATH as the offline drawbridge/bindtest image
  --no-docker-start      do not start docker if it is stopped
USAGE
  exit 2
}

ENSURE_DOCKER=0
RUNC=""
RESTART_DOCKER=0
TEST_IMAGE=""
START_DOCKER=1

while [ $# -gt 0 ]; do
  case "$1" in
    --ensure-docker) ENSURE_DOCKER=1 ;;
    --runc) RUNC="${2:?--runc needs a path}"; shift ;;
    --restart-docker) RESTART_DOCKER=1 ;;
    --test-image) TEST_IMAGE="${2:?--test-image needs a path}"; shift ;;
    --no-docker-start) START_DOCKER=0 ;;
    -h|--help) usage ;;
    *) echo "provision-docker: unknown option $1" >&2; usage ;;
  esac
  shift
done

WRAPPER=/usr/local/bin/drawbridge-runc

# 1. Docker Engine, rootful (Ubuntu 24.04's docker.io ships runc with
#    seccomp listenerPath support — needs runc >= 1.1.0). Opt-in: a user's
#    own VM already has an engine, and installing one uninvited is not a
#    thing `drawbridge up` gets to do.
if [ "$ENSURE_DOCKER" = 1 ] && ! command -v docker >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -yq docker.io
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "provision-docker: no docker in this guest — the runc wrapper is registered with Docker Engine's daemon.json and needs one installed" >&2
  exit 1
fi

# 2. Wrapper runtime: a COPY, never the caller's path, so Docker's default
#    runtime depends on neither the Mac-side mount staying alive nor /tmp
#    surviving a reboot. Re-run after builds; no docker restart needed — the
#    shim execs it fresh per container.
#
#    Install beside and rename: `install` truncates its destination, which
#    fails with ETXTBSY if a container happens to be starting through the
#    wrapper right then. Rename over it is atomic and works regardless.
if [ -n "$RUNC" ]; then
  install -m 0755 -o root -g root "$RUNC" "$WRAPPER.drawbridge-new"
  mv -f "$WRAPPER.drawbridge-new" "$WRAPPER"
fi

# 3. Restart only when the caller actually changed daemon.json; otherwise
#    just make sure the engine is up. Restarting docker kills running
#    containers, so it is not something to do on every idempotent re-run.
#
#    `reset-failed` first, always. systemd rate-limits unit starts
#    (StartLimitBurst/StartLimitIntervalSec), and two restarts inside the
#    burst window — which an `up --oci` after any other docker restart is —
#    put docker.service into `failed` with `start-limit-hit` and no restart
#    attempted at all. Observed live on colima. Clearing the counter makes
#    the restart deterministic instead of dependent on what happened to the
#    engine in the last ten seconds; on a healthy unit it is a no-op.
if [ "$RESTART_DOCKER" = 1 ]; then
  systemctl reset-failed docker 2>/dev/null || true
  systemctl restart docker
elif [ "$START_DOCKER" = 1 ]; then
  systemctl is-active --quiet docker || {
    systemctl reset-failed docker 2>/dev/null || true
    systemctl start docker
  }
fi

# 4. Offline test image: docker import of a local tar — NO registry pull in
#    any test path. Re-imported only when the source binary changed. Dev
#    flow only; `drawbridge up` has no business creating images.
if [ -n "$TEST_IMAGE" ]; then
  mkdir -p /var/lib/drawbridge
  SUM=$(sha256sum "$TEST_IMAGE" | cut -d' ' -f1)
  STAMP=/var/lib/drawbridge/bindtest.sha256
  if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP")" != "$SUM" ] || \
     ! docker image inspect drawbridge/bindtest >/dev/null 2>&1; then
    STAGING=$(mktemp -d)
    cp "$TEST_IMAGE" "$STAGING/drawbridge-agent"
    tar -C "$STAGING" -cf - . | docker import - drawbridge/bindtest >/dev/null
    rm -rf "$STAGING"
    echo "$SUM" > "$STAMP"
  fi
fi

DOCKER_VERSION=$(docker --version | cut -d, -f1 | awk '{print $3}')
if [ -f "$WRAPPER" ]; then
  echo "provision-docker: ok (docker $DOCKER_VERSION, wrapper $(sha256sum "$WRAPPER" | cut -c1-12))"
else
  echo "provision-docker: ok (docker $DOCKER_VERSION, no wrapper installed)"
fi
