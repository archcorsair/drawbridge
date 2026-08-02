#!/usr/bin/env bash
# Dev-flow wrapper around the guest provisioning script (`just vm-docker` /
# `just oci-up`). Runs INSIDE the dev guest as root, off the virtiofs mount.
#
# This file is deliberately thin. The provisioning itself lives in
# internal/guestbin/assets/provision-docker.sh — the same file `drawbridge up
# --oci` embeds and streams into an arbitrary user's guest — so the dev VM
# and a real attach install the wrapper the same way and restart docker under
# the same rule. Anything added here and not there is drift.
#
# Two things stay dev-only, on purpose:
#   - the offline `drawbridge/bindtest` image, which exists for the OCI test
#     suite and has no business being created in a user's VM;
#   - the /etc/docker/daemon.json merge below. On the `up` path that merge is
#     Go's (internal/guestbin/provision.go), because `drawbridge down` has to
#     restore the pre-`--oci` bytes exactly and only the writer can promise
#     that. The dev flow has no `down` to answer to and keeps the original
#     in-guest merge, which is also why it writes no /etc/drawbridge state
#     file: `down` must not revert a developer's own VM setup.
set -euo pipefail

REPO="${1:?usage: provision-docker.sh <repo-dir>}"
ASSET="$REPO/internal/guestbin/assets/provision-docker.sh"

case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64)  ARCH=amd64 ;;
  *) echo "provision-docker: unsupported guest arch $(uname -m)" >&2; exit 1 ;;
esac
RUNC="$REPO/bin/drawbridge-runc-linux-$ARCH"
AGENT="$REPO/bin/drawbridge-agent-linux-$ARCH"

# 1. Docker Engine + the wrapper runtime, from the shared script.
bash "$ASSET" --ensure-docker --runc "$RUNC" --no-docker-start

# 2. daemon.json: register the wrapper and make it the default runtime
#    (user-decided; revert = drop the default-runtime key). Merge, never
#    clobber; restart docker only when the file actually changed.
mkdir -p /etc/docker
CHANGED=$(python3 - <<'EOF'
import json, os
p = "/etc/docker/daemon.json"
cfg = {}
if os.path.exists(p):
    with open(p) as f:
        cfg = json.load(f)
before = json.dumps(cfg, sort_keys=True)
cfg.setdefault("runtimes", {})["drawbridge"] = {"path": "/usr/local/bin/drawbridge-runc"}
cfg["default-runtime"] = "drawbridge"
after = json.dumps(cfg, sort_keys=True)
if before != after:
    with open(p, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    print("yes")
else:
    print("no")
EOF
)

# 3. Restart (only if the config changed) and import the offline test image.
RESTART=()
[ "$CHANGED" = "yes" ] && RESTART=(--restart-docker)
bash "$ASSET" "${RESTART[@]}" --test-image "$AGENT"
