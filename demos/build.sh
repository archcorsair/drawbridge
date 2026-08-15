#!/bin/sh
# Builds the binaries every tape under demos/ expects at demos/bin/.
#
# The CLI is stamped v0.1.0 so the fixture's current daemons match it and the
# deliberately stale one (lima:dev, v0.0.9) trips the skew chip on camera.
#
# Record with vhs. Everything comes from mise (`mise install` picks up vhs,
# ttyd, ffmpeg and cmake from mise.toml; ttyd rides the conda backend, since
# neither aqua nor the GitHub releases ship a darwin binary), then:
#
#   sh demos/build.sh
#   mise x -- vhs demos/<name>.tape     # writes demos/out/<name>.gif
#
# Fallback, only if the conda ttyd backend fails on a machine: build ttyd
# from source with the mise cmake and no brew. Build libuv (v1.48.0, cmake,
# -DLIBUV_BUILD_TESTS=OFF), then libwebsockets (v4.3.3,
# -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DLWS_WITH_SSL=OFF -DLWS_WITH_LIBUV=ON
# -DLWS_WITHOUT_TESTAPPS=ON), then ttyd (1.7.7,
# -DCMAKE_POLICY_VERSION_MINIMUM=3.5), all with CMAKE_INSTALL_PREFIX and
# CMAKE_PREFIX_PATH pointing at one local prefix; `install_name_tool
# -add_rpath <prefix>/lib <prefix>/bin/ttyd`, and put <prefix>/bin on PATH.
set -e
cd "$(dirname "$0")/.."
mkdir -p demos/bin demos/out
go build -ldflags "-X github.com/archcorsair/drawbridge/internal/buildinfo.Version=v0.1.0" -o demos/bin/drawbridge ./cmd/drawbridge
go build -o demos/bin/tui-demo-daemon ./cmd/tui-demo-daemon
echo "built demos/bin/drawbridge and demos/bin/tui-demo-daemon"
