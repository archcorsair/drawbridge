#!/bin/sh
# The tapes' one-line entry point: replace any previous fixture, serve the
# requested socket set under the given fake HOME, and run the TUI against it
# with the demo env in place. Keeping this in a script keeps the typed
# command in every tape short enough to hide cleanly.
#
#   sh demos/run.sh <home> [sockets] [rootsock]
#
# DRAWBRIDGE_TUI_BG defaults to dark; a tape overrides it inline
# (`DRAWBRIDGE_TUI_BG=light sh demos/run.sh ...`). rootsock defaults to an
# absent path, which hides any real installed root daemon from the demo;
# the fight tapes point it at the fixture's fake root socket instead.
set -e
HOME_DIR=${1:?usage: demos/run.sh <home> [sockets] [rootsock]}
SOCKETS=${2:-colima,dev,skew,broken}
ROOT_SOCK=${3:-$HOME_DIR/no-root.sock}
pkill -f tui-demo-daemon 2>/dev/null || true
rm -rf "$HOME_DIR"
./demos/bin/tui-demo-daemon -home "$HOME_DIR" -sockets "$SOCKETS" >/dev/null 2>&1 &
sleep 1
clear
HOME="$HOME_DIR" \
	DRAWBRIDGE_TUI_BG="${DRAWBRIDGE_TUI_BG:-dark}" \
	DRAWBRIDGE_TUI_DEMO_DOCTOR="$HOME_DIR/doctor" \
	DRAWBRIDGE_INTROSPECT_ROOT="$ROOT_SOCK" \
	./demos/bin/drawbridge tui
pkill -f tui-demo-daemon 2>/dev/null || true
