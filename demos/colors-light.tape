# Color semantics, light palette: the same glyph-plus-word cells with the
# light halves of every pair, dim off ANSI 7 so it stays readable on white,
# pinned with DRAWBRIDGE_TUI_BG=light.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/colors-light.tape

Output demos/out/colors-light.gif

Set Shell bash
Set FontSize 13
Set Width 900
Set Height 470
Set Padding 12
Set Framerate 12
Set TypingSpeed 30ms
Set Theme "Catppuccin Latte"

Hide
# The recorder lags input by a nondeterministic warmup; everything latency
# sensitive happens hidden, and the long post-launch wait lets the renderer
# catch up fully so the gif opens on live footage.
Sleep 2s
Type "DRAWBRIDGE_TUI_BG=light sh demos/run.sh /tmp/dbd-coll"
Enter
Sleep 30s
Show

# The dashboard on a light terminal: dim is bright black, never invisible.
Sleep 3.5s
# Doctor verdicts in the light halves.
Type "d"
Sleep 4s
Type "j"
Sleep 400ms
Enter
Sleep 8s

Hide
Type "q"
Sleep 500ms
