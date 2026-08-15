# Color semantics, dark palette: every status cell is glyph plus word
# (mirror states, session dots, doctor verdicts), the accent pair carries
# focus, and the verdict colors stay reserved for verdicts.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/colors-dark.tape

Output demos/out/colors-dark.gif

Set Shell bash
Set FontSize 13
Set Width 900
Set Height 470
Set Padding 12
Set Framerate 12
Set TypingSpeed 30ms
Set Theme "Catppuccin Mocha"

Hide
# The recorder lags input by a nondeterministic warmup; everything latency
# sensitive happens hidden, and the long post-launch wait lets the renderer
# catch up fully so the gif opens on live footage.
Sleep 2s
Type "sh demos/run.sh /tmp/dbd-cold"
Enter
Sleep 30s
Show

# The dashboard: glyph state cells, session dots, the ephemeral sync fold.
Sleep 3s
Type "x"
Sleep 2s
# Refusal IDs colored by class (auth red, skip dim, the rest warn).
Type "r"
Sleep 2.5s
Type "r"
Sleep 800ms
# Doctor verdicts: the check, the bang, the cross, the quiet dot, the i.
Type "d"
Sleep 4s
Type "j"
Sleep 400ms
Type "j"
Sleep 400ms
Enter
Sleep 8s

Hide
Type "q"
Sleep 500ms
