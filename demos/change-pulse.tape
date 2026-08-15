# The change pulse and age tint, told through lima:dev's flapping mirror
# session: every time the session heals, its rows come back as changes, the
# gutter marks each with a diamond for five seconds, fresh SINCE values read
# warm, and settled rows recede. In between, the "session down, press d"
# wording holds the table's place. No keys after the daemon switch: the
# fixture's cycle does the work.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/change-pulse.tape

Output demos/out/change-pulse.gif

Set Shell bash
Set FontSize 13
Set Width 900
Set Height 470
Set Padding 12
Set Framerate 10
Set TypingSpeed 30ms
Set Theme "Catppuccin Mocha"

Hide
# The recorder lags input by a nondeterministic warmup; everything latency
# sensitive happens hidden, and the long post-launch wait lets the renderer
# catch up fully so the gif opens on live footage.
Sleep 2s
Type "sh demos/run.sh /tmp/dbd-pulse"
Enter
Sleep 30s
Show

Sleep 1.5s
Tab
# A full flap cycle plays: the session drops, heals, the returning rows
# carry the diamond and warm SINCE values, then the table settles.
Sleep 32s

Hide
Type "q"
Sleep 500ms
