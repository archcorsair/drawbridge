# Refusal grouping: lima:dev's auth storm streams into the pane at one line
# every two seconds; u folds the repeats into one counted line per cause, so
# the one-off refusals stay visible beside the storm.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/refusal-grouping.tape

Output demos/out/refusal-grouping.gif

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
Type "sh demos/run.sh /tmp/dbd-ref"
Enter
Sleep 30s
Show

# Over to the storming daemon; the footer badge is already counting.
Sleep 2s
Type "l"
Sleep 1.5s
# The raw pane: the storm scrolls, the follow window keeps the newest line.
Type "r"
Sleep 5s
# u: one counted line per cause; the one-offs keep their raw spelling.
Type "u"
Sleep 5s
# And back to raw.
Type "u"
Sleep 8s

Hide
Type "q"
Sleep 500ms
