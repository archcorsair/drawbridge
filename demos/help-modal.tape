# The help modal: a centered card over the dimmed live screen, two columns
# at this width, accent key labels, and the you-are-here marker following
# the current view (Global on the dashboard, Doctor view inside it).
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/help-modal.tape

Output demos/out/help-modal.gif

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
Type "sh demos/run.sh /tmp/dbd-help"
Enter
Sleep 30s
Show

Sleep 2.5s
# The card floats over the live dashboard, which keeps refreshing dimly.
Type "?"
Sleep 4s
Escape
Sleep 1s
# Inside the doctor view the marker moves to its group.
Type "d"
Sleep 3.5s
Type "?"
Sleep 3.5s
Escape
Sleep 8s

Hide
Type "q"
Sleep 500ms
