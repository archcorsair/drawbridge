# Motion: the header heartbeat brightens at each 1 Hz fetch, and every way
# of switching daemons (tab, the switcher's enter, a number) pulses the
# summary chrome in the accent color for a few frames.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/motion.tape

Output demos/out/motion.gif

Set Shell bash
Set FontSize 13
Set Width 900
Set Height 470
Set Padding 12
Set Framerate 15
Set TypingSpeed 30ms
Set Theme "Catppuccin Mocha"

Hide
# The recorder lags input by a nondeterministic warmup; everything latency
# sensitive happens hidden, and the long post-launch wait lets the renderer
# catch up fully so the gif opens on live footage.
Sleep 2s
Type "sh demos/run.sh /tmp/dbd-mot"
Enter
Sleep 30s
Show

# The heartbeat dot breathes at the refresh cadence.
Sleep 3s

# tab: the summary chrome flashes accent as the selection lands.
Tab@1.8s 2
Sleep 1.5s

# The switcher: cursor, then enter; the flash confirms the landing.
Type "v"
Sleep 1.2s
Type "j"
Sleep 800ms
Type "j"
Sleep 1s
Enter
Sleep 2s

# The number jump, same feedback.
Type "1"
Sleep 8s

Hide
Type "q"
Sleep 500ms
