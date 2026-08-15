# The attention strip, in the whole fleet story it sits in: the fighting
# banner, the elsewhere line pointing at the fires on unselected daemons
# (with the root/user flavor tag on the fighting pair), the skew card, the
# unreadable socket, and the switcher naming them all.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/attention-strip.tape

Output demos/out/attention-strip.gif

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
Type "sh demos/run.sh /tmp/dbd-fleet colima,dev,skew,broken,fight /tmp/dbd-fleet/root.sock"
Enter
Sleep 30s
Show

# The fake root daemon is selected: the strip points at the user combatant
# and the degraded lima:dev while the banner names the fight.
Sleep 4s
# Cycle onto the healthy user daemon: the strip keeps pointing at the fires.
Type "l"
Sleep 3.5s
# Onto the degraded daemon itself: its own trouble leaves the strip.
Type "l"
Sleep 3s
# The switcher: the fighting pair adjacent, skew and unreadable rows saying
# only what they know.
Type "v"
Sleep 3.5s
Escape
Sleep 8s

Hide
Type "q"
Sleep 500ms
