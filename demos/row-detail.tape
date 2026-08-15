# The row cursor and detail strip, with the per-entry counters: the cursor
# opens the strip on a bound row (state, meaning, next command, traffic),
# the strip follows the cursor as the scripted bind flip re-sorts the table
# onto the lsof line, and tab onto the stale lima:dev shows the honest
# absence a pre-accounting daemon gets instead of counters.
# Run from the repo root after `sh demos/build.sh`, then:
#   mise x -- vhs demos/row-detail.tape

Output demos/out/row-detail.gif

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
Type "sh demos/run.sh /tmp/dbd-row"
Enter
Sleep 30s
Show

# Drive the cursor onto a bound row and open the strip: state, what it
# means, the next command, and the live traffic counters.
Sleep 3s
Type "j"
Sleep 800ms
Enter
Sleep 4s
Escape
Sleep 800ms
# The row that lost its bind race: the strip carries the bind-failed
# meaning and its lsof line.
Type "g"
Sleep 800ms
Enter
Sleep 4s
Escape
Sleep 500ms
# tab onto the stale v0.0.9 daemon: its strip says, honestly, that it
# reports no per-entry counters.
Tab
Sleep 4.5s
Type "g"
Sleep 600ms
Type "j"
Sleep 600ms
Enter
Sleep 8s

Hide
Type "q"
Sleep 500ms
