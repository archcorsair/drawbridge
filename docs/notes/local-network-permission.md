# macOS Local Network permission vs. terminal/CLI apps (macOS 27 Beta 4)

Research notes, 2026-07-30. Situation: Lima vzNAT guest at `192.168.64.2` on `bridge100`; ARP resolves but all IP traffic from the terminal (and another desktop app) is silently dropped; the apps never appear in System Settings → Privacy & Security → Local Network and no prompt ever fires.

## TL;DR — most likely fixes for this machine, in order

1. **This is very likely the confirmed macOS 27.0b4 bug, and the first move is a plain reboot, then the subnet-exemption defaults.** Apple DTS has acknowledged a known local-network-privacy bug in **macOS 27.0b4 (r. 181140179), fix expected "in subsequent seeds"** ([Apple dev forums thread 814226](https://developer.apple.com/forums/thread/814226), Jan–Feb 2026; community FB23981410). Separately, a long-running class of bugs makes granted/exempt state get **ignored until a reboot or a Settings toggle** (Sequoia 15.0 → Tahoe 26.2, [thread 792453](https://developer.apple.com/forums/thread/792453)). A reboot has not been tried yet in this state — do that first; it is the cheapest thing that has repeatedly fixed exactly this symptom.

2. **Exempt the private ranges from local-network checks entirely (Apple-supported, macOS 15.5+), then reboot:**

   ```sh
   sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses -array "192.168.64.0/24"
   sudo defaults write com.apple.network.local-network AllowedWiFiLocalNetworkAddresses -array "192.168.64.0/24"
   sudo reboot
   ```

   These keys debuted in macOS 15.5 and are documented in Apple's TN3179 (Feb 2026 revision added the "configure local network privacy on specific networks" section) — traffic to listed CIDRs no longer requires the permission at all, for every app. This is exactly what **Tart** documents for CI hosts that must reach VM guests non-interactively ([tart.run/faq](https://tart.run/faq/), which uses the full RFC 1918 set). Write both keys — it's unclear which interface class `bridge100` is bucketed under. Widening to `"192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12"` is Tart's recommendation if you want it to also cover future subnets. Check current state with `sudo defaults read com.apple.network.local-network` (expect "does not exist" if never set). Low risk: it only *loosens* the privacy gate for private ranges on your own machine; delete the keys and reboot to revert.

3. **Interim unblock for drawbridge: run the Mac-side daemon as root (launchd daemon).** On macOS, local network privacy **automatically allows**: any launchd daemon, any program running as root, and CLI tools run from Terminal or over SSH including their children (TN3179, quoted below). drawbridge already needs a privileged `drawbridged` for ports <1024, so a root launchd daemon is a compliant permanent posture, not just a workaround. `sudo nc -vz 192.168.64.2 4777` succeeding while plain `nc` hangs both confirms the diagnosis and proves this path works on this build.

4. **If all of the above fail: Recovery-mode reset of the NetworkExtension plists** (unsupported; see "If all else fails").

## Diagnosis confirmation — run before and after each fix

1. `sudo nc -vz 192.168.64.2 4777` vs `nc -vz 192.168.64.2 4777`. Root is exempt by design; root-works/user-fails ⇒ local-network-privacy block confirmed. **Root also failing ⇒ the 27.0b4 bug is breaking even the exemption paths (or it's not this permission at all — recheck Lima/vmnet, pf, VPN filters).**
2. Note **which terminal app**. Apple's own Terminal (and SSH sessions) are *exempt* — tools run from them are never subject to the check and **never appear in the Settings list** (that part of what you see is normal). If plain `nc` fails from Apple Terminal specifically, that is per se OS misbehavior, not a missing grant. Third-party terminals (iTerm2, Ghostty, VS Code's integrated terminal, etc.) ARE subject: they are the "responsible process" for every CLI tool run inside them and should prompt/appear.
3. From the third-party terminal, run `dns-sd -B _ssh._tcp` and leave it running ~30 s. Bonjour browsing does mDNS multicast and is a reliable prompt trigger, and — critically — it *stays alive*: macOS has a documented bug where **short-lived processes never get the alert shown (FB16131937)** — a `nc -vz` that exits immediately can fail while the permission stays undetermined. If `dns-sd` runs long and still no prompt and no Settings entry appears, the prompt machinery itself is broken on this seed.
4. Watch decisions live while reproducing: `log stream --predicate 'subsystem CONTAINS "networkextension"' --info` (nehelper/nesessionmanager log the path-evaluation verdicts). Apple DTS's own debugging advice in thread 814226 is: prove the check fires, and if it fires without a prompt, file FB with a sysdiagnose.
5. After any fix, retest both the terminal and the other desktop app — state is evaluated per responsible process and **per user account**.

## Mechanism in ~10 lines

- Local network privacy shipped on macOS in **Sequoia 15.0** (iOS had it since 14). It is **not TCC**: "Local Network Privacy does not use TCC, so you cannot use `tccutil` to reset it" (Quinn "The Eskimo!", Apple DTS — via [mjtsai.com](https://mjtsai.com/blog/2024/10/02/local-network-privacy-on-sequoia/)). `tccutil reset All` / `tccutil reset LocalNetwork` do nothing (confirmed failing in the wild, e.g. [Insomnia #9783](https://github.com/Kong/insomnia/issues/9783)).
- It is enforced by the **NetworkExtension policy subsystem** (`nehelper`, `nesessionmanager`); state lives in SIP-protected `/Library/Preferences/com.apple.networkextension*.plist`, per user account. DTS-sanctioned restart (dev machines): `sudo launchctl stop com.apple.nesessionmanager && sudo launchctl start com.apple.nesessionmanager` ([thread 729034](https://developer.apple.com/forums/thread/729034)); `sudo killall nehelper` is the unsupported equivalent. Restarting these re-reads policy but does not reliably re-arm a prompt.
- **On macOS, plain outgoing unicast TCP to a local address DOES require the permission** (TN3179 table: outgoing TCP yes, UDP unicast/multicast/broadcast yes). So the `nc` test *is* a legitimate access attempt — but it is a poor *prompt* trigger because it exits instantly (FB16131937). `dns-sd -B` is the right trigger.
- Exemptions (TN3179, verbatim): "macOS automatically allows local network access by: Any daemon started by `launchd` · Any program running as root · Command-line tools run from Terminal or over SSH, including any child processes they spawn." (launchd *agents* are NOT exempt.)
- For everything else macOS attributes traffic to the **responsible process** (app → its helpers/children) and records one grant for the whole app; launchd agents can point attribution at an app via `AssociatedBundleIdentifiers` in the agent plist.
- There is **no API to trigger the prompt** (r. 69157424) and **no supported reset to "undetermined" on macOS** (FB14944392); Apple's own advice is "test in a VM and restore a snapshot" or use a fresh user account. The old "send UDP to port 9" trigger trick no longer works ([thread 663768](https://developer.apple.com/forums/thread/663768)).

**Implication for our nc test:** from Apple Terminal it should never prompt because it should never be blocked; from a third-party terminal it may never prompt because the process dies too fast. Either way, "no prompt + no Settings entry + traffic dropped" on 27.0b4 points at the acknowledged seed bug, with the subnet-exemption defaults as the deterministic bypass.

## Question-by-question findings

### 1. Known beta bugs — yes, directly on point

- **macOS 27.0b4: confirmed known bug r. 181140179** causing local network privacy problems; Apple DTS says fix expected in subsequent seeds. Community FB23981410 filed against 27 Beta 4. ([Apple dev forums 814226](https://developer.apple.com/forums/thread/814226) — Apple-official responses, Jan–Feb 2026.)
- Precedent, same class of bug every cycle: granted permission **ignored after reboot** until toggled, Sequoia 15.0 → Tahoe 26.2, fixed in 26.3 beta then regressed for some in 26.3.1 ([thread 792453](https://developer.apple.com/forums/thread/792453), FB20989430, FB14321888 — the latter fixed in 15.6); app **vanishes from the Local Network list after an update** with no re-prompt (Tahoe 26.3.1, [Insomnia #9783](https://github.com/Kong/insomnia/issues/9783), Apr 2026 — tied to Electron code-signature/bundle changes making macOS treat it as a new app); app never prompts at all ([Home Assistant iOS #4192](https://github.com/home-assistant/iOS/issues/4192), Tahoe). Eclectic Light's standing advice: "don't rely on local network privacy in releases prior to 15.3" ([eclecticlight.co](https://eclecticlight.co/2025/03/10/manage-privacy-protection-for-network-devices-and-others/) — community; note that article wrongly says it's TCC-managed).

### 2. Mechanism / what to restart

See mechanism section. Safe-ish on a dev box: `sudo launchctl stop com.apple.nesessionmanager && sudo launchctl start ...` (official), `sudo killall nehelper` (unsupported). Neither is reported to conjure missing Settings entries on Tahoe/27 — the reboot and the defaults keys are what actually move the needle. `tccutil` is a no-op for this permission.

### 3. Forcing the prompt for CLI contexts

- Apple Terminal/SSH: exempt, never prompts, never listed — nothing to force (TN3179; Quinn: "Terminal is considered the responsible code and, as a system app, it's not subject to local network privacy").
- Third-party terminal: it is the responsible process; make it prompt with a **long-running multicast** operation from inside it: `dns-sd -B _ssh._tcp` (or `_services._dns-sd._udp`). Avoid short-lived triggers (FB16131937). No lsregister/Finder-launch trick has Apple sanction; the bundled-GUI-first approach just amounts to "let the responsible app trigger the prompt once."
- Current doc of record: **TN3179 "Understanding local network privacy"** (replaced the 2020 "Local Network Privacy FAQ"; rewritten 2024-10-31, revised 2025-07-18 with FB14321888/FB16131937, revised **2026-02-17** adding the per-network configuration section). Apple-official.

### 4. Root bypass — yes

"Any program running as root" is automatically allowed (TN3179, current revision — verified against macOS 15; no macOS 26/27 doc change retracts it). One Sequoia-era caveat as precedent: in 15.0 the exemption briefly didn't cover DNS operations (FB14812974, fixed 15.1). So `sudo nc` should work, and a root `drawbridged` launchd daemon is a durable exemption. If root is *also* blocked on this seed, that's new 27.0b4 breakage worth putting in an FB.

### 5. Manual grant paths, ranked by safety

| Path | Status | Risk |
|---|---|---|
| `sudo defaults write com.apple.network.local-network AllowedEthernetLocalNetworkAddresses/-WiFi- -array "192.168.64.0/24"` + reboot | **Apple-supported** (macOS 15.5+, TN3179 Feb 2026 rev; Tart FAQ) | Low — loosens privacy for listed CIDRs only |
| New user account (state is per-user) | Supported, diagnostic | None; inconvenient |
| Restart nesessionmanager/nehelper | Semi-supported (dev only) | Low; rarely sufficient |
| Recovery-mode delete of `/Library/Preferences/com.apple.networkextension.plist` + `.control` + `.necp` + `.uuidcache` variants, then reboot | **Unsupported**; widely reported working ([zachbr.io](https://zachbr.io/posts/2025-11-29-reset-macos-local-network-permissions/) Nov 2025, [MacRumors](https://forums.macrumors.com/threads/local-network-access-nightmare.2448144/), Reddit reports echoed in thread 814226 — those users disabled SIP instead of using Recovery) | Wipes VPN/content-filter registrations stored in the same plists (most re-register on next launch); Quinn calls plist surgery a bad idea; did NOT fix the Insomnia 26.3.1 case |
| In-place `sudo defaults delete /Library/Preferences/com.apple.networkextension.plist` | Doesn't work while booted — SIP returns "Operation not permitted"; must be done from Recovery | — |
| MDM payload | **None found** — no dedicated Local Network permission MDM key documented through macOS 26 (searches of Apple MDM/enterprise docs and WWDC25 NetworkExtension material came up empty). The `com.apple.network.local-network` defaults are the de facto management knob. | — |

### 6. How VM tools handle it

- **Tart** (tart.run/faq, macOS 15+): the only vendor with explicit doc — the RFC 1918 `AllowedEthernet/WiFiLocalNetworkAddresses` defaults + host reboot, for exactly our symptom (host-side process can't reach guest IP, prompt unreliable in automation).
- **OrbStack**: [#2527](https://github.com/orbstack/orbstack/issues/2527) "Host can't reach *.orb.local on macOS 26" — same one-way-ARP/no-route symptom cluster on macOS 26 (root cause there partly OrbStack's own forwarder); earlier reports fixed by toggling OrbStack's Local Network checkbox after reboot ([thread 769037](https://developer.apple.com/forums/thread/769037)).
- **VS Code**: [#228862](https://github.com/microsoft/vscode/issues/228862) "Mac Sequoia: broken local network access" — Electron app unable to reach UTM VMs after upgrade; resolved by granting/toggling Local Network for VS Code (the responsible app for its integrated terminal!). Relevant if drawbridge is being tested from a VS Code terminal.
- **Lima**: no dedicated Local Network guidance in lima-vm docs/issues yet; vz/vzNAT relies on the host app being allowed. For drawbridge this means the *host binary that dials 192.168.64.2* inherits whatever app it was launched from — Terminal (exempt), a third-party terminal (needs grant), or a launchd daemon (exempt).
- **Home Assistant macOS app**: [#4192](https://github.com/home-assistant/iOS/issues/4192) — Tahoe never prompts; users pointed to the Recovery reset.

## If all else fails

1. Reboot once more after any plist/defaults change — several of these bugs only re-evaluate policy at boot.
2. Recovery mode → Disk Utility → mount Data volume → Terminal → `rm /Volumes/<Data>/Library/Preferences/com.apple.networkextension.plist` (plus `.control`, `.necp`, `.uuidcache` siblings) → reboot. All apps re-prompt from scratch; VPN/filter configs re-register on next app launch (zachbr.io procedure).
3. Safe mode boot (holds off third-party network extensions) as a differential: if traffic flows in safe mode, a filter — not the permission — is the blocker.
4. File Feedback: reproduce (`dns-sd -B` from the affected terminal + a `nc` attempt), `sudo sysdiagnose`, then FB citing r. 181140179 / FB23981410 as related, noting macOS 27.0b4 and that even the Terminal/root exemptions misbehave if step 1 of the diagnosis showed that. Then park on the `com.apple.network.local-network` defaults until the next seed.

## Sources

Apple-official:
- [TN3179: Understanding local network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy) — revisions 2024-10-31 / 2025-07-18 / 2026-02-17; successor to the 2020 Local Network Privacy FAQ.
- [Dev forums 814226 — Apps do not trigger local-network pop-up on Sequoia/Tahoe/27](https://developer.apple.com/forums/thread/814226) (DTS/Quinn; the 27.0b4 known bug r. 181140179; Jan–Feb 2026).
- [Dev forums 792453 — permission ignored after reboot](https://developer.apple.com/forums/thread/792453) (Jul 2025 – Mar 2026; FB20989430, FB14321888).
- [Dev forums 663768 — Triggering the Local Network Privacy Alert (obsolete trick)](https://developer.apple.com/forums/thread/663768).
- [Dev forums 729034 — official nesessionmanager restart](https://developer.apple.com/forums/thread/729034).
- [Dev forums 763753 / 767391 — daemons, root, CLI exemptions](https://developer.apple.com/forums/thread/763753).

Community:
- [Tart FAQ — AllowedLocalNetworkAddresses defaults for VM hosts](https://tart.run/faq/).
- [mjtsai.com — Local Network Privacy on Sequoia](https://mjtsai.com/blog/2024/10/02/local-network-privacy-on-sequoia/) (Oct 2024; aggregates Quinn quotes).
- [zachbr.io — Reset macOS Local Network Permissions](https://zachbr.io/posts/2025-11-29-reset-macos-local-network-permissions/) (Nov 2025).
- [Kong/insomnia #9783](https://github.com/Kong/insomnia/issues/9783) (Tahoe 26.3.1, Apr 2026) · [home-assistant/iOS #4192](https://github.com/home-assistant/iOS/issues/4192) · [orbstack #2527](https://github.com/orbstack/orbstack/issues/2527) (macOS 26) · [microsoft/vscode #228862](https://github.com/microsoft/vscode/issues/228862) (Sequoia).
- [eclecticlight.co — Manage privacy protection for network devices](https://eclecticlight.co/2025/03/10/manage-privacy-protection-for-network-devices-and-others/) (Mar 2025; caution: incorrectly describes the permission as TCC-managed).
- [MacRumors — Local Network Access Nightmare](https://forums.macrumors.com/threads/local-network-access-nightmare.2448144/) · [coofdy.com — Fixing stuck macOS Local Network permissions](https://coofdy.com/blog/2024-12-04-fixing-stuck-macos-local-network-permissions/) (Dec 2024).

## Findings on this machine (2026-07-30, macOS 27 Beta 4)

Two stacked problems, diagnosed in sequence:

1. **The connected route `192.168.64/24 → bridge100` had been deleted** while
   the interface still held `192.168.64.1/24`. Unscoped lookups fell through
   to the LAN default (UniFi gateway), which black-holed them — timeouts for
   every app *including root*, no prompts (no app was ever evaluated), ARP
   entry present only because guest→Mac traffic populated the cache. Suspects:
   Tailscale route management (connected at the time) or the Little Snitch
   6.5 nightly (old version queued "waiting to uninstall on reboot").
   Restored with `sudo route -n add -net 192.168.64.0/24 192.168.64.1`
   (the `-interface bridge100` form got EINVAL on this build). Watch for
   recurrence on Tailscale reconnect / VM restart.
2. **With the route restored, the Local Network permission denial appeared
   underneath**: unprivileged `nc` → EHOSTUNREACH; `sudo nc` → succeeded
   (root exempt, per TN3179). Prompts/Settings entries remain broken on this
   seed (r. 181140179), so the grant path is the supported subnet exemption:
   `sudo defaults write com.apple.network.local-network
   AllowedEthernetLocalNetworkAddresses -array "192.168.64.0/24"` (+ the
   WiFi key) + reboot.
3. **A third layer, found while attempting the vzNAT-direct bench baseline
   (same day, post-reboot): the Little Snitch 6.5 nightly (7300) network
   extension DPI-classifies first payload bytes and stalls ambiguous
   HTTP-method prefixes.** Wire-proven matrix (guest-side tcpdump, fresh
   binaries): handshake instant in all cases; a **lone first byte `'D'` or
   `'G'`** (DELETE/GET prefix) is held ~2.0 s — many held flows flush at the
   *same microsecond* when the classifier gives up — while `'x'` passes in
   µs and **`'D'` + 3 padding bytes passes in µs** (prefix disambiguated).
   The classifier waits for a request line that a parked drawbridge `'D'`
   conn never sends, so **every** reverse-dial pool refill stalls ~2 s, in
   every process, every run: outbound first-byte p95 ≈ 2 s, burst k≥16 hits
   the 3 s `pop` timeout (client sees RST), inbound bulk hangs past 60 s.
   Loopback is exempt (why the SSH-forwarder transport never showed it);
   connect-only probes (`nc -vz`) look clean — test with payloads. With
   pending alerts piled up the nightly escalated further (12 s+/indefinite
   holds, black-holed internet SYNs from unruled binaries). Crucially,
   **"disable filter" in Little Snitch did NOT stop the DPI hold** — only
   deactivating the network extension itself did (System Settings → General
   → Login Items & Extensions → Network Extensions; `systemextensionsctl
   uninstall` is SIP-gated). Worth an obdev bug report. Baseline numbers
   taken with the extension active are invalid; the clean run landed in
   plan.md §Benchmark. Robustness note for the transport seam: never leave
   the conn-type byte as a lone first segment — pad the type announcement
   (e.g. 4 bytes) so protocol-sniffing middleboxes classify instantly.
4. **A second, distinct Little Snitch bug, isolated 2026-07-30 (same 6.5
   nightly (7300) extension): TCP half-close kills inbound delivery on
   non-loopback flows.** Once a Mac process calls `shutdown(SHUT_WR)`,
   inbound bytes that arrive afterwards are ACKed by the kernel but **never
   delivered to the process** — `read()` blocks indefinitely; `close()`
   then RSTs the unread data. This — not vzNAT FIN loss, and not the
   finding-3 first-byte hold — is the cause of the bench
   `TestBench/InboundThroughput` wedge. Any write → shutdown → read
   protocol is affected.

   Wire-proven on the bench 'S' upload flow with simultaneous tcpdump on
   Mac `bridge100` and guest `lima0` (captures byte-identical — nothing is
   lost on the wire): the Mac pushed all 268,435,464 bytes (256 MiB + 8-byte
   header) plus its FIN in 0.12 s; the guest sink's 1-byte ack (`0x01`) and
   FIN arrived back on `bridge100` at t+0.21 s; the Mac kernel ACKed both
   within 40 µs — a complete, healthy TCP conversation — and the mirror
   process's blocked `read()` then starved for 75 s until teardown emitted
   `[R.] … ack 3`, proof the kernel had accepted the two bytes the app
   never saw.

   Controls that killed the earlier hypotheses (each on a stable agent,
   vzNAT transport confirmed in-log):
   - **No outbound leg → still wedges.** The "only after outbound traffic
     has flowed" correlation was bench ordering; a contaminated control also
     showed how it fooled us — when the agent bounces mid-probe,
     `limaaddr` silently falls back to the loopback forwarder, which is
     exempt, and the leg "passes".
   - **1-byte upload → still wedges.** Volume is irrelevant.
   - **Standalone, zero drawbridge components → wedges.** Direct dial to a
     plain sink on the guest vzNAT IP: write 1 byte, `CloseWrite()`, read →
     0 bytes in 20 s. Identical flow without the half-close → response
     byte delivered in microseconds. 11-packet pcap of the standalone
     repro (whole conversation done in 3.4 ms, then 15 s of app-side
     silence, then RST):

   ```
   t+0.003  Mac  → guest  [P.] seq 1:2  len 1      (request byte)
   t+0.003  Mac  → guest  [F.] seq 2               (shutdown(SHUT_WR))
   t+0.0032 guest → Mac   [P.] seq 1:2, ack 3, len 1   (response byte)
   t+0.0032 guest → Mac   [F.] seq 2, ack 3
   t+0.0032 Mac  → guest  [.] ack 2                (kernel ACKs data)
   t+0.0032 Mac  → guest  [.] ack 3                (kernel ACKs FIN)
   t+15.0   Mac  → guest  [R.] seq 3, ack 3        (close() on unread data)
   ```

   Mechanism-wise this is consistent with the NE flow filter tearing down
   its flow context on the app's outbound FIN and never issuing
   verdicts/delivery for subsequent inbound bytes: the kernel path is
   untouched (ACKs flow on the wire), only app-side delivery dies.
   Loopback is exempt, as with finding 3 — the SSH-forwarder transport
   never shows it.

   Repro tooling: `DRAWBRIDGE_WEDGE=1 go test -run TestWedgeRepro
   ./internal/bench/` (knobs: `DRAWBRIDGE_WEDGE_OUTBOUND` iters, 0 to skip;
   `DRAWBRIDGE_WEDGE_BYTES`), and the standalone probe (macOS `nc` has no
   shutdown flag, so Go):

   ```go
   c, _ := net.Dial("tcp", "192.168.64.2:PORT") // any guest TCP service
   c.Write([]byte{'x'})
   c.(*net.TCPConn).CloseWrite()
   c.SetReadDeadline(time.Now().Add(20 * time.Second))
   n, err := io.Copy(io.Discard, c) // extension active: n=0, timeout
   ```

   **No drawbridge workaround is appropriate.** `SetLinger` / ack-before-
   close sequencing don't apply — the data is already ACKed at the kernel;
   the failure is delivery of inbound bytes after the outbound FIN, before
   any `close()`. Suppressing real FINs on the transport would require
   in-band EOF framing on the `'S'`/`'D'` streams (never half-close the
   TCP conn until both directions finish) — protocol complexity purely to
   dodge a third-party bug that equally breaks plain direct connections to
   the guest. Goes into the obdev bug-report thread instead. Mitigations
   meanwhile: deactivate the LS network extension for inbound-bulk work,
   or pin the loopback transport (`DRAWBRIDGE_AGENT=tcp://127.0.0.1:4777`).

5. **`sysctl net.inet.tcp.pcblist_n` is filtered per responsible app on
   this seed (found 2026-08-01 via the TUI's `adv 0`).** An unprivileged
   process under ghostty or **Apple Terminal** receives an empty pcblist —
   immediately, persistently, no error — while the *identical binary*
   under Claude.app's process tree receives the full LISTEN set (26–27),
   and `sudo` receives it from any context (root exemption intact, unlike
   the LN gate's worst days). Apple's own `netstat` run from a terminal is
   equally filtered: attribution follows the responsible app, not the
   binary's signature — which also kills "exec netstat" as a fallback.
   Consequence for drawbridge: a foreground `drawbridged` launched from a
   terminal advertises **zero Mac listeners from birth** — `currentSet()`
   returns empty-without-error, the 'M' session stays healthy, and sync is
   silently one-directional (mirroring guest→Mac unaffected). No aging is
   involved; the first interactive TUI run surfaced it as `sync up ·
   adv 0 · parked 8` within seconds. Discriminator, same shape as ever:
   a tiny `macsync.Listeners()` loop probe, user-vs-sudo; a Mac never legitimately has
   zero LISTEN sockets, so **an empty enumeration on macOS is the gate,
   not the truth**. Postures: `sudo drawbridge install` (root LaunchDaemon
   — exemption proven live), or launch the daemon from a granted app
   context. Which grant Claude.app holds that terminals lack is
   undetermined (the Settings UI on this seed does not reliably list
   candidates); revisit on the next seed.
