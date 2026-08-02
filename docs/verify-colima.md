# Verifying drawbridge against Colima (manual)

CI never has a Colima VM. This file is therefore the *verification artifact*
for every Colima claim the project makes: run it on a dev Mac, paste the
transcript into the landing PR. It is referenced by docs/ergonomics.md §8
(Phase 3) and is the recipe later phases re-run rather than re-invent.

Commands are bash. From nushell, wrap them: `bash -lc '…'`.

What it proves, in order:

1. `drawbridged -vm colima:colima` maps a provider ref to the right Lima
   instance, the right DHCP lease record (`colima` — **not** `lima-colima`,
   see step 1) and the right `LIMA_HOME`, and resolves **vznat-direct** — not
   the SSH forwarder, which a Colima instance does not have for :4777.
2. A `DRAWBRIDGE_AGENT`-pinned subset of the e2e suite passes against a
   manually pushed agent inside that instance.

What it deliberately does *not* prove: `drawbridge up` (Phase 4), the OCI
wrapper (needs provisioning the guest's docker), or any `<1024` leg (needs
the root LaunchDaemon).

---

## 0. Prerequisites

```bash
mise install                 # colima is pinned in mise.toml
colima version
just build                   # bin/drawbridged, bin/drawbridge-agent-linux-arm64
```

The dev VM may stay running: the two instances are independent, and leaving
it up is worth doing on purpose — it is the case where the lease db holds
records for both guests and the resolver has to pick the right one.

---

## 1. Start a Colima VM

```bash
colima start --vm-type vz --network-address --cpu 2 --memory 4
```

- `--vm-type vz` is required. A qemu Colima has no host-reachable guest IP at
  all (user-mode slirp, no lease record), which is the "rejected with a
  doctor message" row of the docs/ergonomics.md §3.1 matrix.
- `--network-address` is what asks for the reachable IP. Without it there is
  no vzNAT interface and nothing for the resolver to find.

### Find colima's LIMA_HOME — do not assume it

Colima moved its config directory in v0.9: `~/.colima` → `$XDG_CONFIG_HOME/colima`
(default `~/.config/colima`). A fresh 0.10 install has **no `~/.colima` at
all**. Colima's own precedence is legacy-first — its binary carries the string
`found ~/.colima, ignoring $XDG_CONFIG_HOME...` — so probe in that order.
This is the same precedence `vmprovider.ColimaHome()` encodes; if the two
disagree on your Mac, that is a bug worth reporting rather than working
around.

```bash
colima_lima_home() {
  for d in "${COLIMA_HOME:+$COLIMA_HOME/_lima}" \
           "$HOME/.colima/_lima" \
           "${XDG_CONFIG_HOME:-$HOME/.config}/colima/_lima"; do
    [ -n "$d" ] && [ -d "$d" ] && { echo "$d"; return; }
  done
  echo "${XDG_CONFIG_HOME:-$HOME/.config}/colima/_lima"
}
export CLH="$(colima_lima_home)"
echo "$CLH"; ls "$CLH"      # expect _config, _networks, colima
```

Sanity-check that drawbridge agrees before going further — this one line is
the §3.3 `LIMA_HOME` plumbing, and it is the step that silently degrades if
it is wrong:

```bash
./bin/drawbridge install -vm colima:colima -print 2>&1 | grep 'LIMA_HOME='
# → LIMA_HOME=<the same path as $CLH> limactl list --format json colima
```

Now confirm the VM, and note the MAC — the rest of the recipe uses it:

```bash
LIMA_HOME="$CLH" limactl list --json colima | python3 -m json.tool | \
  grep -E '"(name|status|vmType|vzNAT|macAddress|hostAgentPID)"'
```

Expect `"vmType": "vz"`, `"vzNAT": true`, and a `macAddress`. The DHCP record
for this guest should now exist — and note the name:

```bash
grep -A4 'name=colima$' /var/db/dhcpd_leases
```

### The lease record is named `colima`, not `lima-colima`

Do not "correct" that grep. A lease record's `name` is DHCP option 12, i.e.
the **guest's hostname**, and the two providers set it differently:

| | guest hostname | lease record |
|---|---|---|
| lima instance `drawbridge` | `lima-drawbridge` | `name=lima-drawbridge` |
| colima default profile | `colima` | `name=colima` |

Lima defaults the hostname to `lima-<instance>`; colima's own cloud-init
overrides it to the instance name. Check for yourself:

```bash
LIMA_HOME="$CLH" limactl shell colima -- hostname          # → colima
limactl shell drawbridge -- hostname                        # → lima-drawbridge
```

Two traps live here.

- `limactl list --json colima` reports `"hostname": "lima-colima"` — Lima's
  *expectation*, which the guest has overridden. It disagrees with the lease
  db, so `vmprovider` never reads it; `LeaseName(provider, instance)` carries
  the rule instead.
- A *Lima* instance literally named `colima` would claim `lima-colima`, while
  colima's default profile claims `colima`. Those are different records and
  must stay so, or one VM answers for the other.

`hw_address` is the same address `limactl` printed, in the lease file's
spelling (ARP type prefix, leading zeros dropped). Both spellings normalize
to one string — that is what `internal/limaaddr` `TestNormalizeHWAddr` pins,
and it is what makes the MAC pin the trustworthy gate once the name is right.

**Unverified, please confirm if you run it:** a *named* profile
(`colima start -p work`) is modelled as instance `colima-work` with lease
record `colima-work`, by the same hostname-equals-instance rule. Only the
default profile has been observed. If you create one, run
`LIMA_HOME="$CLH" limactl shell colima-work -- hostname` and
`grep 'name=colima-work$' /var/db/dhcpd_leases`, and fix
`vmprovider.LeaseName` plus this paragraph if they disagree.

---

## 2. Push and run the agent by hand

Phase 4's `drawbridge up` does this; until then it is two commands. The guest
is arm64 on Apple Silicon — use the matching cross-compiled binary.

```bash
LIMA_HOME="$CLH" limactl copy \
  bin/drawbridge-agent-linux-arm64 colima:/tmp/drawbridge-agent

LIMA_HOME="$CLH" limactl shell colima -- sudo bash -c '
  install -m0755 /tmp/drawbridge-agent /usr/local/bin/drawbridge-agent
  systemctl stop drawbridge-agent 2>/dev/null
  systemctl reset-failed drawbridge-agent 2>/dev/null
  systemd-run --unit=drawbridge-agent --collect /usr/local/bin/drawbridge-agent'
```

Preflight, if the agent does not come up — the same checks Phase 4 turns into
doctor messages:

```bash
LIMA_HOME="$CLH" limactl shell colima -- bash -c '
  uname -m; uname -r
  test -r /sys/kernel/btf/vmlinux && echo btf-ok
  test -d /sys/fs/cgroup/cgroup.controllers && echo cgroup2-ok
  command -v systemctl >/dev/null && echo systemd-ok'

LIMA_HOME="$CLH" limactl shell colima -- \
  sudo journalctl -u drawbridge-agent -n 50 --no-pager
```

A Colima image without systemd (the legacy Alpine one) is out of scope for
v1 — recreate with the default Ubuntu image rather than working around it.

---

## 3. `drawbridged -vm colima:colima` resolves vznat-direct

```bash
./bin/drawbridged -vm colima:colima -mirror-ip 127.0.0.1
```

The startup lines to check, in order:

```
drawbridged: -vm colima:colima → colima instance colima (DHCP lease record colima)
drawbridged: agent tcp://192.168.64.NN:4777 (source=vznat-direct); mirroring guest listeners onto 127.0.0.1
```

`source=vznat-direct` is the pass condition. Two ways it can read otherwise,
both diagnosable from the warning line the daemon prints just above:

- `source=ssh-forwarder` with the Local Network note — grant Local Network to
  the terminal app (System Settings → Privacy & Security → Local Network),
  relaunch the terminal, retry. Unprivileged `drawbridged` is subject to that
  gate; the installed root LaunchDaemon is not (TN3179).
- `source=vznat-leases` — the direct `limactl` lookup failed and the lease db
  supplied the address instead. *Unprivileged*, that means the `LIMA_HOME`
  plumbing did not work; investigate before moving on, since that is exactly
  what §3.3 added. *Under sudo it is the expected source, not a failure*:
  `limactl` refuses euid 0, so root never has a `vznat-direct` candidate and
  resolving via the lease record (named `colima`) is precisely the root
  LaunchDaemon's designed path — seeing it live is a bonus check of this
  recipe, not a substitute for the unprivileged `vznat-direct` run.

Pin the guest's MAC once you have it, and confirm the resolver still resolves
— a pin that matches nothing fails closed, which looks like "it stopped
working":

```bash
./bin/drawbridged -vm colima:colima -vm-mac <macAddress from step 1>
```

Leave one `drawbridged` running for step 4, or let the tests run their own
in-process mirror (they do; the suite does not need an installed daemon).

---

## 4. The pinned e2e subset

```bash
COLIMA_IP=$(LIMA_HOME="$CLH" limactl shell colima -- hostname -I | tr ' ' '\n' | grep '^192\.168\.64\.')

DRAWBRIDGE_E2E=1 \
DRAWBRIDGE_VM=colima:colima \
DRAWBRIDGE_AGENT="tcp://$COLIMA_IP:4777" \
go test -count=1 -v -run \
  'TestGuestListenerReachableOnMacLocalhost|TestGuestBindGetsSynchronousEADDRINUSE|TestMacListenerReachableFromGuest' \
  ./internal/e2e/
```

`DRAWBRIDGE_VM` takes drawbridged's own `-vm` grammar, so the suite shells
into the right instance under the right `LIMA_HOME`. `DRAWBRIDGE_AGENT` pins
the endpoint so a green run cannot be attributed to a fallback path.

Excluded from the subset, with reasons:

| Test | Why not |
|---|---|
| `TestForwarderHalfClose` | needs :4777 forwarded to Mac loopback; only the dev template does that |
| `TestMacUDPServiceReachableFromGuest`, `TestGuestUDPListenerReachableOnMacLocalhost` | pass if the guest has them, but UDP is not what this recipe is verifying — run them once as a bonus, not as a gate |
| `oci_test.go` legs | need `just vm-docker` provisioning inside the guest |
| `TestPrivileged*` | need the root LaunchDaemon |

`TestGuestBindGetsSynchronousEADDRINUSE` and `TestMacListenerReachableFromGuest`
run binaries from the repo *at the host's own path* inside the guest. Colima
mounts `$HOME` by default, so a repo under `$HOME` is already there; check
before blaming the test:

```bash
LIMA_HOME="$CLH" limactl shell colima -- ls "$PWD/bin/drawbridge-agent-linux-arm64"
```

If it is missing, restart Colima with an explicit mount:
`colima start --vm-type vz --network-address --mount "$PWD:w"`.

### The attribution caveat — read before believing a green run

Colima runs Lima's port forwarder, and drawbridge coexists with it rather
than disabling it (docs/ergonomics.md §3.4). `TestGuestListenerReachableOnMacLocalhost`
starts its guest server on `--bind 0.0.0.0`, and Lima forwards wildcard binds
— so **that leg can pass with drawbridge doing nothing at all**. It is the
same pathology the Phase 2 results recorded against our own dev template.

Establish attribution explicitly. With no `drawbridged` and no test running:

```bash
LIMA_HOME="$CLH" limactl shell colima -- \
  bash -c 'systemd-run --unit=fwdcheck --collect python3 -m http.server 47999 --bind 0.0.0.0'
curl -sS -m2 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:47999/   # 200 ⇒ Colima's forwarder, not us
LIMA_HOME="$CLH" limactl shell colima -- sudo systemctl stop fwdcheck
```

If that returns 200, the wildcard leg proves nothing on this instance and the
attributable evidence is the other two tests — the reverse path
(`TestMacListenerReachableFromGuest`) and bind arbitration
(`TestGuestBindGetsSynchronousEADDRINUSE`), neither of which the forwarder
can satisfy. Say so in the transcript rather than reporting three greens.

The same fact is what `internal/vmprovider`'s coexistence detector reports:

```go
f, _ := vmprovider.NewColima().Forwarding("colima")
// f.HostAgent == true, f.Wildcard == "1-65535" ⇒ f.Active()
```

---

## 5. Clean up

```bash
LIMA_HOME="$CLH" limactl shell colima -- sudo bash -c '
  systemctl stop drawbridge-agent 2>/dev/null
  systemctl reset-failed drawbridge-agent 2>/dev/null
  rm -f /usr/local/bin/drawbridge-agent /tmp/drawbridge-agent'

colima stop
# and, to leave no lease record behind for the next run:
colima delete
```

`colima delete` matters more than it looks: a deleted instance leaves its
DHCP record in `/var/db/dhcpd_leases` until the lease expires, and a *new*
`colima` VM writes a second record with the same guest-chosen name and a
newer expiry. That is the recreated-VM case the MAC pin exists to separate
from the name-squatting case — worth reproducing once, deliberately, rather
than meeting by accident.

---

## 6. Transport auth addendum (Phase 4.5, 2026-07-31)

`drawbridge up colima:<profile>` now also provisions a per-VM transport
secret: Mac side at `~/Library/Application Support/drawbridge/
transport-secret-colima-<instance>` (0600), guest side at
`/etc/drawbridge/transport-secret` (0600 root). The e2e harness derives
the Mac half automatically from `DRAWBRIDGE_VM`, so the §4 subset runs
authenticated with no extra flags once `up` has run (override with
`DRAWBRIDGE_SECRET_FILE` if needed). Two checks worth adding to a
transcript:

```bash
# both digests must match:
shasum -a 256 ~/Library/Application\ Support/drawbridge/transport-secret-colima-colima | cut -d' ' -f1
LIMA_HOME="$CLH" limactl shell colima -- sudo sha256sum /etc/drawbridge/transport-secret | cut -d' ' -f1
```

The acceptance check for the auth feature itself: point the daemon at the
*wrong* VM's endpoint (`DRAWBRIDGE_AGENT=tcp://127.0.0.1:4777` while the
dev VM's forwarder holds that port) — it must log "closed during
transport authentication (source=…)" continuously and never mirror
anything. `drawbridge down` removes the guest half with `/etc/drawbridge`;
the Mac file is kept deliberately (a recreated VM plus `up` re-adopts the
same identity).
