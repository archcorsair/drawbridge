# Verifying drawbridge against a Podman machine (manual)

CI never has a Podman machine. This file is therefore the *verification
artifact* for every Podman claim the project makes: run it on a dev Mac,
paste the transcript into the landing PR. It is the podman counterpart to
[verify-colima.md](verify-colima.md), referenced by [podman.md](podman.md)
§9 (7.6), and it is the recipe later phases re-run rather than re-invent.

Commands are bash. From nushell, wrap them: `bash -lc '…'`.

What it proves, in order:

1. `drawbridge up podman:NAME` provisions a Fedora CoreOS guest running
   SELinux Enforcing, and the Mac reaches the agent at
   `source=gvproxy-publish`: a loopback port the *guest* publishes through
   gvproxy and re-publishes at every machine start.
2. The Mac-side e2e suite passes against that machine, pinned to the
   recorded endpoint so a green run cannot be attributed to anything else.
3. `--oci` gives a `podman run --network host` container the same bind
   arbitration a docker container has had since Phase 4, rootless included.
4. `drawbridge down` leaves the guest with nothing.
5. The same three semantics hold on the `applehv` provider, not only the
   `libkrun` default.

What it deliberately does *not* prove, because it needs Mac root: any `<1024`
leg, and the installed LaunchDaemon. Those are `just smoke-sudo` and
`just smoke-sudo-oci` at the end, which are one command each.

---

## 0. Prerequisites

```bash
mise install
just build                   # bin/drawbridge, bin/drawbridged, the four guest binaries
```

### Installing podman

The **official `.pkg`** from podman's releases page is the reference install
and the only one this recipe has been run against: podman 6.0.2 with bundled
`gvproxy v0.8.9`, `vfkit`, `krunkit` and `podman-mac-helper`. Podman
Desktop's "Podman" extension runs that same pkg, so a Podman Desktop user is
already on the reference install and needs nothing else.

One consequence of the pkg worth knowing before anything looks broken: it
installs to `/opt/podman/bin` and puts that directory on PATH through
`/etc/paths.d/podman-pkg`, which **only a login shell reads**. A CLI invoked
from a build tool, a non-login shell or launchd does not see `podman`:

```bash
podman version --format '{{.Client.Version}}'      # 6.0.2
env -i /bin/sh -c 'command -v podman || echo "not on PATH here"'
# → not on PATH here
```

drawbridge handles this itself (`vmprovider.PodmanBin` falls back to
`/opt/podman/bin/podman`), so nothing in this recipe needs the export. Add
`/opt/podman/bin` to your own PATH if you want to run the `podman` commands
below without it.

Homebrew's `podman` formula is a different install with its own helper
versions and has not been verified here. If you run this recipe against it,
say so in the transcript.

### The gvproxy floor

Branch A rides gvproxy's forwarder, which only propagates TCP half-close
after the tcpproxy commit of 2025-01-21. Below that floor, upload-then-ack
flows die and `drawbridge doctor -probe` says so by name.

```bash
/opt/podman/bin/gvproxy -version      # gvproxy version v0.8.9
```

The support line is podman >= 6.0, whose bundled gvproxy is past the
boundary.

---

## 1. Create a machine

### Rootless (the default)

```bash
podman machine init --now --cpus 2 --memory 2048 --disk-size 20 spike
podman machine info --format json | python3 -c \
  'import json,sys;d=json.load(sys.stdin);print(d["Host"]["VMType"], d["Host"]["MachineConfigDir"])'
# → libkrun /Users/<you>/.config/containers/podman/machine/libkrun
```

**libkrun is podman 6's default macOS provider**, not applehv, and it is
fully attachable. The whole of Phase 7 was developed on it. §5 below repeats
the three semantics on applehv.

### Rootful, which is what `:80` needs

```bash
podman machine init --rootful --now --cpus 2 --memory 2048 --disk-size 20 spike-rootful
```

**Do not name it `spike-root`.** podman auto-creates a system connection
called `<machine>-root` for every machine's rootful endpoint, so
`podman machine init … spike-root` fails with "system connection
`spike-root` already exists" the moment a machine called `spike` is there.
Use a suffix podman does not claim: `-rootful`, `-rf`.

Rootless is fine for everything except a container binding a port below the
guest's `net.ipv4.ip_unprivileged_port_start`, which Fedora CoreOS ships at
1024. That refusal is the guest kernel's and happens long before drawbridge
is involved; `drawbridge doctor` says so and names the two choices
(`podman machine set --rootful` on a stopped machine, or raising the
sysctl). The rootless legs below use `:8080`.

### Only one machine runs at a time

```bash
podman machine start spike-hv
# Error: spike already starting or running on the libkrun provider:
#        only one VM can be active at a time
```

Across providers, not just within one. So every machine swap in this recipe
is a `stop` then a `start`, and a Mac with three machines has two stopped
ones by construction. `drawbridge doctor` says that out loud in check 1 so a
stopped sibling does not read as a fault.

---

## 2. `drawbridge up`

```bash
./bin/drawbridge up podman:spike --oci
```

```
drawbridge: podman:spike, linux/arm64, kernel 7.1.3-200.fc44.aarch64, SELinux Enforcing, rpm-ostree
drawbridge: chose transport port 4778, recorded in ~/Library/Application Support/drawbridge/vm-podman-spike.json
drawbridge: installed /usr/local/bin/drawbridge-agent (v0.1.2)
drawbridge: wrote /etc/drawbridge/transport-secret (transport auth enabled)
drawbridge: wrote /etc/systemd/system/drawbridge-agent.service
drawbridge: drawbridge-agent.service is active
drawbridge: installed /usr/local/bin/drawbridge-crun
drawbridge: wrote /etc/containers/containers.conf.d/50-drawbridge.conf (podman's crun runtime now execs /usr/local/bin/drawbridge-crun)
drawbridge: note: the guest's /etc/containers is a virtiofs mount of your Mac's podman config directory
  (podman machine's own etc-containers.mount), so that drop-in is one file on the Mac, shared by
  every podman machine and read by the Mac's podman client too. …
  On this Mac it is ~/.config/containers/containers.conf.d/50-drawbridge.conf
drawbridge: WARNING: 2 other podman machine(s) on this Mac read that same file: podman:spike-hv, podman:spike-rootful
drawbridge: agent v0.1.2 in the guest, CLI v0.1.2
drawbridge: transport tcp://127.0.0.1:4778 (source gvproxy-publish; the guest agent re-publishes it on every machine start)

Next: sudo drawbridge install -vm podman:spike
```

Three things in that output are podman-specific and worth checking rather
than skimming.

**The port is chosen and recorded, not derived.** There is no DHCP lease for
a gvproxy machine, so the Mac-side record is the only thing that knows which
loopback port this machine's transport is on. Re-running `up` reuses the
recorded port without probing it, because by then gvproxy is holding it:

```bash
cat ~/Library/Application\ Support/drawbridge/vm-podman-spike.json
```

```json
{"version":1,"provider":"podman","instance":"spike","transport":"gvproxy-publish",
 "endpoint":"tcp://127.0.0.1:4778",
 "ssh":{"port":57446,"identity":"…/podman/machine/machine","user":"core"},
 "rootful":false,"vmtype":"libkrun","written_by":"v0.1.2","written_at":"…"}
```

**The `--oci` drop-in is a file on your Mac.** `/etc/containers` in the guest
is a virtiofs mount of `~/.config/containers`, shipped by podman's own
`etc-containers.mount` unit so your registries, auth and policy follow you
into every machine. One `up --oci` therefore registers the wrapper for every
podman machine on the Mac, and `down` on any one of them removes it for all.
That is harmless by construction: the drop-in's second entry is the real
crun, so a machine without the wrapper installed falls straight back to it.
Confirm both halves:

```bash
podman machine ssh spike -- cat /etc/containers/containers.conf.d/50-drawbridge.conf
cat ~/.config/containers/containers.conf.d/50-drawbridge.conf     # the same file
podman machine ssh spike -- findmnt -no SOURCE,FSTYPE,OPTIONS /etc/containers
# → <id> virtiofs rw,relatime,context=system_u:object_r:nfs_t:s0
```

**SELinux is Enforcing and the mount is labelled `nfs_t` wholesale.** Every
file `up` installs gets a `restorecon`, and the label to check is `bin_t` on
the binaries:

```bash
podman machine ssh spike -- ls -Z /usr/local/bin/drawbridge-agent /usr/local/bin/drawbridge-crun
# → system_u:object_r:bin_t:s0 (both)
podman machine ssh spike -- sudo ausearch -m avc -ts recent    # expect <no matches>
```

`restorecon` on the drop-in is a no-op, deliberately unfixable: a `context=`
mount option fixes every label on that filesystem, so `matchpathcon` says
`etc_t` and `ls -Z` says `nfs_t` and nothing can change it. podman reads the
file anyway.

---

## 3. Resolution, and the agent's own publish

```bash
./bin/drawbridged -vm podman:spike -introspect off
```

```
drawbridged: skip-list: 22,323 ignored in both directions (not mirrored, not synced); -skip replaces the list, -skip "" empties it
drawbridged: -vm podman:spike → podman machine spike (no DHCP lease: gvproxy is user-mode, so the endpoint comes from the per-VM record)
drawbridged: agent tcp://127.0.0.1:4778 (source=gvproxy-publish); mirroring guest listeners onto 127.0.0.1; syncing Mac listeners into the guest
drawbridged: mirror: skipping guest udp :323 (skip-list; -skip to override)
drawbridged: mirror: skipping guest tcp :22 (skip-list; -skip to override)
```

`source=gvproxy-publish` is the pass condition, and unlike Lima's
`ssh-forwarder` it is **not a fallback**: it is the only path a podman
machine has. `drawbridge doctor` grades it `ok` for exactly that reason.

The publish belongs to the guest, not to this Mac. The agent posts it to
gvproxy's in-guest API at every start, which is what brings the forward back
after `podman machine stop`:

```bash
podman machine ssh spike -- sudo journalctl -u drawbridge-agent -n 20 --no-pager | grep gvproxy
# → gvproxy: published 127.0.0.1:4778 -> 192.168.127.2:4777 (the Mac dials tcp://127.0.0.1:4778)

podman machine ssh spike -- curl -sS http://192.168.127.1/services/forwarder/all
# → [{"local":"127.0.0.1:4778","remote":"192.168.127.2:4777","protocol":"tcp"},
#    {"local":"127.0.0.1:57446","remote":"192.168.127.2:22","protocol":"tcp"}]
```

Two entries, and only two, on a machine with nothing published: ours and
podman's own ssh forward. Anything else in that table is a `podman run -p`
and is what doctor's check 10 reports.

`drawbridge doctor -vm podman:spike -v` is the whole of this section in one
command, and `-probe` adds the half-close test (20 s, because the window has
to outlast the agent's 15 s liveness ping):

```
[ok] half-close probe — the agent kept streaming after the client's FIN
     the endpoint is loopback, and on this provider that IS the transport's path
     (gvproxy publishes it there), so this is evidence about the real path and not only about the agent.
```

---

## 4. The e2e suite

```bash
DRAWBRIDGE_E2E=1 \
DRAWBRIDGE_VM=podman:spike \
DRAWBRIDGE_AGENT=tcp://127.0.0.1:4778 \
go test -count=1 -v ./internal/e2e/
```

Observed 2026-09-11 on `podman:spike`: **11 pass / 5 skip / 0 fail.**

`DRAWBRIDGE_VM` takes drawbridged's own `-vm` grammar, so the harness shells
into the machine through `podman machine ssh` and gates on the provider's own
listing. `DRAWBRIDGE_AGENT` pins the endpoint, so a green run cannot be
attributed to some other VM's forward.

Read `-v`, not the exit status: without `DRAWBRIDGE_E2E=1` every leg skips
and the suite still prints `ok`.

The five skips, with reasons:

| Test | Why it skips |
|---|---|
| `TestContainerBindGetsSynchronousEADDRINUSE`, `TestHostNetContainerListenerMirrored`, `TestBridgedContainerNotArbitrated` | provisioned for docker (`just vm-docker` and the `drawbridge/bindtest` image). The podman equivalent is §5 below and `just smoke-sudo-oci`. |
| `TestPrivilegedMirror`, `TestPrivilegedReserve` | need the root LaunchDaemon (`just e2e-root`, or `just smoke-sudo`) |

`TestForwarderHalfClose` is the one leg worth naming as a pass rather than
counting. On Lima it forces the SSH forwarder; on a podman machine the
user-mode forwarder *is* gvproxy, so the leg puts an upload-then-ack flow
through the exact path this provider always uses. That is the property the
7.0 spike existed to settle, re-checked on every run.

---

## 5. The `--oci` legs

A host-network container's listener on Mac localhost, and a second
container's bind refused synchronously. Rootless, so `:8080`:

```bash
printf 'server {\n    listen 8080;\n    location / { return 200 "drawbridge-smoke\\n"; }\n}\n' \
  | podman machine ssh spike -- dd of=/tmp/db-nginx.conf status=none
podman machine ssh spike -- podman pull docker.io/library/nginx

# with `./bin/drawbridged -vm podman:spike` running in another terminal:
podman machine ssh spike -- podman run --rm -d --network host --name db-web \
  -v /tmp/db-nginx.conf:/etc/nginx/conf.d/default.conf:ro,Z docker.io/library/nginx
curl -sS http://127.0.0.1:8080/          # → drawbridge-smoke
```

```
drawbridged: mirroring guest :8080 on 127.0.0.1:8080
agent: oci: supervising container 6453158b3c0c… (init pid 12087, metadata {"v":1,"source":"drawbridge-crun","hostNetwork":true})
agent: notify: bind 0.0.0.0:8080 pid=12087 -> unknown
```

`-> unknown` is correct here and not a failure: it means no Mac-side session
had an opinion about that port. With the root daemon installed it reads
`-> ok`.

Now the feature. Stop the container, let the **Mac** hold `:8080`, and start
the container again:

```bash
podman machine ssh spike -- podman rm -f db-web
python3 -m http.server 8080 --bind 127.0.0.1 &
printf 'podman run --rm --network host --name db-dup -v /tmp/db-nginx.conf:/etc/nginx/conf.d/default.conf:ro,Z docker.io/library/nginx >/tmp/x.log 2>&1\necho drawbridge-exit=$?\ngrep -m1 "Address already in use" /tmp/x.log\n' \
  | podman machine ssh spike -- sh
```

```
drawbridge-exit=1
2026/09/11 22:12:01 [emerg] 1#1: bind() to 0.0.0.0:8080 failed (98: Address already in use)
agent: notify: bind 0.0.0.0:8080 pid=12287 -> inuse
```

Both halves matter: the container's own errno *and* the agent's `-> inuse`
line. Without the second, a container that failed to start for an unrelated
reason would look like a pass.

The script goes in on **stdin** with `sh` as the only argv word. `podman
machine ssh NAME -- a b c` joins argv into one remote command string without
quoting, exactly as `limactl shell` does, so anything with a space in it is
re-split in the guest.

On a **rootful** machine the same legs run at `:80` with no config file at
all (`podman run -d --network host nginx`), which is the quickstart demo. The
Mac side of `:80` needs the root daemon, so that is `just smoke-sudo-oci`.

### Acceptance line

```bash
podman machine ssh spike -- podman info --format '{{.Host.OCIRuntime.Path}}'
# → /usr/local/bin/drawbridge-crun
```

---

## 6. `drawbridge down`

```bash
./bin/drawbridge down podman:spike
```

```
drawbridge: removed /etc/systemd/system/drawbridge-agent.service
drawbridge: removed /etc/containers/containers.conf.d/50-drawbridge.conf
drawbridge: removed /usr/local/bin/drawbridge-agent
drawbridge: removed /usr/local/bin/drawbridge-crun
drawbridge: removed ~/Library/Application Support/drawbridge/vm-podman-spike.json
drawbridge: done — the guest has no drawbridge files left
drawbridge: kept the Mac-side transport secret …/transport-secret-podman-spike
```

The assertion is that the next command **prints nothing**:

```bash
podman machine ssh spike -- \
  'ls /usr/local/bin /etc/drawbridge /etc/systemd/system /etc/containers/containers.conf.d 2>/dev/null | grep drawbridge'
# (no output, exit 1)
```

The Mac-side transport secret is kept on purpose: `down` is guest-scoped, so
a recreated machine plus `up` re-adopts the same identity. Delete the file to
rotate.

`down` deletes the drop-in only when its digest still matches what `up`
wrote. Edit it and `down` says so and leaves it:

```
drawbridge: /etc/containers/containers.conf.d/50-drawbridge.conf: edited since `up`; not removed
```

And stock crun runs containers again immediately:

```bash
podman machine ssh spike -- podman info --format '{{.Host.OCIRuntime.Path}}'   # → /usr/bin/crun
podman machine ssh spike -- podman run --rm --network host docker.io/library/nginx -v   # starts
```

---

## 7. The applehv leg

Everything above on the other macOS provider, to keep it a matrix row rather
than an assumption. Only one machine runs at a time, so this is a swap:

```bash
podman machine init --provider applehv --now --cpus 2 --memory 2048 --disk-size 20 spike-hv
# later, from a running `spike`:
podman machine stop spike && podman machine start spike-hv

./bin/drawbridge up podman:spike-hv
DRAWBRIDGE_E2E=1 DRAWBRIDGE_VM=podman:spike-hv DRAWBRIDGE_AGENT=tcp://127.0.0.1:4778 \
  go test -count=1 -v -run 'TestGuestListenerReachableOnMacLocalhost|TestGuestBindGetsSynchronousEADDRINUSE|TestMacListenerReachableFromGuest|TestForwarderHalfClose' ./internal/e2e/
```

Observed 2026-09-11: 4/4 pass, same FCOS build, same `gvproxy-publish`
source, same doctor report.

**The guest NIC is not `eth0` on applehv.** It is `enp0s1`:

```bash
podman machine ssh spike-hv -- ip -4 addr show eth0     # Device "eth0" does not exist.
podman machine ssh spike-hv -- ip -4 route get 192.168.127.1
# → 192.168.127.1 dev enp0s1 src 192.168.127.2
```

Nothing in drawbridge names an interface, which is why this is a note rather
than a bug: the agent binds `192.168.127.2`, gvproxy's fixed lease for the
machine, and the transport's `auto` mode finds it by address.

Swap back when you are done:

```bash
./bin/drawbridge down podman:spike-hv
podman machine stop spike-hv && podman machine start spike
```

---

## 8. The root acceptance

Everything that needs Mac root is two commands, each asking for the password
once and printing one JSON document to paste back.

```bash
just smoke-sudo podman:spike            # 11 checks, expect ran 11 / passed 11 / failed 0
just smoke-sudo-oci podman:spike        # 14 checks, expect ran 14 / passed 14 / failed 0
```

They install the freshly built daemon for the machine, prove the three
semantics through it (a guest listener on Mac localhost, a Mac listener
reachable in the guest, a guest bind on a Mac-held port refused with
`EADDRINUSE` from both an on-thread and an off-thread bind), run
`sudo drawbridge doctor` and assert it reports no failing check, then
uninstall and reinstall whatever daemon was installed before. `-oci` adds the
three container legs from §5.

Two preconditions, both easy to get wrong:

- The guest must already be provisioned (`drawbridge up <vm> --oci` for the
  `-oci` variant) and the nginx image already pulled. The smoke run does not
  pull, deliberately: a run that downloaded 70 MB would be measuring the
  registry.
- The guest agent and the CLI must be the same build. The doctor check
  compares them, and a guest provisioned from an older commit fails it.
  Re-run `drawbridge up` if the versions have drifted.

For the `:80` demo, swap to the rootful machine first
(`podman machine stop spike && podman machine start spike-rootful`) and run
the same two commands against it.

---

## 9. Clean up

```bash
./bin/drawbridge down podman:spike
podman machine stop spike
podman machine rm -f spike            # only if you want the machine gone
rm -f ~/Library/Application\ Support/drawbridge/transport-secret-podman-spike
```

There is no DHCP lease to expire, which is one thing podman makes simpler
than Lima: nothing on the Mac keeps a record of a machine you removed except
the transport secret, and that is a file you delete.

If you removed the last machine that had `--oci`, check the shared drop-in is
gone too, since it lives on your Mac rather than in any guest:

```bash
ls ~/.config/containers/containers.conf.d/
```
