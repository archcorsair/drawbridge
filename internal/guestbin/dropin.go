package guestbin

// The `--oci` half of `drawbridge up` on a podman guest (docs/podman.md
// §6.2), and the deliberate opposite of provision.go's daemon.json merge.
//
// Podman reads `/etc/containers/containers.conf.d/*.conf` in addition to
// its own config, so registration needs no merge into a file the user owns:
// `up` writes one whole file that did not exist, and `down` deletes exactly
// that file. What the state records is therefore not "what was there
// before" but "what we wrote", as a digest — which is the only evidence
// that distinguishes a file still ours to delete from one the user has
// since edited.
//
// The drop-in shadows the *existing* `crun` key rather than registering a
// new runtime name. Podman keys several feature-detection lists on the
// runtime name (`runtime_supports_json`, `…_nocgroups`, `…_kvm`), each
// replaced wholesale by TOML rather than merged, so a new name would need
// all of them edited too; keeping the name `crun` keeps every one of those
// lists truthful, because the wrapper execs crun.
//
// Everything here is pure — bytes in, bytes out — for the same reason the
// daemon.json half is: `down`'s promise ("delete it only if it is still
// byte-for-byte what `up` wrote") is a claim about exact bytes, and a claim
// about exact bytes is only testable against fixtures.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// DropinDir is podman's global drop-in directory. It does not exist on a
// stock Fedora CoreOS podman machine (verified live, docs/podman.md §7.0
// results), so `up` creates it; `down` leaves it, because an empty
// directory podman itself documents is not litter and removing it would
// race any other tool that writes there.
const DropinDir = "/etc/containers/containers.conf.d"

// DropinPath is the one file `--oci` writes on a podman guest. The `50-`
// prefix puts it after the image's vendor drop-ins
// (`/usr/share/containers/containers.conf.d/…`) and leaves room on both
// sides for an administrator who wants the last word.
const DropinPath = DropinDir + "/50-drawbridge.conf"

// dropinHeader says who wrote the file and what removes it, because the
// first person to find it will be someone who did not.
const dropinHeader = "# written by drawbridge up --oci; removed by drawbridge down. Do not edit.\n"

// DropinBytes renders the drop-in for a guest whose real crun is at
// realCrun.
//
// The second element of the list is podman's own fallback: if the wrapper
// ever vanishes, podman execs the real crun and containers keep starting.
// That is also what makes `down`'s ordering forgiving — deleting the
// wrapper before the drop-in would still leave a working engine.
//
// The path is a parameter rather than a constant even though every podman
// machine so far has crun at /usr/bin/crun: the constant would be a silent
// lie on a guest that does not, and the caller has the answer for free from
// the preflight it already runs.
func DropinBytes(realCrun string) ([]byte, error) {
	if err := checkRuntimePath(realCrun); err != nil {
		return nil, err
	}
	return []byte(dropinHeader +
		"[engine.runtimes]\n" +
		"crun = [\"" + WrapperPath(EnginePodman) + "\", \"" + realCrun + "\"]\n"), nil
}

// checkRuntimePath refuses anything that would not survive being quoted
// into a TOML string. The value comes from `command -v crun` in the guest,
// which is the user's own VM — but a newline here would forge TOML
// directives, and a file this package promises to delete by digest must
// never contain something it did not intend to write.
func checkRuntimePath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("guestbin: crun path %q is not absolute", p)
	}
	if strings.ContainsAny(p, "\"\\\n\r\t") {
		return fmt.Errorf("guestbin: crun path %q contains characters that cannot appear in the drop-in", p)
	}
	return nil
}

// Provision state versions. Docker guests keep writing 1, byte-identical to
// every state file already in a guest, which is what lets a newer `up`
// leave an older one's record alone; podman's is 2 because it records
// entirely different things (there is no daemon.json, and no "before").
const (
	StateVersionDocker = provisionStateVersion // 1
	StateVersionPodman = 2
	MaxStateVersion    = StateVersionPodman
)

// PodmanState is /etc/drawbridge/provision.json on a podman guest.
//
// A separate type from ProvisionState rather than more optional fields on
// it: the two describe disjoint reverts, and sharing a struct would put a
// `"rootful": false` into every docker guest's state file — a byte change
// to a file whose whole job is byte-level evidence.
type PodmanState struct {
	Version int    `json:"version"`
	Engine  string `json:"engine"`

	// RuntimePath is where the wrapper was installed, so `down` removes the
	// binary this `up` put there rather than a path it assumed.
	RuntimePath string `json:"runtime_path"`

	// DropinPath and DropinSHA256 are the file and the digest of what we
	// wrote into it. The digest is the whole of `down`'s decision: equal
	// means the file is still ours to delete, different means someone
	// edited it and it is not.
	DropinPath   string `json:"dropin_path"`
	DropinSHA256 string `json:"dropin_sha256"`

	// Rootful is the machine's mode at `up` time. `down` needs it to aim
	// the API-service restart at the right systemd instance, and a machine
	// switched with `podman machine set --rootful` in between is exactly
	// the case where re-deriving it would aim at the wrong one.
	Rootful bool `json:"rootful"`

	// OCISockOwner is the local user the agent chowns the OCI socket to,
	// empty on a rootful machine where root's 0600 is already right
	// (docs/podman.md §6.3). Recorded so a later `up` without `--oci` keeps
	// rendering the flag instead of silently disabling arbitration.
	OCISockOwner string `json:"oci_sock_owner"`
}

// EncodePodmanState renders the state file, indented for the same reason
// the docker one is: someone debugging a half-reverted guest will `cat` it.
func EncodePodmanState(st PodmanState) ([]byte, error) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodePodmanState reads a version-2 state file.
func DecodePodmanState(b []byte) (PodmanState, error) {
	var st PodmanState
	if err := json.Unmarshal(b, &st); err != nil {
		return PodmanState{}, fmt.Errorf("%s is not valid JSON (%w): remove it to skip the `--oci` revert, or fix it — drawbridge will not guess what `up --oci` changed", ProvisionPath, err)
	}
	if st.Version > MaxStateVersion {
		return PodmanState{}, newerStateError(st.Version)
	}
	return st, nil
}

// PeekStateVersion reads just the version out of a state file, so `down`
// can pick the reader before committing to a shape. A file with no version
// is version 0, which is not a version this build ever wrote and is
// reported as such by the caller rather than guessed at here.
func PeekStateVersion(b []byte) (int, error) {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return 0, fmt.Errorf("%s is not valid JSON (%w): remove it to skip the `--oci` revert, or fix it — drawbridge will not guess what `up --oci` changed", ProvisionPath, err)
	}
	return head.Version, nil
}

func newerStateError(v int) error {
	return fmt.Errorf("%s was written by a newer drawbridge (state version %d, this build understands %d): re-run `drawbridge down` with that version",
		ProvisionPath, v, MaxStateVersion)
}

// RevertDropin is `down`'s decision about the drop-in: delete it, or leave
// it and say why.
//
// `current` is nil when the file is gone. There is deliberately no third
// answer — no "rewrite it", no "un-merge" — because the file is ours
// whole-cloth: either it is still what we wrote, in which case removing it
// is exact, or it is not, in which case someone made a decision and `down`
// is not entitled to overrule it. The reason string is printed verbatim, so
// it is written to be read by whoever finds the file still there.
func RevertDropin(st PodmanState, current []byte) (del bool, reason string) {
	path := st.DropinPath
	if path == "" {
		path = DropinPath
	}
	switch {
	case current == nil:
		return false, "" // already gone; nothing to say
	case st.DropinSHA256 == "":
		// No digest recorded, so no evidence. `up` always records one, so
		// this is a hand-edited state file; leaving the drop-in is the
		// answer that cannot destroy anything.
		return false, path + ": no digest recorded by `up`; not removed"
	case sha256Hex(current) == st.DropinSHA256:
		return true, ""
	default:
		return false, path + ": edited since `up`; not removed"
	}
}
