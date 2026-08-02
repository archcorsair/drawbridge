package guestbin

// The `--oci` half of `drawbridge up`, and the only part of it that mutates
// a file the user owns: Docker Engine's /etc/docker/daemon.json.
//
// Everything here is pure — bytes in, bytes out — for one reason. `down`
// promises to leave daemon.json byte-identical to its pre-`--oci` state
// (docs/ergonomics.md §8, Phase 4 verify), and a promise about exact bytes
// can only be tested if the code that produces them can be run against
// fixtures without a VM. The guest-side script does the rest (install the
// wrapper, restart docker); it does not touch this file. See the header of
// assets/provision-docker.sh.
//
// The revert strategy, in order of preference:
//
//  1. restore the recorded original bytes verbatim — exact by construction,
//     including whatever indentation, key order and comments-shaped
//     whitespace the user's engine or config management wrote;
//  2. if the file has changed since `up` wrote it, un-merge surgically:
//     drop only the keys we added and restore only the value we replaced.
//     Formatting normalizes in this path, which is the honest trade — the
//     alternative is clobbering an edit the user made deliberately.
//
// Choosing between them needs evidence, which is what the recorded sha256 of
// what we wrote is for. Without it, "restore the original" and "the user
// re-tuned their daemon" are indistinguishable, and one of the two answers
// silently destroys work.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// The keys this package owns in daemon.json, and the runtime it registers.
const (
	RuntimeName    = "drawbridge"
	runtimesKey    = "runtimes"
	defaultRTKey   = "default-runtime"
	daemonJSONPath = "/etc/docker/daemon.json"
)

// DaemonJSONPath is Docker Engine's config file — the one file `--oci`
// edits.
const DaemonJSONPath = daemonJSONPath

// provisionStateVersion is the schema version of the state file. `down` from
// a newer CLI must be able to read a file an older `up` wrote, and refuse
// rather than misread the other direction.
const provisionStateVersion = 1

// ProvisionState is /etc/drawbridge/provision.json: the record of what
// `--oci` changed, written by `up` and read by `down`.
//
// It records decisions, not intentions. "We set default-runtime" and "it was
// already drawbridge" are different states with different reverts, and the
// only moment either is knowable is before the write.
type ProvisionState struct {
	Version int `json:"version"`

	// RuntimePath is where the wrapper was installed. Recorded so `down`
	// removes the binary this `up` put there and not a path it assumed.
	RuntimePath string `json:"runtime_path"`

	// AddedRuntime is true when we created runtimes["drawbridge"]. False
	// means the user had already registered it and `down` leaves it alone.
	AddedRuntime bool `json:"added_runtime"`

	// SetDefaultRuntime is true when we wrote default-runtime;
	// PrevDefaultRuntime is what it said before, empty when the key was
	// absent (in which case revert removes it rather than writing "runc" —
	// the engine's default is the engine's business, not ours to hardcode).
	SetDefaultRuntime  bool   `json:"set_default_runtime"`
	PrevDefaultRuntime string `json:"prev_default_runtime,omitempty"`

	// DaemonJSONExisted distinguishes "we edited a file" from "we created
	// one". Reverting a creation means deleting the file, and leaving an
	// empty `{}` behind instead would be a change, not a revert.
	DaemonJSONExisted bool `json:"daemon_json_existed"`

	// DaemonJSONBefore is the file's exact prior content, and DaemonJSONAfter
	// the sha256 of what we wrote. Together they are what makes an exact
	// revert possible *and* checkable: the hash says whether the file is
	// still ours to restore.
	DaemonJSONBefore string `json:"daemon_json_before,omitempty"`
	DaemonJSONAfter  string `json:"daemon_json_after,omitempty"`
}

// Merge is the `--oci` daemon.json edit: register the wrapper runtime and
// make it the default.
//
// `existing` is nil when the file does not exist — distinct from empty,
// which is a file that exists and holds nothing (docker treats that as an
// error, and so do we, rather than silently overwriting it).
//
// Changed is false when the file already says what we would write. That is
// the merge-compare-write discipline §4.2 requires: an idempotent re-run of
// `up --oci` must not rewrite the file, must not restart docker, and — most
// of the sharp edge — must not overwrite a truthful state file with one that
// claims we made changes we did not make.
func Merge(existing []byte, runtimePath string) (merged []byte, st ProvisionState, changed bool, err error) {
	st = ProvisionState{
		Version:           provisionStateVersion,
		RuntimePath:       runtimePath,
		DaemonJSONExisted: existing != nil,
		DaemonJSONBefore:  string(existing),
	}

	cfg, err := decodeObject(existing)
	if err != nil {
		return nil, ProvisionState{}, false, err
	}

	// runtimes.drawbridge
	runtimes, err := decodeNested(cfg, runtimesKey)
	if err != nil {
		return nil, ProvisionState{}, false, err
	}
	want, err := json.Marshal(map[string]string{"path": runtimePath})
	if err != nil {
		return nil, ProvisionState{}, false, err
	}
	if prev, ok := runtimes[RuntimeName]; !ok || !jsonEqual(prev, want) {
		st.AddedRuntime = !ok
		runtimes[RuntimeName] = json.RawMessage(want)
	}
	encoded, err := json.Marshal(runtimes)
	if err != nil {
		return nil, ProvisionState{}, false, err
	}
	cfg[runtimesKey] = json.RawMessage(encoded)

	// default-runtime
	if prev, ok := cfg[defaultRTKey]; !ok || !jsonEqual(prev, mustJSONString(RuntimeName)) {
		st.SetDefaultRuntime = true
		if ok {
			var s string
			if err := json.Unmarshal(prev, &s); err != nil {
				return nil, ProvisionState{}, false, fmt.Errorf("%s: %s is not a string: %w", daemonJSONPath, defaultRTKey, err)
			}
			st.PrevDefaultRuntime = s
		}
		cfg[defaultRTKey] = json.RawMessage(mustJSONString(RuntimeName))
	}

	merged, err = encodeObject(cfg)
	if err != nil {
		return nil, ProvisionState{}, false, err
	}
	st.DaemonJSONAfter = sha256Hex(merged)

	// Compare against the file as it stands, bytes and all: a semantically
	// equal file that we would reformat is *not* a change worth a docker
	// restart, and reformatting a user's config uninvited is its own small
	// betrayal.
	if existing != nil && bytes.Equal(existing, merged) {
		return merged, st, false, nil
	}
	if existing != nil && !st.AddedRuntime && !st.SetDefaultRuntime {
		// Everything we want is already in the file; the only difference is
		// formatting we would impose. Leave it, and record the file as it
		// actually is so `down` compares against reality.
		st.DaemonJSONAfter = sha256Hex(existing)
		return existing, st, false, nil
	}
	return merged, st, true, nil
}

// Revert undoes Merge. `current` is nil when daemon.json is gone.
//
// Returns the bytes to write, whether to remove the file instead, and
// whether anything needs doing at all — `down` on a guest that never ran
// `up --oci` is a no-op success, not an error.
func Revert(current []byte, st ProvisionState) (out []byte, remove bool, changed bool, err error) {
	if st.Version > provisionStateVersion {
		return nil, false, false, fmt.Errorf("%s was written by a newer drawbridge (state version %d, this build understands %d): re-run `drawbridge down` with that version",
			ProvisionPath, st.Version, provisionStateVersion)
	}
	if current == nil {
		return nil, false, false, nil // already gone; nothing to revert
	}

	// The exact path: the file is still byte-for-byte what `up` wrote, so
	// the recorded original is the truthful answer.
	if st.DaemonJSONAfter != "" && sha256Hex(current) == st.DaemonJSONAfter {
		if !st.DaemonJSONExisted {
			return nil, true, true, nil
		}
		before := []byte(st.DaemonJSONBefore)
		return before, false, !bytes.Equal(before, current), nil
	}

	// The surgical path: someone edited daemon.json since. Undo only our own
	// keys and keep their edit. Formatting normalizes here — unavoidable
	// without an order-preserving JSON model, and far cheaper than the
	// alternative of discarding their change.
	cfg, err := decodeObject(current)
	if err != nil {
		return nil, false, false, err
	}
	if st.AddedRuntime {
		runtimes, err := decodeNested(cfg, runtimesKey)
		if err != nil {
			return nil, false, false, err
		}
		delete(runtimes, RuntimeName)
		if len(runtimes) == 0 {
			// We created the map; leaving `"runtimes": {}` behind would be a
			// leftover, not a revert.
			delete(cfg, runtimesKey)
		} else {
			encoded, err := json.Marshal(runtimes)
			if err != nil {
				return nil, false, false, err
			}
			cfg[runtimesKey] = json.RawMessage(encoded)
		}
	}
	if st.SetDefaultRuntime {
		// Only if it still says what we set it to: a user who re-pointed
		// default-runtime after `up` meant it.
		if v, ok := cfg[defaultRTKey]; ok && jsonEqual(v, mustJSONString(RuntimeName)) {
			if st.PrevDefaultRuntime == "" {
				delete(cfg, defaultRTKey)
			} else {
				cfg[defaultRTKey] = json.RawMessage(mustJSONString(st.PrevDefaultRuntime))
			}
		}
	}
	out, err = encodeObject(cfg)
	if err != nil {
		return nil, false, false, err
	}
	return out, false, !bytes.Equal(out, current), nil
}

// decodeObject parses daemon.json into a key-preserving map. Values stay raw
// so keys we do not own survive the round trip with their own formatting of
// arrays, numbers and nested objects intact.
func decodeObject(b []byte) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		if b == nil {
			return map[string]json.RawMessage{}, nil
		}
		// An existing but empty file. Docker fails to start on one, so
		// treating it as `{}` would quietly repair a broken config while
		// pretending to have merged into it.
		return nil, fmt.Errorf("%s exists but is empty: fix or remove it before running `drawbridge up --oci`", daemonJSONPath)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON (%w): fix it before running `drawbridge up --oci` — drawbridge will not overwrite a config it cannot read", daemonJSONPath, err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("%s parses as null, not an object: fix or remove it before running `drawbridge up --oci`", daemonJSONPath)
	}
	return cfg, nil
}

func decodeNested(cfg map[string]json.RawMessage, key string) (map[string]json.RawMessage, error) {
	raw, ok := cfg[key]
	if !ok {
		return map[string]json.RawMessage{}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %q is not an object: %w", daemonJSONPath, key, err)
	}
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	return m, nil
}

// encodeObject renders daemon.json. Two-space indent and a trailing newline
// match what Docker's own docs show and what the dev script has always
// written; json.Marshal sorts keys, which makes the output a function of the
// content alone — the property the sha256 comparison depends on.
func encodeObject(cfg map[string]json.RawMessage) ([]byte, error) {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// jsonEqual compares two raw values semantically, so a difference in
// whitespace inside a value we would rewrite does not read as a change.
func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ax, err1 := json.Marshal(x)
	by, err2 := json.Marshal(y)
	return err1 == nil && err2 == nil && bytes.Equal(ax, by)
}

func mustJSONString(s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		panic("guestbin: marshaling a string cannot fail: " + err.Error())
	}
	return b
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// EncodeState renders the state file. Indented because a human debugging a
// half-reverted guest will `cat` it, and it is small enough that the bytes
// cost nothing.
func EncodeState(st ProvisionState) ([]byte, error) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// DecodeState reads the state file. A missing file is the caller's business
// (there is nothing to revert); a corrupt one is an error, because guessing
// is the one thing this file exists to prevent.
func DecodeState(b []byte) (ProvisionState, error) {
	var st ProvisionState
	if err := json.Unmarshal(b, &st); err != nil {
		return ProvisionState{}, fmt.Errorf("%s is not valid JSON (%w): remove it to skip the daemon.json revert, or fix it — drawbridge will not guess what `up --oci` changed", ProvisionPath, err)
	}
	return st, nil
}
