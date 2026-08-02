package guestbin

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden daemon.json files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

const runcPath = "/usr/local/bin/drawbridge-runc"

// The merge is what `up --oci` writes into a file the user owns. The golden
// files pin the bytes; the state assertions pin what `down` will believe.
func TestMerge(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          string // fixture file, "" for an absent daemon.json
		out         string // golden file, "" when unchanged
		wantChanged bool
		wantState   ProvisionState
	}{
		{
			// No file at all: the common Lima case. `down` must delete it
			// again rather than leave a `{}` behind.
			name:        "absent",
			out:         "daemon-absent.merged.json",
			wantChanged: true,
			wantState: ProvisionState{
				AddedRuntime: true, SetDefaultRuntime: true, DaemonJSONExisted: false,
			},
		},
		{
			// An engine with unrelated settings. Keys we do not own survive,
			// and `default-runtime` was absent, so revert removes it — never
			// writes "runc", which is the engine's default and not ours to
			// assert.
			name:        "plain",
			in:          "daemon-plain.json",
			out:         "daemon-plain.merged.json",
			wantChanged: true,
			wantState: ProvisionState{
				AddedRuntime: true, SetDefaultRuntime: true, DaemonJSONExisted: true,
			},
		},
		{
			// A user who already runs crun as their default. Losing that on
			// revert would be the worst kind of bug: silent, and only
			// visible the next time they start a container.
			name:        "other-default",
			in:          "daemon-other-default.json",
			out:         "daemon-other-default.merged.json",
			wantChanged: true,
			wantState: ProvisionState{
				AddedRuntime: true, SetDefaultRuntime: true,
				PrevDefaultRuntime: "crun", DaemonJSONExisted: true,
			},
		},
		{
			// Already merged — the second `up --oci`. Nothing to write, and
			// crucially nothing recorded as ours: reverting a registration
			// the user made themselves is not `down`'s to do.
			name:      "already-merged",
			in:        "daemon-premerged.json",
			wantState: ProvisionState{DaemonJSONExisted: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var in []byte
			if tc.in != "" {
				in = fixture(t, tc.in)
			}
			merged, st, changed, err := Merge(in, runcPath)
			if err != nil {
				t.Fatal(err)
			}
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if st.AddedRuntime != tc.wantState.AddedRuntime ||
				st.SetDefaultRuntime != tc.wantState.SetDefaultRuntime ||
				st.PrevDefaultRuntime != tc.wantState.PrevDefaultRuntime ||
				st.DaemonJSONExisted != tc.wantState.DaemonJSONExisted {
				t.Fatalf("state = %+v, want %+v", st, tc.wantState)
			}
			if st.RuntimePath != runcPath {
				t.Fatalf("state.RuntimePath = %q, want %q", st.RuntimePath, runcPath)
			}
			if st.DaemonJSONBefore != string(in) {
				t.Fatalf("state.DaemonJSONBefore does not hold the original bytes")
			}
			if st.DaemonJSONAfter != sha256Hex(merged) {
				t.Fatalf("state.DaemonJSONAfter is not the digest of what we would write")
			}
			if tc.out != "" {
				golden(t, tc.out, string(merged))
			} else if string(merged) != string(in) {
				t.Fatalf("an unchanged merge must return the file untouched:\n%s", merged)
			}
		})
	}
}

// The §8 Phase 4 assertion, as a unit test: after `up --oci` and `down`, the
// file is byte-identical to what it was — including whatever indentation and
// key order the user's own tooling wrote, which our formatter would not
// reproduce.
func TestRevertIsByteIdentical(t *testing.T) {
	for _, name := range []string{"daemon-plain.json", "daemon-other-default.json", "daemon-premerged.json"} {
		t.Run(name, func(t *testing.T) {
			before := fixture(t, name)
			merged, st, _, err := Merge(before, runcPath)
			if err != nil {
				t.Fatal(err)
			}
			out, remove, _, err := Revert(merged, st)
			if err != nil {
				t.Fatal(err)
			}
			if remove {
				t.Fatal("revert wants to remove a file that existed before")
			}
			if string(out) != string(before) {
				t.Fatalf("revert is not byte-identical:\n--- got ---\n%s\n--- want ---\n%s", out, before)
			}
		})
	}
}

// The file `up --oci` created is removed, not blanked.
func TestRevertRemovesCreatedFile(t *testing.T) {
	merged, st, _, err := Merge(nil, runcPath)
	if err != nil {
		t.Fatal(err)
	}
	out, remove, changed, err := Revert(merged, st)
	if err != nil {
		t.Fatal(err)
	}
	if !remove || !changed || out != nil {
		t.Fatalf("Revert = (%q, remove=%v, changed=%v), want a removal", out, remove, changed)
	}
}

// Someone edited daemon.json between `up --oci` and `down`. Restoring the
// recorded original would silently discard their edit, so the revert becomes
// surgical: our keys go, theirs stay. Formatting normalizes here, and that
// is the documented trade.
func TestRevertPreservesLaterEdits(t *testing.T) {
	before := fixture(t, "daemon-plain.json")
	_, st, _, err := Merge(before, runcPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := fixture(t, "daemon-plain.edited.json")
	out, remove, changed, err := Revert(edited, st)
	if err != nil {
		t.Fatal(err)
	}
	if remove || !changed {
		t.Fatalf("Revert(edited) = remove=%v changed=%v, want an in-place rewrite", remove, changed)
	}
	got := string(out)
	if strings.Contains(got, RuntimeName) {
		t.Fatalf("surgical revert left drawbridge behind:\n%s", got)
	}
	if !strings.Contains(got, `"live-restore"`) {
		t.Fatalf("surgical revert discarded the user's own edit:\n%s", got)
	}
	golden(t, "daemon-plain.edited.reverted.json", got)
}

// A user who re-pointed default-runtime after `up --oci` meant it; `down`
// must not overwrite that with the value it happened to record.
func TestRevertKeepsReassignedDefault(t *testing.T) {
	before := fixture(t, "daemon-other-default.json")
	_, st, _, err := Merge(before, runcPath)
	if err != nil {
		t.Fatal(err)
	}
	reassigned := []byte(`{"default-runtime":"youki","runtimes":{"drawbridge":{"path":"/usr/local/bin/drawbridge-runc"},"crun":{"path":"/usr/bin/crun"}}}`)
	out, _, _, err := Revert(reassigned, st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"youki"`) {
		t.Fatalf("revert clobbered a default-runtime the user chose after up:\n%s", out)
	}
}

// `down` on a guest whose daemon.json is already gone is a no-op success,
// not an error: idempotence in both directions is the contract.
func TestRevertMissingFile(t *testing.T) {
	_, _, changed, err := Revert(nil, ProvisionState{Version: 1, AddedRuntime: true})
	if err != nil || changed {
		t.Fatalf("Revert(nil) = changed=%v, %v; want a silent no-op", changed, err)
	}
}

// A state file from a future CLI has to be refused, not misread. The whole
// point of the file is that the revert is never a guess.
func TestRevertRefusesNewerState(t *testing.T) {
	_, _, _, err := Revert([]byte("{}"), ProvisionState{Version: 99})
	if err == nil || !strings.Contains(err.Error(), "newer drawbridge") {
		t.Fatalf("Revert with a future state version: got %v, want a refusal", err)
	}
}

// A daemon.json we cannot parse is not one we get to overwrite — docker
// would not have started with it either, and clobbering it would destroy the
// evidence of why.
func TestMergeRefusesUnparseable(t *testing.T) {
	for _, in := range []string{"{ not json", "", "null", "[]"} {
		if _, _, _, err := Merge([]byte(in), runcPath); err == nil {
			t.Fatalf("Merge(%q) succeeded, want a refusal", in)
		}
	}
}

// Round-tripping the state file is what connects `up` to `down` across
// processes, so the exact shape matters more than the convenience.
func TestStateRoundTrip(t *testing.T) {
	_, st, _, err := Merge(fixture(t, "daemon-other-default.json"), runcPath)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncodeState(st)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeState(blob)
	if err != nil {
		t.Fatal(err)
	}
	if back != st {
		t.Fatalf("state round trip lost information:\n got %+v\nwant %+v", back, st)
	}
	if _, err := DecodeState([]byte("{oops")); err == nil {
		t.Fatal("a corrupt state file must be an error — guessing is the one thing it exists to prevent")
	}
}
