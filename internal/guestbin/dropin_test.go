package guestbin

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The drop-in's bytes are a contract in two directions: podman parses them,
// and `down` deletes the file only when its digest still matches. Pinning
// them here is what makes both testable without a VM.
func TestDropinBytes(t *testing.T) {
	got, err := DropinBytes("/usr/bin/crun")
	if err != nil {
		t.Fatal(err)
	}
	const want = `# written by drawbridge up --oci; removed by drawbridge down. Do not edit.
[engine.runtimes]
crun = ["/usr/local/bin/drawbridge-crun", "/usr/bin/crun"]
`
	if string(got) != want {
		t.Fatalf("drop-in bytes changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	// The key is `crun`, not a new runtime name: podman keys its
	// runtime_supports_* lists on the name, and each is replaced wholesale
	// by TOML rather than merged.
	if !strings.Contains(want, "\ncrun = [") {
		t.Fatal("the drop-in no longer shadows the crun key")
	}
	// And the first element is the wrapper the engine constants name, so a
	// rename on either side is a test failure rather than a guest where
	// podman execs a path nothing installed.
	if !strings.Contains(string(got), `"`+WrapperPath(EnginePodman)+`"`) {
		t.Fatalf("the drop-in does not point at %s:\n%s", WrapperPath(EnginePodman), got)
	}
}

// The real crun path is a parameter because a constant would be a silent
// lie on a guest that puts it somewhere else.
func TestDropinBytesUsesTheGuestsCrun(t *testing.T) {
	got, err := DropinBytes("/usr/local/sbin/crun")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `"/usr/local/sbin/crun"]`) {
		t.Fatalf("fallback path not used:\n%s", got)
	}
}

// A path that cannot be quoted into TOML is refused rather than escaped:
// this file is deleted by digest, so it must never contain something `up`
// did not mean to write.
func TestDropinBytesRefusesUnquotablePaths(t *testing.T) {
	for _, bad := range []string{
		"",
		"crun",
		"/usr/bin/crun\"]\n[engine]\nruntime = \"evil",
		"/usr/bin/cr\\un",
		"/usr/bin/crun\n",
	} {
		if _, err := DropinBytes(bad); err == nil {
			t.Fatalf("DropinBytes(%q) was accepted", bad)
		}
	}
}

func dropinDigest(t *testing.T, realCrun string) ([]byte, string) {
	t.Helper()
	b, err := DropinBytes(realCrun)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}

// The three answers `down` can reach, and the evidence each turns on.
func TestRevertDropin(t *testing.T) {
	body, digest := dropinDigest(t, "/usr/bin/crun")
	st := PodmanState{
		Version: StateVersionPodman, Engine: EnginePodman,
		RuntimePath: WrapperPath(EnginePodman),
		DropinPath:  DropinPath, DropinSHA256: digest,
	}

	t.Run("unchanged", func(t *testing.T) {
		del, reason := RevertDropin(st, body)
		if !del {
			t.Fatalf("a drop-in still byte-identical to what `up` wrote was kept: %q", reason)
		}
		if reason != "" {
			t.Fatalf("a deletion came with a reason to print: %q", reason)
		}
	})

	t.Run("edited", func(t *testing.T) {
		edited := append(append([]byte{}, body...), "# a human was here\n"...)
		del, reason := RevertDropin(st, edited)
		if del {
			t.Fatal("an edited drop-in was deleted")
		}
		if !strings.Contains(reason, "edited since `up`; not removed") || !strings.Contains(reason, DropinPath) {
			t.Fatalf("reason does not name the file and the finding: %q", reason)
		}
	})

	t.Run("absent", func(t *testing.T) {
		del, reason := RevertDropin(st, nil)
		if del || reason != "" {
			t.Fatalf("an absent drop-in produced del=%v reason=%q", del, reason)
		}
	})

	t.Run("no digest recorded", func(t *testing.T) {
		bare := st
		bare.DropinSHA256 = ""
		del, reason := RevertDropin(bare, body)
		if del {
			t.Fatal("a drop-in was deleted on no evidence at all")
		}
		if !strings.Contains(reason, "no digest recorded") {
			t.Fatalf("reason = %q", reason)
		}
	})

	// A drop-in written for a different crun is *not* what this `up` wrote,
	// even though drawbridge wrote both.
	t.Run("different crun", func(t *testing.T) {
		other, _ := dropinDigest(t, "/usr/local/sbin/crun")
		if del, _ := RevertDropin(st, other); del {
			t.Fatal("a drop-in with a different digest was deleted")
		}
	})
}

func TestPodmanStateRoundTrip(t *testing.T) {
	st := PodmanState{
		Version: StateVersionPodman, Engine: EnginePodman,
		RuntimePath: "/usr/local/bin/drawbridge-crun",
		DropinPath:  DropinPath, DropinSHA256: strings.Repeat("ab", 32),
		Rootful: false, OCISockOwner: "core",
	}
	blob, err := EncodePodmanState(st)
	if err != nil {
		t.Fatal(err)
	}
	// Every field §6.2 names is present, `rootful: false` included: a state
	// file is read by humans as often as by `down`, and an omitted false is
	// indistinguishable from a field an older writer did not have.
	for _, key := range []string{
		`"version": 2`, `"engine": "podman"`, `"runtime_path"`,
		`"dropin_path"`, `"dropin_sha256"`, `"rootful": false`, `"oci_sock_owner": "core"`,
	} {
		if !strings.Contains(string(blob), key) {
			t.Fatalf("state file is missing %s:\n%s", key, blob)
		}
	}
	v, err := PeekStateVersion(blob)
	if err != nil || v != StateVersionPodman {
		t.Fatalf("PeekStateVersion = %d, %v", v, err)
	}
	back, err := DecodePodmanState(blob)
	if err != nil {
		t.Fatal(err)
	}
	if back != st {
		t.Fatalf("round trip changed the state:\n%+v\n%+v", back, st)
	}
}

// A docker guest's state file must stay exactly what it has always been:
// version 1, and not one byte of podman's schema.
func TestDockerStateStaysVersionOne(t *testing.T) {
	_, st, _, err := Merge(nil, "/usr/local/bin/drawbridge-runc")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncodeState(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), `"version": 1`) {
		t.Fatalf("docker state is no longer version 1:\n%s", blob)
	}
	for _, key := range []string{"engine", "dropin_path", "dropin_sha256", "rootful", "oci_sock_owner"} {
		if strings.Contains(string(blob), `"`+key+`"`) {
			t.Fatalf("podman's %q leaked into a docker state file:\n%s", key, blob)
		}
	}
}

// The version rule runs both ways. A build that understands 2 refuses 3…
func TestDecodePodmanStateRefusesNewer(t *testing.T) {
	_, err := DecodePodmanState([]byte(`{"version":3,"engine":"podman"}`))
	if err == nil || !strings.Contains(err.Error(), "newer drawbridge") {
		t.Fatalf("a version-3 state file was accepted: %v", err)
	}
}

// …and the version-1 reader — which is what an older `drawbridge down` is,
// byte for byte — refuses a version-2 file rather than misreading it as a
// daemon.json revert it has no business performing.
func TestVersionOneReaderRefusesPodmanState(t *testing.T) {
	_, _, _, err := Revert([]byte("{}"), ProvisionState{Version: StateVersionPodman})
	if err == nil || !strings.Contains(err.Error(), "newer drawbridge") {
		t.Fatalf("the v1 revert accepted a v2 state file: %v", err)
	}
}
