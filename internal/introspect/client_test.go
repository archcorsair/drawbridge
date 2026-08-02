package introspect

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// A daemon speaking a newer schema is not a parse failure: the two frozen
// fields still mean what they always meant, and everything else is declared
// unusable so a consumer falls back to inference instead of trusting fields
// whose meaning may have changed (D4).
func TestSchemaSkewKeepsFrozenFields(t *testing.T) {
	payload := []byte(`{
	  "schema": 2,
	  "version": "v9.9.9",
	  "mirror": {"entries": "a shape this build does not know"},
	  "somethingNew": {"nested": true}
	}`)
	snap, err := Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if snap.Usable {
		t.Fatal("schema 2 reported usable")
	}
	if snap.State.Schema != 2 || snap.State.Version != "v9.9.9" {
		t.Fatalf("frozen fields lost: %+v", snap.State)
	}
	if len(snap.State.Mirror.Entries) != 0 {
		t.Fatalf("unusable payload leaked fields: %+v", snap.State.Mirror)
	}
}

// Within schema 1 the rule is the opposite: unknown and absent fields are
// tolerated, because additive change is the only change allowed there.
func TestUnknownFieldsWithinSchemaOneAreTolerated(t *testing.T) {
	payload := []byte(`{"schema":1,"version":"v0.1.0","futureField":{"a":[1,2]},"sync":{"poolParked":3,"newCounter":7}}`)
	snap, err := Decode(payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !snap.Usable {
		t.Fatal("schema 1 reported unusable")
	}
	if snap.State.Sync.PoolParked != 3 {
		t.Fatalf("PoolParked = %d, want 3", snap.State.Sync.PoolParked)
	}
	if snap.State.Mirror.SessionUp {
		t.Fatal("absent field did not decode to its zero value")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"not json", "this is not a snapshot"},
		{"truncated", `{"schema":1,"version":"v0`},
		{"no schema", `{"version":"v0.1.0"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decode([]byte(tc.in)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Decode(%q) = %v, want ErrMalformed", tc.in, err)
			}
		})
	}
}

// Absent is the ordinary case — no daemon, or one that is not running — and
// must be distinguishable from a daemon that answered with nonsense.
func TestFetchAbsentVersusMalformed(t *testing.T) {
	if _, err := Fetch(sockPath(t), 200*time.Millisecond); !errors.Is(err, ErrAbsent) {
		t.Fatalf("Fetch of a nonexistent socket = %v, want ErrAbsent", err)
	}

	path := sockPath(t)
	serve(t, path, func() State {
		// A snapshot function cannot produce invalid JSON, so corruption is
		// simulated at the decode boundary instead; this only pins that the
		// two error classes are distinct sentinels.
		return State{Schema: Schema}
	})
	snap, err := Fetch(path, time.Second)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !snap.Usable {
		t.Fatal("a schema-1 payload reported unusable")
	}
	if errors.Is(ErrAbsent, ErrMalformed) || errors.Is(ErrMalformed, ErrAbsent) {
		t.Fatal("the two sentinels are not distinguishable")
	}
}

// The payload must never grow a field carrying secret material: the socket is
// group-readable on the root flavor, and digests are doctor's job.
func TestPayloadCarriesNoSecretMaterial(t *testing.T) {
	b, err := json.Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	walk(t, generic)
}

// allowedSecretKeys are the only "secret"-spelled fields the payload may
// carry: a path and a state word. Bytes, proofs, and digests are doctor's
// business, computed directly against the files.
var allowedSecretKeys = map[string]bool{"secretpath": true, "secretstate": true}

func walk(t *testing.T, v any) {
	t.Helper()
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			lower := strings.ToLower(k)
			for _, f := range []string{"secret", "proof", "digest", "sha256", "hmac"} {
				if strings.Contains(lower, f) && !allowedSecretKeys[lower] {
					t.Fatalf("payload field %q looks like secret material", k)
				}
			}
			walk(t, child)
		}
	case []any:
		for _, e := range val {
			walk(t, e)
		}
	}
}
