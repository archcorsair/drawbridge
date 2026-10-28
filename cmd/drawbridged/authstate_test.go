package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/archcorsair/drawbridge/internal/introspect"
	"github.com/archcorsair/drawbridge/internal/transportauth"
)

// The introspection snapshot reports the posture the dials actually have. A
// secret that vanished after this daemon loaded it is not "none": every dial
// refuses, so the mode in force is still static-hmac-v1, with the file absent
// (M6). A path this process never had a secret at stays "none".
func TestAuthStateFollowsTheLatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "transport-secret-lima-dev")
	want := func(mode, state string) {
		t.Helper()
		got := authState(path)
		if got.Mode != mode || got.SecretState != state || got.SecretPath != path {
			t.Fatalf("authState = %+v, want mode %q state %q", got, mode, state)
		}
	}

	want(introspect.AuthModeNone, introspect.SecretAbsent)

	s, err := transportauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s.Format()), 0o600); err != nil {
		t.Fatal(err)
	}
	want(introspect.AuthModeStaticHMACv1, introspect.SecretOK)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	want(introspect.AuthModeStaticHMACv1, introspect.SecretAbsent)

	if err := os.WriteFile(path, []byte("nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want(introspect.AuthModeStaticHMACv1, introspect.SecretMalformed)
}
