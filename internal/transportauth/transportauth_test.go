package transportauth

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSecret is the fixed vector's key: bytes 0x00..0x1f.
func testSecret() Secret {
	var s Secret
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func TestLoadAbsentMalformedGood(t *testing.T) {
	dir := t.TempDir()
	good := testSecret()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name string
		path string
		want error // nil means "loads"
	}{
		{"absent", filepath.Join(dir, "nope"), ErrAbsent},
		{"empty", write("empty", ""), ErrMalformed},
		{"short", write("short", "0011\n"), ErrMalformed},
		{"long", write("long", good.Format()[:64]+"ab\n"), ErrMalformed},
		{"nonhex", write("nonhex", strings.Repeat("z", 64)+"\n"), ErrMalformed},
		{"good", write("good", good.Format()), nil},
		{"noNewline", write("nonl", strings.TrimSpace(good.Format())), nil},
		{"uppercase", write("upper", strings.ToUpper(strings.TrimSpace(good.Format()))+"\n"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Load(tc.path)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("Load = %v, want %v", err, tc.want)
				}
				if !strings.Contains(err.Error(), tc.path) {
					t.Errorf("error %q does not name the file", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if s != good {
				t.Fatalf("loaded secret differs from the written one")
			}
		})
	}

	// LoadOptional folds absent into (nil, nil) — "no file" is a mode, not a
	// failure — but keeps malformed fatal.
	if p, err := LoadOptional(filepath.Join(dir, "nope")); p != nil || err != nil {
		t.Fatalf("LoadOptional(absent) = %v, %v; want nil, nil", p, err)
	}
	if p, err := LoadOptional(""); p != nil || err != nil {
		t.Fatalf("LoadOptional(\"\") = %v, %v; want nil, nil", p, err)
	}
	if _, err := LoadOptional(filepath.Join(dir, "empty")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("LoadOptional(malformed) = %v, want ErrMalformed", err)
	}
	if p, err := LoadOptional(filepath.Join(dir, "good")); err != nil || p == nil || *p != good {
		t.Fatalf("LoadOptional(good) = %v, %v", p, err)
	}
}

func TestGenerateFormatRoundTrip(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated secrets are equal")
	}
	f := a.Format()
	if len(f) != 2*SecretLen+1 || f[len(f)-1] != '\n' {
		t.Fatalf("Format = %q, want 64 hex chars + newline", f)
	}
	if strings.ToLower(f) != f {
		t.Fatalf("Format = %q, want lowercase hex", f)
	}
	got, err := Parse([]byte(f))
	if err != nil || got != a {
		t.Fatalf("Parse(Format) = %v, %v", got, err)
	}
}

// A secret must be unprintable by construction: the "never in logs"
// invariant cannot rely on every future caller remembering it.
func TestSecretStringRedacts(t *testing.T) {
	s := testSecret()
	if strings.Contains(s.String(), "000102") {
		t.Fatalf("Secret.String leaks bytes: %q", s.String())
	}
	if got := (&s).String(); strings.Contains(got, "000102") {
		t.Fatalf("(*Secret).String leaks bytes: %q", got)
	}
}

// Fixed vectors pin the HMAC construction — key, label, and the frame bytes
// that follow it — so an accidental change to any of the three fails here
// rather than silently breaking compatibility with a provisioned guest.
func TestProofVectors(t *testing.T) {
	s := testSecret()
	for _, tc := range []struct {
		typ        byte
		mac, agent string
	}{
		{'S', "7a9a0ed9be59483432b20ccbde76cb0ec2e4dec01d0135965fd89695abd31cee",
			"3bda52a3de39ecbc0c75cf619807c0f7a8e0828561a1da9327bf0d28ab435d28"},
		{'D', "878628497cbb08b16e4d35a042c725de54b679378d4020ca5e143a5ebf381a54",
			"a008de603df269b6a2122b88bc446c9932e3ba2214a202cadd30219e8ce653b2"},
	} {
		frame := Frame(tc.typ, AuthStaticHMACv1)
		if got := hex.EncodeToString(mustProof(s.MacProof(frame))); got != tc.mac {
			t.Errorf("MacProof('%c') = %s, want %s", tc.typ, got, tc.mac)
		}
		if got := hex.EncodeToString(mustProof(s.AgentProof(frame))); got != tc.agent {
			t.Errorf("AgentProof('%c') = %s, want %s", tc.typ, got, tc.agent)
		}
	}
}

func mustProof(p [ProofLen]byte) []byte { return p[:] }

// Direction, conn type, and the auth byte are all inside the MAC: no proof
// is reusable anywhere it was not minted for (§3.2).
func TestProofsAreBound(t *testing.T) {
	s := testSecret()
	fS := Frame('S', AuthStaticHMACv1)
	fM := Frame('M', AuthStaticHMACv1)
	f0 := Frame('S', AuthNone)

	if s.MacProof(fS) == s.AgentProof(fS) {
		t.Error("mac and agent proofs match on the same frame")
	}
	if s.MacProof(fS) == s.MacProof(fM) {
		t.Error("proof is not bound to the conn type")
	}
	if s.MacProof(fS) == s.MacProof(f0) {
		t.Error("proof is not bound to the auth byte")
	}
	other, _ := Generate()
	if other.MacProof(fS) == s.MacProof(fS) {
		t.Error("different secrets produce the same proof")
	}
}

// Verify must be the constant-time compare, and must reject a truncated or
// oversized proof rather than comparing a prefix.
func TestVerifyConstantTimeAndLengthStrict(t *testing.T) {
	s := testSecret()
	frame := Frame('E', AuthStaticHMACv1)
	want := s.MacProof(frame)

	if !Verify(want, want[:]) {
		t.Fatal("Verify rejected the correct proof")
	}
	if Verify(want, want[:ProofLen-1]) {
		t.Error("Verify accepted a truncated proof")
	}
	if Verify(want, append(want[:], 0)) {
		t.Error("Verify accepted an oversized proof")
	}
	if Verify(want, nil) {
		t.Error("Verify accepted an empty proof")
	}
	bad := want
	bad[0] ^= 0x01
	if Verify(want, bad[:]) {
		t.Error("Verify accepted a one-bit-off proof")
	}
	// The compare is hmac.Equal itself, not a hand-rolled loop: pinned by
	// agreeing with it on every case above.
	if Verify(want, bad[:]) != hmac.Equal(want[:], bad[:]) {
		t.Error("Verify disagrees with hmac.Equal")
	}
}

func TestAuthFrameFollowsLocalSecretOnly(t *testing.T) {
	s := testSecret()
	if got := AuthFrame('D', nil); got != [FrameLen]byte{'D', 0, 0, 0} {
		t.Errorf("AuthFrame(nil) = %v, want today's frame", got)
	}
	if got := AuthFrame('D', &s); got != [FrameLen]byte{'D', 1, 0, 0} {
		t.Errorf("AuthFrame(secret) = %v, want auth=1", got)
	}
}
