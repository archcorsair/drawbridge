// Package transportauth is the per-VM transport authentication scheme
// (docs/transport-auth.md): a shared 32-byte secret provisioned by
// `drawbridge up`, and static, direction- and type-bound HMAC-SHA256 proofs
// riding in the transport's existing 4-byte type frame.
//
// The package is deliberately portable — the Mac daemon and the guest agent
// both link it — and deliberately small: one HMAC per connection, no state
// between connections, no round trip beyond the proofs themselves (§4).
//
// Secrets are file-borne only. They never appear in argv, environment, or
// logs; Secret.String redacts, so a stray %v cannot leak one.
package transportauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// SecretLen is the secret's size in bytes; the file holds it as 2*SecretLen
// lowercase hex characters plus a newline (§5).
const SecretLen = 32

// Secret is a per-VM transport secret.
type Secret [SecretLen]byte

// String redacts. The secret must never reach a log line, and the cheapest
// way to guarantee that is to make printing it impossible by construction.
func (s Secret) String() string { return "transportauth.Secret(redacted)" }

// Load results, kept distinct because they mean opposite things (§6): absent
// selects unauthenticated mode, malformed always fails closed (§5, mirroring
// the `-vm-mac` "a malformed pin fails closed" rule).
var (
	ErrAbsent    = errors.New("no transport secret file")
	ErrMalformed = errors.New("malformed transport secret")
)

// Generate returns a fresh secret from crypto/rand.
func Generate() (Secret, error) {
	var s Secret
	if _, err := rand.Read(s[:]); err != nil {
		return Secret{}, fmt.Errorf("generating transport secret: %w", err)
	}
	return s, nil
}

// Format renders the on-disk representation: 64 lowercase hex characters and
// a trailing newline, so the file is greppable, diffable, and safe to echo
// into a guest over stdin.
func (s Secret) Format() string { return hex.EncodeToString(s[:]) + "\n" }

// Parse reads the on-disk representation. Anything else — wrong length, bad
// hex, empty — is ErrMalformed. Surrounding whitespace is tolerated (the
// trailing newline is part of the format); case is not enforced, so a
// hand-written uppercase secret still loads.
func Parse(b []byte) (Secret, error) {
	txt := strings.TrimSpace(string(b))
	if len(txt) != 2*SecretLen {
		return Secret{}, fmt.Errorf("%w: want %d hex characters, got %d", ErrMalformed, 2*SecretLen, len(txt))
	}
	raw, err := hex.DecodeString(txt)
	if err != nil {
		return Secret{}, fmt.Errorf("%w: not hexadecimal", ErrMalformed)
	}
	var s Secret
	copy(s[:], raw)
	return s, nil
}

// Load reads and parses path. A missing file reports ErrAbsent; an
// unreadable or unparsable one reports ErrMalformed (§7 row 8 treats the two
// failure shapes alike — both mean "configured, but unusable").
func Load(path string) (Secret, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Secret{}, fmt.Errorf("%s: %w", path, ErrAbsent)
		}
		return Secret{}, fmt.Errorf("%s: %w (%w)", path, ErrMalformed, err)
	}
	s, err := Parse(b)
	if err != nil {
		return Secret{}, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// LoadOptional is Load with absent folded into (nil, nil): the shape both
// sides want, because "no file" is a mode (§6), not an error. An empty path
// means "not configured" too, so a zero-valued SecretFile field is legal.
func LoadOptional(path string) (*Secret, error) {
	if path == "" {
		return nil, nil
	}
	s, err := Load(path)
	if errors.Is(err, ErrAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Frame layout (§3.2): {type u8, auth u8, 0, 0}. Byte 1 is permanently the
// auth-scheme byte; bytes 2–3 remain the reserved-zero version escape hatch.
const (
	FrameLen = 4
	ProofLen = sha256.Size

	AuthNone         = 0 // today's wire, byte-identical
	AuthStaticHMACv1 = 1 // 32-byte HMAC-SHA256 proof follows the frame
)

// Domain separation: a proof is bound to its direction, the conn type, and
// the auth byte, so no captured proof is valid anywhere else (§3.2).
const (
	labelMac   = "drawbridge-transport-v1:mac"
	labelAgent = "drawbridge-transport-v1:agent"
)

// Frame builds the 4-byte type frame for a conn type and auth scheme.
func Frame(typ, auth byte) [FrameLen]byte { return [FrameLen]byte{typ, auth, 0, 0} }

// AuthFrame is the frame a side sends for typ given its own secret state:
// each side decides its mode from its own file, never from the wire (§6).
func AuthFrame(typ byte, sec *Secret) [FrameLen]byte {
	if sec == nil {
		return Frame(typ, AuthNone)
	}
	return Frame(typ, AuthStaticHMACv1)
}

// MacProof is what the Mac writes immediately after the frame.
func (s Secret) MacProof(frame [FrameLen]byte) [ProofLen]byte { return s.proof(labelMac, frame) }

// AgentProof is what the agent writes back before it dispatches.
func (s Secret) AgentProof(frame [FrameLen]byte) [ProofLen]byte { return s.proof(labelAgent, frame) }

func (s Secret) proof(label string, frame [FrameLen]byte) [ProofLen]byte {
	m := hmac.New(sha256.New, s[:])
	m.Write([]byte(label))
	m.Write(frame[:])
	var out [ProofLen]byte
	m.Sum(out[:0])
	return out
}

// Verify compares a received proof against the expected one in constant
// time. The compare sits on a network-observable path, so hmac.Equal is not
// optional (§4).
func Verify(want [ProofLen]byte, got []byte) bool { return hmac.Equal(want[:], got) }
