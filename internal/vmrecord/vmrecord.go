// Package vmrecord is the Mac-side per-VM record `drawbridge up` writes for
// a provider whose transport endpoint cannot be rediscovered from the
// machine itself (docs/podman.md §3.4).
//
// Lima and Colima need nothing like it: their guests hold a vmnet address
// with a DHCP lease record, so resolution is a lookup any process can repeat
// (internal/limaaddr). A podman machine has no host-dialable guest address at
// all — gvproxy is user-mode — so the endpoint is a loopback port *we* chose
// at `up` time and the guest agent republishes through gvproxy on every
// start. Something has to remember which port that was, and this is it.
//
// Three properties are load-bearing:
//
//   - It carries no secret. An endpoint, an ssh port, a key *path*: the
//     transport secret stays in its own 0600 file, and the bytes are
//     file-borne only (docs/transport-auth.md §5). The file is still 0600,
//     because the endpoint it names is the one the root daemon will dial.
//   - It lives beside the transport secret, under the same SUDO_USER-aware
//     home (transportauth.Dir), so `sudo drawbridge install` reads the record
//     the unprivileged `up` wrote rather than one under /var/root.
//   - The *running* root daemon never reads it. `install` renders what it
//     found into the plist; root then has everything in argv and parses no
//     user-writable file while running.
//
// Deleting the file and re-running `up` is the reset.
package vmrecord

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// Version is the schema version this build writes. A reader that meets a
// newer one refuses rather than guesses, the same rule the guest-side
// provisioning state follows.
const Version = 1

// Transport sources, as recorded and as reported by the resolver. Branch B
// (`ssh-tunnel`, docs/podman.md §3.3) is designed and not built; the constant
// is deliberately absent until it is, so nothing can write a value no reader
// understands.
const TransportGvproxyPublish = "gvproxy-publish"

// ErrAbsent is what Read returns when there is no record. It is a legitimate
// state — `install` before `up`, or a VM that was never attached — so callers
// distinguish it from a broken file and say which.
var ErrAbsent = errors.New("no VM record")

// Record is what `up` learned about a VM that resolution cannot rediscover.
type Record struct {
	Version  int    `json:"version"`
	Provider string `json:"provider"`
	Instance string `json:"instance"`

	// Transport names which scheme the endpoint belongs to, so a reader can
	// tell "the agent publishes this loopback port through gvproxy" from a
	// future branch's socket without inspecting the endpoint's shape.
	Transport string `json:"transport"`
	Endpoint  string `json:"endpoint"` // canonical, e.g. tcp://127.0.0.1:4778

	SSH SSH `json:"ssh"`

	Rootful bool   `json:"rootful"`
	VMType  string `json:"vmtype"`

	WrittenBy string `json:"written_by"` // the CLI version that wrote it
	WrittenAt string `json:"written_at"` // RFC3339
}

// SSH is the machine's ssh coordinate triple as the provider reported it.
// Recorded even though branch A does not dial it: doctor compares the record
// against a live `podman machine inspect` to catch a machine that was
// recreated under the same name, and the port is the field that moves.
type SSH struct {
	Port     int    `json:"port"`
	Identity string `json:"identity"` // a path; never key bytes
	User     string `json:"user"`
}

// FileName is the record's basename for a VM, derived from the canonical ref
// exactly as the transport secret's is — so the two files always describe the
// same machine.
func FileName(ref vmprovider.Ref) string {
	return "vm-" + ref.Provider + "-" + ref.Instance + ".json"
}

// Path is where the record for a VM lives: beside the transport secret, under
// the invoking user's home (root's SUDO_USER home under sudo).
func Path(ref vmprovider.Ref) (string, error) {
	dir, err := transportauth.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, FileName(ref)), nil
}

// Write stores the record for a VM, creating the directory if needed.
//
// The mode is applied explicitly after the write: os.WriteFile only applies
// it when it creates the file, and umask can trim it either way.
func Write(ref vmprovider.Ref, rec Record) error {
	path, err := Path(ref)
	if err != nil {
		return err
	}
	rec.Version = Version
	rec.Provider, rec.Instance = ref.Provider, ref.Instance
	if rec.WrittenAt == "" {
		rec.WrittenAt = time.Now().UTC().Format(time.RFC3339)
	}
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the VM record: %w", err)
	}
	blob = append(blob, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// Read loads the record for a VM. A missing file is ErrAbsent; a malformed or
// future one is an error naming the path and the remedy, never a zero value
// that would send the daemon at a plausible-looking endpoint nobody chose.
func Read(ref vmprovider.Ref) (Record, error) {
	path, err := Path(ref)
	if err != nil {
		return Record{}, err
	}
	blob, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return Record{}, fmt.Errorf("%w at %s", ErrAbsent, path)
	case err != nil:
		return Record{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var rec Record
	if err := json.Unmarshal(blob, &rec); err != nil {
		return Record{}, fmt.Errorf("parsing %s: %w\n  Delete it and re-run `drawbridge up %s`", path, err, ref.Spec)
	}
	if rec.Version > Version {
		return Record{}, fmt.Errorf("%s was written by a newer drawbridge (record version %d, this build reads %d): upgrade the CLI",
			path, rec.Version, Version)
	}
	if rec.Endpoint == "" {
		return Record{}, fmt.Errorf("%s records no endpoint: re-run `drawbridge up %s`", path, ref.Spec)
	}
	return rec, nil
}

// Remove deletes the record. Absent is success: `down` is idempotent.
func Remove(ref vmprovider.Ref) (bool, error) {
	path, err := Path(ref)
	if err != nil {
		return false, err
	}
	switch err := os.Remove(path); {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("removing %s: %w", path, err)
	}
}
