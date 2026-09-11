package vmrecord

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

func ref(t *testing.T, spec string) vmprovider.Ref {
	t.Helper()
	r, err := vmprovider.ParseRef(spec)
	if err != nil {
		t.Fatalf("ParseRef(%q): %v", spec, err)
	}
	return r
}

func sample() Record {
	return Record{
		Transport: TransportGvproxyPublish,
		Endpoint:  "tcp://127.0.0.1:4778",
		SSH:       SSH{Port: 57446, Identity: "/Users/u/.local/share/containers/podman/machine/machine", User: "core"},
		Rootful:   false,
		VMType:    "libkrun",
		WrittenBy: "v0.2.0",
	}
}

// The record is the sibling of the transport secret, and for the same reason:
// `sudo drawbridge install` has to find what the unprivileged `up` wrote.
func TestPathSitsBesideTheTransportSecret(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")
	p, err := Path(r)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := transportauth.PathForRef(r)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != filepath.Dir(secret) {
		t.Fatalf("record %q and secret %q are not siblings", p, secret)
	}
	if filepath.Base(p) != "vm-podman-spike.json" {
		t.Fatalf("basename = %q, want vm-podman-spike.json", filepath.Base(p))
	}
}

func TestRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")

	if _, err := Read(r); !errors.Is(err, ErrAbsent) {
		t.Fatalf("Read before Write = %v, want ErrAbsent", err)
	}
	if err := Write(r, sample()); err != nil {
		t.Fatal(err)
	}
	got, err := Read(r)
	if err != nil {
		t.Fatal(err)
	}
	want := sample()
	want.Version, want.Provider, want.Instance = Version, "podman", "spike"
	want.WrittenAt = got.WrittenAt
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if got.WrittenAt == "" {
		t.Fatal("Write did not stamp written_at")
	}

	// The endpoint it names is the one the root daemon will dial, so the file
	// is not world-readable even though it holds no secret bytes.
	p, _ := Path(r)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", fi.Mode().Perm())
	}

	// Nothing secret is in it: a path is recorded, never key bytes.
	blob, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "proof", "key", "hmac"} {
		for k := range raw {
			if strings.Contains(strings.ToLower(k), forbidden) {
				t.Fatalf("the record carries a %q field, transport secrets are file-borne only", k)
			}
		}
	}

	removed, err := Remove(r)
	if err != nil || !removed {
		t.Fatalf("Remove = %v, %v; want a removal", removed, err)
	}
	// Idempotent: `down` runs against guests that never had a record.
	if removed, err := Remove(r); err != nil || removed {
		t.Fatalf("second Remove = %v, %v; want a no-op success", removed, err)
	}
}

// A record we cannot read must never degrade into a zero value: the endpoint
// would then be empty and the daemon would be pointed somewhere nobody chose.
func TestUnreadableRecordsFailWithARemedy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := ref(t, "podman:spike")
	p, err := Path(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"malformed", "{not json", "drawbridge up"},
		{"from the future", `{"version":99,"endpoint":"tcp://127.0.0.1:4778"}`, "newer drawbridge"},
		{"no endpoint", `{"version":1,"endpoint":""}`, "records no endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Read(r)
			if err == nil {
				t.Fatal("Read accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			if errors.Is(err, ErrAbsent) {
				t.Fatal("a broken record read as an absent one")
			}
		})
	}
}

// Under sudo the record belongs to the invoking user, not root, the same
// rule (and the same seam) as the transport secret's path.
func TestPathFollowsTheSudoUserHome(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	p, err := Path(ref(t, "podman:spike"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := transportauth.Dir()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(p) != dir {
		t.Fatalf("Path dir = %q, want transportauth.Dir() %q", filepath.Dir(p), dir)
	}
}

// The record is what `up` learned then; the machine's config is what is true
// now. Which field moved is the message, so the comparison returns a list.
func TestDisagreements(t *testing.T) {
	rec := sample()
	rec.VMType = "libkrun"
	live := vmprovider.MachineConfig{
		Name:    "spike",
		VMType:  "libkrun",
		Rootful: false,
		SSH:     vmprovider.PodmanSSH{Port: 57446, RemoteUsername: "core"},
	}
	if d := rec.Disagreements(live); len(d) != 0 {
		t.Fatalf("an unchanged machine disagreed: %v", d)
	}

	for _, tc := range []struct {
		name string
		fix  func(*vmprovider.MachineConfig)
		want string
	}{
		{"recreated on another provider", func(c *vmprovider.MachineConfig) { c.VMType = "applehv" }, "machine type"},
		{"switched to rootful", func(c *vmprovider.MachineConfig) { c.Rootful = true }, "rootful"},
		{"recreated under the same name", func(c *vmprovider.MachineConfig) { c.SSH.Port = 61000 }, "ssh port"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := live
			tc.fix(&c)
			d := rec.Disagreements(c)
			if len(d) != 1 || !strings.Contains(d[0], tc.want) {
				t.Fatalf("Disagreements = %v, want one mentioning %q", d, tc.want)
			}
		})
	}

	// Every field at once: all of them are named, not just the first.
	c := live
	c.VMType, c.Rootful, c.SSH.Port = "applehv", true, 61000
	if d := rec.Disagreements(c); len(d) != 3 {
		t.Fatalf("Disagreements = %v, want all three named", d)
	}

	// A field neither side knows is not a disagreement: an older record with
	// no vmtype, or a config we could only partly read, must not manufacture
	// a refusal out of an absence.
	blank := rec
	blank.VMType, blank.SSH.Port = "", 0
	c = live
	c.VMType, c.SSH.Port = "", 0
	if d := blank.Disagreements(c); len(d) != 0 {
		t.Fatalf("missing fields on both sides disagreed: %v", d)
	}
}
