package vmprovider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []limaJSON {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	raw, err := decodeList(f)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return raw
}

func instances(t *testing.T, name, provider string) []Instance {
	t.Helper()
	raw := fixture(t, name)
	out := make([]Instance, 0, len(raw))
	for _, li := range raw {
		out = append(out, li.instance(provider))
	}
	return out
}

// `limactl list --json` is a *stream* of objects, one per instance, not an
// array — a decoder that expects `[...]` sees a working single-instance Mac
// and a broken multi-instance one.
func TestDecodeListIsAStream(t *testing.T) {
	if got := len(fixture(t, "lima-list.json")); got != 3 {
		t.Fatalf("decoded %d instances, want 3", got)
	}
	if got := len(fixture(t, "colima-list.json")); got != 2 {
		t.Fatalf("decoded %d colima instances, want 2", got)
	}
	// Whitespace is the decoder's business, not the fixture's.
	raw, err := decodeList(strings.NewReader(`{"name":"a"}  {"name":"b"}` + "\n\n" + `{"name":"c"}`))
	if err != nil || len(raw) != 3 {
		t.Fatalf("decodeList(concatenated) = %d, %v; want 3", len(raw), err)
	}
	if _, err := decodeList(strings.NewReader("not json")); err == nil {
		t.Fatal("decodeList accepted non-JSON")
	}
	if raw, err := decodeList(strings.NewReader("")); err != nil || raw != nil {
		t.Fatalf("decodeList(empty) = %v, %v; want no instances", raw, err)
	}
}

func TestListLima(t *testing.T) {
	got := instances(t, "lima-list.json", ProviderLima)
	want := []Instance{
		{ProviderLima, "drawbridge", "vz", "lima-drawbridge", true, "52:55:55:a5:de:d2"},
		{ProviderLima, "default", "qemu", "lima-default", false, ""},
		{ProviderLima, "stock-vz", "vz", "lima-stock-vz", true, "52:55:55:11:22:33"},
	}
	assertInstances(t, got, want)
}

// Colima is the same driver against a different LIMA_HOME — but its guests
// are not named like Lima's. Note the fixture: Lima reports
// `"hostname":"lima-colima"` while the guest's real hostname, and therefore
// its DHCP lease record, is `colima` (both observed live on 0.10.3/2.2.0).
// The LeaseName must come from the provider, never from that field.
func TestListColima(t *testing.T) {
	got := instances(t, "colima-list.json", ProviderColima)
	want := []Instance{
		{ProviderColima, "colima", "vz", "colima", true, "52:55:55:0a:de:02"},
		{ProviderColima, "colima-work", "vz", "colima-work", false, "52:55:55:0a:de:03"},
	}
	assertInstances(t, got, want)

	// Pin the trap itself: the fixture really does carry Lima's misleading
	// hostname, so a future "simplification" that reads it fails here.
	for _, li := range fixture(t, "colima-list.json") {
		if li.Hostname != "lima-"+li.Name {
			t.Fatalf("fixture %q no longer reproduces Lima's lima-<name> hostname (%q) — "+
				"the point of this case is that it disagrees with the lease record", li.Name, li.Hostname)
		}
	}
}

// The MAC is the value `-vm-mac` pins, so it must come from the vzNAT
// interface and from nothing else — the resolver only ever matches a vzNAT
// lease record, and another interface's address would pin it to a record
// that does not exist.
func TestMACAddressComesFromVZNAT(t *testing.T) {
	li := limaJSON{Name: "x"}
	li.Network = append(li.Network, struct {
		VZNAT      bool   `json:"vzNAT"`
		MACAddress string `json:"macAddress"`
	}{VZNAT: false, MACAddress: "de:ad:be:ef:00:01"})
	if got := li.instance(ProviderLima).MACAddress; got != "" {
		t.Fatalf("MACAddress = %q, want empty (no vzNAT interface)", got)
	}
	li.Network = append(li.Network, struct {
		VZNAT      bool   `json:"vzNAT"`
		MACAddress string `json:"macAddress"`
	}{VZNAT: true, MACAddress: "52:55:55:a5:de:d2"})
	if got := li.instance(ProviderLima).MACAddress; got != "52:55:55:a5:de:d2" {
		t.Fatalf("MACAddress = %q, want the vzNAT address", got)
	}
}

// Everything in this package shells out to limactl, which refuses euid 0 and
// keeps its state in the invoking user's LIMA_HOME. Failing before exec is
// what lets the error say what to do instead; the check exists so a future
// caller cannot make the root daemon depend on it by accident.
func TestRootIsRefusedBeforeExec(t *testing.T) {
	if os.Geteuid() == 0 {
		l := NewLima()
		if _, err := l.List(); err == nil || !strings.Contains(err.Error(), "user-scoped") {
			t.Fatalf("List() as root = %v, want ErrRootScoped", err)
		}
		return
	}
	t.Skip("not root: ErrRootScoped is asserted by inspection of the one seam (limactl)")
}

func TestShellNeedsACommand(t *testing.T) {
	if _, err := NewLima().Shell("drawbridge", nil); err == nil {
		t.Fatal("Shell with no argv was accepted")
	}
}

func TestStderrTailIsBounded(t *testing.T) {
	if got := stderrTail("   \n  "); got != "" {
		t.Fatalf("stderrTail(blank) = %q, want empty", got)
	}
	long := strings.Repeat("line\n", 40)
	got := stderrTail(long)
	if strings.Count(got, ";") != 2 {
		t.Fatalf("stderrTail kept more than the last 3 lines: %q", got)
	}
}

func assertInstances(t *testing.T, got, want []Instance) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d instances (%+v), want %d", len(got), got, len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("instance %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
