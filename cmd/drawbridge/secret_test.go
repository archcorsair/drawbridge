package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/transportauth"
	"github.com/archcorsair/drawbridge/internal/vmprovider"
)

// `up`'s transport-secret step (docs/transport-auth.md §5): the Mac file is
// authoritative, the guest converges to it, and a re-run writes nothing.

func secretEnv(t *testing.T, spec string) (vmprovider.Ref, string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	ref, err := vmprovider.ParseRef(spec)
	if err != nil {
		t.Fatal(err)
	}
	p, err := transportauth.PathForRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	return ref, p
}

func runEnsure(t *testing.T, f *fakeGuest, ref vmprovider.Ref) string {
	t.Helper()
	var out strings.Builder
	if err := ensureSecret(&guest{p: f, inst: ref.Instance, out: &out}, ref); err != nil {
		t.Fatalf("ensureSecret: %v", err)
	}
	return out.String()
}

func TestEnsureSecretGeneratesWhenAbsent(t *testing.T) {
	ref, macPath := secretEnv(t, "lima:drawbridge")
	f := newFakeGuest(t)

	out := runEnsure(t, f, ref)

	sec, err := transportauth.Load(macPath)
	if err != nil {
		t.Fatalf("Mac secret: %v", err)
	}
	if got := f.files[guestbin.SecretPath]; got != sec.Format() {
		t.Fatalf("guest secret = %q, want the Mac's %q", got, sec.Format())
	}
	if !f.ran("install -m 0600") {
		t.Fatalf("the guest secret was not installed 0600:\n%s", strings.Join(f.calls, "\n"))
	}
	// The directory is 0700 and the file 0600: this is the one artifact whose
	// mode is the whole security property.
	fi, err := os.Stat(macPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("Mac secret mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(macPath))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("secret directory mode = %v, want 0700", di.Mode().Perm())
	}
	for _, want := range []string{"generated a transport secret", guestbin.SecretPath} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Never in a command line: the bytes reach the guest on stdin.
	for _, c := range f.calls {
		if strings.Contains(c, strings.TrimSpace(sec.Format())) {
			t.Fatalf("the secret appeared in a guest command: %q", c)
		}
	}
}

// A second `up` reuses the Mac file and streams nothing: the digests already
// match, so the re-run is cheap and the journal stays quiet.
func TestEnsureSecretIdempotentRerun(t *testing.T) {
	ref, macPath := secretEnv(t, "lima:drawbridge")
	f := newFakeGuest(t)
	runEnsure(t, f, ref)
	first, err := os.ReadFile(macPath)
	if err != nil {
		t.Fatal(err)
	}

	f.calls = nil
	out := runEnsure(t, f, ref)

	second, err := os.ReadFile(macPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("the Mac secret was regenerated on a re-run")
	}
	if strings.Contains(out, "generated") || strings.Contains(out, "wrote") {
		t.Fatalf("a converged re-run said something:\n%s", out)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "dd of=") || strings.Contains(c, "install -m") {
			t.Fatalf("a converged re-run wrote to the guest: %q", c)
		}
	}
}

// The guest holding a *different* secret (VM recreated, snapshot restored)
// converges to the Mac's, which is authoritative.
func TestEnsureSecretConvergesDifferingGuest(t *testing.T) {
	ref, macPath := secretEnv(t, "lima:drawbridge")
	f := newFakeGuest(t)
	stale, err := transportauth.Generate()
	if err != nil {
		t.Fatal(err)
	}
	f.files[guestbin.SecretPath] = stale.Format()

	out := runEnsure(t, f, ref)

	sec, err := transportauth.Load(macPath)
	if err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.SecretPath] != sec.Format() {
		t.Fatal("the guest kept its stale secret")
	}
	if !strings.Contains(out, "wrote "+guestbin.SecretPath) {
		t.Fatalf("the convergence was silent:\n%s", out)
	}
}

// Rotation, as documented: delete the Mac file, re-run. The guest follows.
func TestEnsureSecretRotates(t *testing.T) {
	ref, macPath := secretEnv(t, "lima:drawbridge")
	f := newFakeGuest(t)
	runEnsure(t, f, ref)
	before := f.files[guestbin.SecretPath]

	if err := os.Remove(macPath); err != nil {
		t.Fatal(err)
	}
	runEnsure(t, f, ref)

	if f.files[guestbin.SecretPath] == before {
		t.Fatal("the guest kept the old secret after rotation")
	}
	sec, err := transportauth.Load(macPath)
	if err != nil {
		t.Fatal(err)
	}
	if f.files[guestbin.SecretPath] != sec.Format() {
		t.Fatal("the guest did not converge to the rotated secret")
	}
}

// A malformed Mac file is not silently repaired: replacing a file another
// install may depend on is not a fix, and the error carries the remedy.
func TestEnsureSecretMalformedMacFileIsFatal(t *testing.T) {
	ref, macPath := secretEnv(t, "lima:drawbridge")
	if err := os.MkdirAll(filepath.Dir(macPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(macPath, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newFakeGuest(t)

	err := ensureSecret(&guest{p: f, inst: ref.Instance, out: io.Discard}, ref)
	if err == nil {
		t.Fatal("a malformed Mac secret was accepted")
	}
	if !strings.Contains(err.Error(), "re-run `drawbridge up`") {
		t.Errorf("error does not name the remedy: %v", err)
	}
	if _, ok := f.files[guestbin.SecretPath]; ok {
		t.Fatal("wrote a guest secret from a malformed Mac file")
	}
}

// Two VMs never share a secret — the per-VM scope decision (§2), checked
// where it actually takes effect.
func TestEnsureSecretIsPerVM(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	read := func(spec string) string {
		t.Helper()
		ref, err := vmprovider.ParseRef(spec)
		if err != nil {
			t.Fatal(err)
		}
		f := newFakeGuest(t)
		runEnsure(t, f, ref)
		return f.files[guestbin.SecretPath]
	}
	dev, colima := read("lima:drawbridge"), read("colima:default")
	if dev == colima {
		t.Fatal("two VMs were provisioned with the same transport secret")
	}
	// And the canonical-ref pin holds end to end: the other spelling of the
	// same colima VM reuses its file rather than generating a second one.
	if again := read("colima:colima"); again != colima {
		t.Fatal("colima:colima and colima:default got different secrets")
	}
}
