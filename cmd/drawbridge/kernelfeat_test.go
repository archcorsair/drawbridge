package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/archcorsair/drawbridge/internal/guestbin"
	"github.com/archcorsair/drawbridge/internal/kernelfeat"
)

// The agent's kernel floor in `up` (audit 2026-10-28 L5): asked of the
// kernel through the binary being installed, before it is installed.

// probingAgent is an agent fixture that carries the probe's marker, as every
// agent from this build does; the plain fixtures model one from before it.
func probingAgent(t *testing.T, tag string) string {
	return writeTempBinary(t, tag+" "+kernelfeat.Marker)
}

func withKernel(f *fakeGuest, rel string) *fakeGuest {
	f.preflight = strings.Replace(f.preflight, "kernel=6.8.0-51-generic", "kernel="+rel, 1)
	return f
}

func runUpCapture(t *testing.T, f *fakeGuest, o upOptions) (string, error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	sel := testSelection(t, "lima:drawbridge")
	var out bytes.Buffer
	err := up(&guest{p: f, inst: sel.Ref.Instance, out: &out}, sel, o)
	return out.String(), err
}

const stagedAgent = "/tmp/usr-local-bin-drawbridge-agent.new"

// A kernel that answers yes: the staged binary is asked, as the login user,
// and then installed.
func TestUpProbesTheStagedAgent(t *testing.T) {
	f := newFakeGuest(t)
	agent := probingAgent(t, "v1")
	out, err := runUpCapture(t, f, upOptions{agentBin: agent})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.probed) != 1 || f.probed[0] != stagedAgent {
		t.Fatalf("probed %v, want the staged copy only", f.probed)
	}
	if f.probedAsRoot {
		t.Fatal("the feature probe ran through sudo; it needs no privilege")
	}
	if !strings.Contains(f.files[agentPath], kernelfeat.Marker) {
		t.Fatal("the agent was not installed after a passing probe")
	}
	if strings.Contains(out, "warning") {
		t.Fatalf("a passing probe printed a warning:\n%s", out)
	}
}

// An unchanged agent is not re-staged, so the installed one (this build's,
// by the digest match) is what gets asked.
func TestUpProbesTheInstalledAgentWhenCurrent(t *testing.T) {
	f := newFakeGuest(t)
	agent := probingAgent(t, "v1")
	if _, err := runUpCapture(t, f, upOptions{agentBin: agent}); err != nil {
		t.Fatal(err)
	}
	f.probed = nil
	if _, err := runUpCapture(t, f, upOptions{agentBin: agent}); err != nil {
		t.Fatal(err)
	}
	if len(f.probed) != 1 || f.probed[0] != agentPath {
		t.Fatalf("probed %v, want the installed agent", f.probed)
	}
}

// A kernel that answers no: `up` refuses in plain words, naming the kernel
// and the feature, and the guest is as it was: the running agent's binary,
// the unit and its state are untouched, and the staged copy is cleaned up.
func TestUpRefusesAKernelWithoutTheCookie(t *testing.T) {
	f := withKernel(newFakeGuest(t), "5.13.0-generic")
	old := probingAgent(t, "old")
	if _, err := runUpCapture(t, f, upOptions{agentBin: old}); err != nil {
		t.Fatal(err)
	}
	unitBefore := f.files[guestbin.UnitPath]
	f.noCookie = true
	f.calls = nil

	_, err := runUpCapture(t, f, upOptions{agentBin: probingAgent(t, "new")})
	if err == nil {
		t.Fatal("up continued on a kernel that said no to SO_NETNS_COOKIE")
	}
	t.Logf("drawbridge up: %v", err)
	for _, want := range []string{"5.13.0-generic", "SO_NETNS_COOKIE", "protocol not available", ">= 6.4"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q:\n%v", want, err)
		}
	}
	if !strings.Contains(f.files[agentPath], "old") {
		t.Fatal("the refused agent replaced the installed one")
	}
	if f.files[guestbin.UnitPath] != unitBefore {
		t.Fatal("the unit changed on a refused run")
	}
	if f.ran("systemctl restart") || f.ran("systemctl enable") {
		t.Fatalf("the agent unit was touched on a refused run:\n%s", strings.Join(f.calls, "\n"))
	}
	if _, ok := f.files[stagedAgent]; ok {
		t.Fatal("the staged agent was left behind")
	}
}

// An agent from before the probe (a -agent-bin from an older build) cannot
// be asked, and must not be run: the fallback is the kernel version, where
// a new kernel passes silently, 5.12/5.13 warn and continue, and anything
// older refuses.
func TestUpOldAgentFallsBackToTheKernelVersion(t *testing.T) {
	t.Run("6.8 passes", func(t *testing.T) {
		f := newFakeGuest(t)
		out, err := runUpCapture(t, f, upOptions{agentBin: writeTempBinary(t, "pre-probe agent")})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "warning") {
			t.Fatalf("a 6.8 kernel warned:\n%s", out)
		}
	})
	t.Run("5.13 warns and continues", func(t *testing.T) {
		f := withKernel(newFakeGuest(t), "5.13.19")
		out, err := runUpCapture(t, f, upOptions{agentBin: writeTempBinary(t, "pre-probe agent")})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"warning", "cannot confirm getsockopt(SO_NETNS_COOKIE)", "predates", "journalctl"} {
			if !strings.Contains(out, want) {
				t.Errorf("5.13 fallback does not say %q:\n%s", want, out)
			}
		}
		t.Logf("%s", out)
		if f.files[agentPath] != "pre-probe agent" || !f.active {
			t.Fatal("a warning stopped the install")
		}
	})
	t.Run("5.10 refuses", func(t *testing.T) {
		f := withKernel(newFakeGuest(t), "5.10.0")
		_, err := runUpCapture(t, f, upOptions{agentBin: writeTempBinary(t, "pre-probe agent")})
		if err == nil || !strings.Contains(err.Error(), "older than 5.12") {
			t.Fatalf("got %v, want the 5.12 refusal", err)
		}
		if _, ok := f.files[agentPath]; ok {
			t.Fatal("a refused run installed the agent")
		}
	})
}

// The arm64 tracker floor, as reproduced live on Ubuntu 22.04's GA kernel
// (5.15.0-185, aarch64): the cookie probe says yes, the kernel config has no
// ftrace direct calls, and the agent would die loading the tracker's first
// fentry program. `up` refuses before installing, with the shared remedy.
func TestUpRefusesArm64WithoutDirectCalls(t *testing.T) {
	f := withKernel(newFakeGuest(t), "5.15.0-185-generic")
	f.directCalls = kernelfeat.ConfigNo
	_, err := runUpCapture(t, f, upOptions{agentBin: probingAgent(t, "new")})
	if err == nil {
		t.Fatal("up continued on an arm64 kernel without ftrace direct calls")
	}
	t.Logf("drawbridge up: %v", err)
	for _, want := range []string{"5.15.0-185-generic", "aarch64", "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS",
		"listener tracker", "linux-generic-hwe-22.04"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not say %q:\n%v", want, err)
		}
	}
	if !strings.Contains(err.Error(), strings.ReplaceAll(kernelfeat.TracerRemedy, "\n", "\n  ")) {
		t.Errorf("refusal does not carry the shared tracker remedy:\n%v", err)
	}
	if _, ok := f.files[agentPath]; ok {
		t.Fatal("a refused run installed the agent")
	}
	if _, ok := f.files[guestbin.UnitPath]; ok {
		t.Fatal("a refused run installed the unit")
	}
}

// With no readable kernel config, arm64 falls back to the 6.4 version floor.
func TestUpArm64VersionFallbackWithoutConfig(t *testing.T) {
	for kernel, refuse := range map[string]bool{"6.3.0": true, "6.4.0": false, "6.8.0-51-generic": false} {
		f := withKernel(newFakeGuest(t), kernel)
		f.directCalls = kernelfeat.ConfigUnknown
		_, err := runUpCapture(t, f, upOptions{agentBin: probingAgent(t, "new")})
		if refuse && (err == nil || !strings.Contains(err.Error(), "older than 6.4")) {
			t.Errorf("%s: got %v, want the 6.4 refusal", kernel, err)
		}
		if !refuse && err != nil {
			t.Errorf("%s: %v", kernel, err)
		}
	}
}
