package ociruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

const listener = "/run/drawbridge-oci.sock"
const meta = `{"v":1,"source":"drawbridge-runc","hostNetwork":true}`

// dockerDefault is the shape of moby's default profile: defaultAction
// ERRNO, one big allow list that includes bare bind, plus fields this
// package must not disturb.
const dockerDefault = `{
  "ociVersion": "1.2.0",
  "process": {"args": ["nginx"], "x-unknown-field": {"keep": true}},
  "linux": {
    "seccomp": {
      "defaultAction": "SCMP_ACT_ERRNO",
      "defaultErrnoRet": 1,
      "architectures": ["SCMP_ARCH_AARCH64"],
      "syscalls": [
        {"names": ["accept4", "bind", "listen"], "action": "SCMP_ACT_ALLOW"},
        {"names": ["clone"], "action": "SCMP_ACT_ALLOW",
         "args": [{"index": 0, "value": 2114060288, "op": "SCMP_CMP_MASKED_EQ"}]}
      ]
    }
  }
}`

func mutate(t *testing.T, raw string) (map[string]any, bool, string) {
	t.Helper()
	out, injected, reason, err := MutateConfig([]byte(raw), listener, meta)
	if err != nil {
		t.Fatalf("MutateConfig: %v", err)
	}
	var spec map[string]any
	if err := json.Unmarshal(out, &spec); err != nil {
		t.Fatalf("output not JSON: %v", err)
	}
	return spec, injected, reason
}

func seccompMap(t *testing.T, spec map[string]any) map[string]any {
	t.Helper()
	linux, _ := spec["linux"].(map[string]any)
	sec, _ := linux["seccomp"].(map[string]any)
	if sec == nil {
		t.Fatal("no linux.seccomp in output")
	}
	return sec
}

func TestInjectsIntoDockerDefaultProfile(t *testing.T) {
	spec, injected, reason := mutate(t, dockerDefault)
	if !injected {
		t.Fatalf("not injected: %s", reason)
	}
	sec := seccompMap(t, spec)
	if sec["listenerPath"] != listener {
		t.Fatalf("listenerPath = %v", sec["listenerPath"])
	}
	if sec["listenerMetadata"] != meta {
		t.Fatalf("listenerMetadata = %v", sec["listenerMetadata"])
	}
	// bind moved out of the allow rule into exactly one NOTIFY rule.
	var notifyRules, bindAllowRules int
	for _, r := range sec["syscalls"].([]any) {
		rule := r.(map[string]any)
		if namesContain(rule, "bind") {
			switch rule["action"] {
			case actNotify:
				notifyRules++
			default:
				bindAllowRules++
			}
		}
	}
	if notifyRules != 1 || bindAllowRules != 0 {
		t.Fatalf("bind rules after mutation: notify=%d other=%d", notifyRules, bindAllowRules)
	}
	// Untouched profile fields survive the round trip.
	if sec["defaultAction"] != "SCMP_ACT_ERRNO" {
		t.Fatalf("defaultAction changed: %v", sec["defaultAction"])
	}
	if sec["defaultErrnoRet"] != float64(1) {
		t.Fatalf("defaultErrnoRet lost: %v", sec["defaultErrnoRet"])
	}
	proc := spec["process"].(map[string]any)
	if _, ok := proc["x-unknown-field"]; !ok {
		t.Fatal("unknown field dropped — mutation must preserve the whole spec")
	}
	// accept4/listen kept their allow rule.
	kept := false
	for _, r := range sec["syscalls"].([]any) {
		if namesContain(r.(map[string]any), "accept4") {
			kept = true
		}
	}
	if !kept {
		t.Fatal("allow rule for accept4 lost")
	}
}

func TestSynthesizesProfileWhenUnconfined(t *testing.T) {
	spec, injected, reason := mutate(t, `{"ociVersion":"1.2.0","linux":{}}`)
	if !injected {
		t.Fatalf("not injected: %s", reason)
	}
	sec := seccompMap(t, spec)
	if sec["defaultAction"] != actAllow {
		t.Fatalf("synthesized defaultAction = %v, want transparent allow", sec["defaultAction"])
	}
	rules := sec["syscalls"].([]any)
	if len(rules) != 1 || !namesContain(rules[0].(map[string]any), "bind") {
		t.Fatalf("synthesized rules: %v", rules)
	}
}

func TestSkipsBridgedContainer(t *testing.T) {
	raw := `{"linux":{"namespaces":[{"type":"pid"},{"type":"network"}]}}`
	_, injected, reason := mutate(t, raw)
	if injected {
		t.Fatal("injected into a private-netns container")
	}
	if !strings.Contains(reason, "network namespace") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestSkipsJoinedNetns(t *testing.T) {
	raw := `{"linux":{"namespaces":[{"type":"network","path":"/proc/1/ns/net"}]}}`
	if _, injected, _ := mutate(t, raw); injected {
		t.Fatal("injected into a joined-netns container")
	}
}

func TestRefusesProfileThatRestrictsBind(t *testing.T) {
	raw := `{"linux":{"seccomp":{
	  "defaultAction":"SCMP_ACT_ALLOW",
	  "syscalls":[{"names":["bind"],"action":"SCMP_ACT_ERRNO"}]}}}`
	_, injected, reason := mutate(t, raw)
	if injected {
		t.Fatal("weakened a profile that denies bind")
	}
	if !strings.Contains(reason, "SCMP_ACT_ERRNO") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRefusesArgConstrainedBind(t *testing.T) {
	raw := `{"linux":{"seccomp":{
	  "defaultAction":"SCMP_ACT_ERRNO",
	  "syscalls":[{"names":["bind"],"action":"SCMP_ACT_ALLOW",
	    "args":[{"index":0,"value":2,"op":"SCMP_CMP_EQ"}]}]}}}`
	_, injected, reason := mutate(t, raw)
	if injected {
		t.Fatal("injected over an arg-constrained bind rule")
	}
	if !strings.Contains(reason, "args") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestRefusesDenyByDefaultWithoutBindRule(t *testing.T) {
	raw := `{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}}}`
	if _, injected, _ := mutate(t, raw); injected {
		t.Fatal("injected where the profile already denies bind by default")
	}
}

func TestHonorsOptOutAnnotation(t *testing.T) {
	raw := `{"annotations":{"dev.drawbridge.arbitrate":"false"},"linux":{}}`
	_, injected, reason := mutate(t, raw)
	if injected {
		t.Fatal("injected despite opt-out annotation")
	}
	if reason != "opt-out annotation" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestAllowDefaultProfileWithNoBindRule(t *testing.T) {
	raw := `{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW",
	  "syscalls":[{"names":["reboot"],"action":"SCMP_ACT_ERRNO"}]}}}`
	spec, injected, reason := mutate(t, raw)
	if !injected {
		t.Fatalf("not injected: %s", reason)
	}
	sec := seccompMap(t, spec)
	// The reboot deny rule must survive untouched.
	found := false
	for _, r := range sec["syscalls"].([]any) {
		if namesContain(r.(map[string]any), "reboot") {
			found = true
		}
	}
	if !found {
		t.Fatal("unrelated deny rule lost")
	}
}
