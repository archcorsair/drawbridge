// Package ociruntime rewrites an OCI runtime bundle's config.json so the
// runtime itself (runc/crun >= listenerPath support) installs a
// bind→SCMP_ACT_NOTIFY filter in the container and delivers the notify fd
// to the drawbridge agent (docs/oci-hook.md, Phase B).
//
// Deliberately no build tag: the mutation logic is pure JSON surgery and
// its tests run on the Mac. The spec is handled as generic maps, never
// typed structs — a round-trip through a struct would silently drop spec
// fields this package has no business touching.
package ociruntime

import (
	"encoding/json"
	"fmt"
)

// OptOutAnnotation disables injection for one container.
const OptOutAnnotation = "dev.drawbridge.arbitrate"

// Actions that make an existing profile's stance on bind provable.
const (
	actAllow  = "SCMP_ACT_ALLOW"
	actLog    = "SCMP_ACT_LOG"
	actNotify = "SCMP_ACT_NOTIFY"
)

// MutateConfig decides whether the bundle should get bind arbitration and,
// when it should, returns the rewritten config.json bytes. injected=false
// with a reason means "exec runc untouched" — never an error a wrapper
// should surface: the failure posture is stock behavior, not a broken
// container start. err is reserved for undecodable input.
func MutateConfig(raw []byte, listenerPath, listenerMetadata string) (out []byte, injected bool, reason string, err error) {
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		return nil, false, "", fmt.Errorf("parse config.json: %w", err)
	}

	if v, ok := annotation(spec, OptOutAnnotation); ok && v == "false" {
		return raw, false, "opt-out annotation", nil
	}
	if hasNetworkNamespace(spec) {
		// Private (or joined) netns: not a host-network container. The
		// agent's netns backstop would CONTINUE these binds anyway; not
		// injecting also spares the container the notify round trips.
		return raw, false, "private network namespace", nil
	}
	sec, refuse := seccompOf(spec)
	if refuse != "" {
		return raw, false, refuse, nil
	}

	linux := ensureMap(spec, "linux")
	if sec == nil {
		// Unconfined (incl. --privileged): synthesize a transparent
		// profile — allow everything, notify on bind. User-decided
		// (docs/oci-hook.md): host-net parity applies here too, with the
		// annotation as the escape hatch.
		linux["seccomp"] = map[string]any{
			"defaultAction": actAllow,
			"syscalls": []any{
				notifyRule(),
			},
			"listenerPath":     listenerPath,
			"listenerMetadata": listenerMetadata,
		}
	} else {
		stripBind(sec)
		sec["syscalls"] = append(syscallRules(sec), notifyRule())
		sec["listenerPath"] = listenerPath
		sec["listenerMetadata"] = listenerMetadata
	}

	out, err = json.Marshal(spec)
	if err != nil {
		return nil, false, "", err
	}
	return out, true, "injected", nil
}

func notifyRule() map[string]any {
	return map[string]any{
		"names":  []any{"bind"},
		"action": actNotify,
	}
}

// seccompOf returns the existing seccomp map (nil when unconfined) or a
// non-empty refusal reason. Injection must be provably a no-op for the
// workload: if the profile restricts bind in any way we can't trivially
// prove out, we must not flip that restriction into notify-CONTINUE
// (= allow) — never weaken a user's profile.
func seccompOf(spec map[string]any) (map[string]any, string) {
	linux, _ := spec["linux"].(map[string]any)
	if linux == nil {
		return nil, ""
	}
	sec, _ := linux["seccomp"].(map[string]any)
	if sec == nil {
		return nil, ""
	}
	da, _ := sec["defaultAction"].(string)
	bindRules := 0
	for _, r := range syscallRules(sec) {
		rule, _ := r.(map[string]any)
		if rule == nil || !namesContain(rule, "bind") {
			continue
		}
		bindRules++
		act, _ := rule["action"].(string)
		if act != actAllow {
			return nil, fmt.Sprintf("profile handles bind with %s", act)
		}
		if args, ok := rule["args"].([]any); ok && len(args) > 0 {
			return nil, "profile constrains bind args"
		}
	}
	if bindRules == 0 && da != actAllow && da != actLog {
		return nil, fmt.Sprintf("profile defaultAction %s with no bind allow rule", da)
	}
	return sec, ""
}

// stripBind removes "bind" from every rule's names, dropping rules left
// empty, so the appended notify rule is the only match.
func stripBind(sec map[string]any) {
	var kept []any
	for _, r := range syscallRules(sec) {
		rule, _ := r.(map[string]any)
		if rule == nil || !namesContain(rule, "bind") {
			kept = append(kept, r)
			continue
		}
		names, _ := rule["names"].([]any)
		var rest []any
		for _, n := range names {
			if s, _ := n.(string); s != "bind" {
				rest = append(rest, n)
			}
		}
		if len(rest) > 0 {
			rule["names"] = rest
			kept = append(kept, rule)
		}
	}
	sec["syscalls"] = kept
}

func syscallRules(sec map[string]any) []any {
	rules, _ := sec["syscalls"].([]any)
	return rules
}

func namesContain(rule map[string]any, name string) bool {
	names, _ := rule["names"].([]any)
	for _, n := range names {
		if s, _ := n.(string); s == name {
			return true
		}
	}
	return false
}

func hasNetworkNamespace(spec map[string]any) bool {
	linux, _ := spec["linux"].(map[string]any)
	if linux == nil {
		return false
	}
	nss, _ := linux["namespaces"].([]any)
	for _, ns := range nss {
		m, _ := ns.(map[string]any)
		if m == nil {
			continue
		}
		if t, _ := m["type"].(string); t == "network" {
			return true
		}
	}
	return false
}

func annotation(spec map[string]any, key string) (string, bool) {
	anns, _ := spec["annotations"].(map[string]any)
	if anns == nil {
		return "", false
	}
	v, ok := anns[key].(string)
	return v, ok
}

func ensureMap(m map[string]any, key string) map[string]any {
	if sub, _ := m[key].(map[string]any); sub != nil {
		return sub
	}
	sub := map[string]any{}
	m[key] = sub
	return sub
}
