package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// topologyInvokeTool identifies governed multi-agent delegation calls that must
// satisfy orchestrator routing manifests when policy defines orchestrator_manifest.
func topologyInvokeTool(toolID string) bool {
	if toolID == "multiagent/invoke_agent" || toolID == "invoke_agent" {
		return true
	}
	if strings.HasSuffix(toolID, "/invoke_agent") {
		return true
	}
	parts := strings.Split(strings.TrimSpace(toolID), "/")
	if len(parts) >= 2 && parts[len(parts)-2] == "invoke_agent" {
		return true
	}
	return false
}

// extractTargetAgentID reads the callee agent id from common CAR shapes.
func extractTargetAgentID(args map[string]any) string {
	return extractNestedString(args, "target_agent_id", "agent_id")
}

func enforceDelegationConstraints(doc *policy.Doc, targetAgentID string, args map[string]any) (bool, string, string) {
	if doc == nil || len(doc.DelegationPolicies) == 0 {
		return true, "", ""
	}
	pol, ok := findDelegationPolicy(doc.DelegationPolicies, targetAgentID)
	if !ok {
		return false, reasons.DelegationExceedsAuthority,
			fmt.Sprintf("target agent %q is not declared in delegate policy", targetAgentID)
	}

	declaredScope := strings.TrimSpace(pol.Scope)
	if declaredScope != "" {
		requestedScope := extractDelegationScope(args)
		if requestedScope == "" {
			return false, reasons.DelegationExceedsAuthority,
				fmt.Sprintf("invoke_agent target %q requires delegation_scope to match declared delegate scope", targetAgentID)
		}
		if !delegationScopeAllowed(declaredScope, requestedScope) {
			return false, reasons.DelegationExceedsAuthority,
				fmt.Sprintf("requested delegation_scope %q exceeds declared scope %q", requestedScope, declaredScope)
		}
	}

	declaredTTL := strings.TrimSpace(pol.TTL)
	if declaredTTL != "" {
		maxTTL, err := time.ParseDuration(declaredTTL)
		if err == nil && maxTTL > 0 {
			requestedTTL, ok := extractDelegationTTL(args)
			if !ok {
				return false, reasons.DelegationExceedsAuthority,
					fmt.Sprintf("invoke_agent target %q requires delegation_ttl to respect declared ttl %q", targetAgentID, declaredTTL)
			}
			if requestedTTL > maxTTL {
				return false, reasons.DelegationExceedsAuthority,
					fmt.Sprintf("requested delegation_ttl %s exceeds declared ttl %s", requestedTTL, maxTTL)
			}
		}
	}

	return true, "", ""
}

func findDelegationPolicy(policies []policy.DelegationPolicy, targetAgentID string) (policy.DelegationPolicy, bool) {
	target := strings.TrimSpace(targetAgentID)
	for _, p := range policies {
		if strings.TrimSpace(p.TargetAgent) == target {
			return p, true
		}
	}
	return policy.DelegationPolicy{}, false
}

func extractDelegationScope(args map[string]any) string {
	return extractNestedString(args, "delegation_scope", "scope")
}

func extractDelegationTTL(args map[string]any) (time.Duration, bool) {
	if args == nil {
		return 0, false
	}
	if ttl, ok := parseDelegationTTLValue(args["delegation_ttl"]); ok {
		return ttl, true
	}
	if ttl, ok := parseDelegationTTLValue(args["ttl"]); ok {
		return ttl, true
	}
	if m, ok := args["params"].(map[string]any); ok {
		if ttl, ok := parseDelegationTTLValue(m["delegation_ttl"]); ok {
			return ttl, true
		}
		if ttl, ok := parseDelegationTTLValue(m["ttl"]); ok {
			return ttl, true
		}
	}
	if m, ok := args["input"].(map[string]any); ok {
		if ttl, ok := parseDelegationTTLValue(m["delegation_ttl"]); ok {
			return ttl, true
		}
		if ttl, ok := parseDelegationTTLValue(m["ttl"]); ok {
			return ttl, true
		}
	}
	if m, ok := args["arguments"].(map[string]any); ok {
		if ttl, ok := parseDelegationTTLValue(m["delegation_ttl"]); ok {
			return ttl, true
		}
		if ttl, ok := parseDelegationTTLValue(m["ttl"]); ok {
			return ttl, true
		}
	}
	return 0, false
}

func extractNestedString(args map[string]any, keys ...string) string {
	if args == nil {
		return ""
	}
	for _, key := range keys {
		if s, ok := args[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	for _, nestedKey := range []string{"params", "input", "arguments"} {
		if nested, ok := args[nestedKey].(map[string]any); ok {
			for _, key := range keys {
				if s, ok := nested[key].(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

func parseDelegationTTLValue(v any) (time.Duration, bool) {
	switch tv := v.(type) {
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(tv))
		if err != nil || d <= 0 {
			return 0, false
		}
		return d, true
	case int:
		if tv <= 0 {
			return 0, false
		}
		return time.Duration(tv) * time.Second, true
	case int64:
		if tv <= 0 {
			return 0, false
		}
		return time.Duration(tv) * time.Second, true
	case float64:
		if tv <= 0 {
			return 0, false
		}
		return time.Duration(tv * float64(time.Second)), true
	default:
		return 0, false
	}
}

func delegationScopeAllowed(declared, requested string) bool {
	declaredTool, declaredConstraint := splitDelegationScope(declared)
	requestedTool, requestedConstraint := splitDelegationScope(requested)
	if declaredTool == "" || requestedTool == "" {
		return false
	}
	if !matchToolPattern(declaredTool, requestedTool) {
		return false
	}
	if declaredConstraint == "" {
		return true
	}
	return strings.TrimSpace(declared) == strings.TrimSpace(requested) && requestedConstraint != ""
}

func splitDelegationScope(scope string) (string, string) {
	v := strings.TrimSpace(scope)
	if v == "" {
		return "", ""
	}
	if idx := strings.Index(v, ":"); idx >= 0 {
		return strings.TrimSpace(v[:idx]), strings.TrimSpace(v[idx+1:])
	}
	return v, ""
}
