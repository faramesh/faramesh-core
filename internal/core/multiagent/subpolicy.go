// Package multiagent — invocation-scoped sub-policy.
//
// When an orchestrator invokes a sub-agent, it can pass an invocation-scoped
// policy that intersects with the sub-agent's base policy. The most
// restrictive of (base ∩ invocation) wins for every tool/action.
package multiagent

import (
	"strings"
	"sync"
)

// SubPolicy represents an invocation-scoped policy overlay.
type SubPolicy struct {
	InvocationID     string   `json:"invocation_id"`
	AllowedTools     []string `json:"allowed_tools"`     // glob patterns, intersected with base
	BlockedTools     []string `json:"blocked_tools"`     // additional blocks
	MaxCostUSD       float64  `json:"max_cost_usd"`
	MaxCalls         int      `json:"max_calls"`
	AllowDeferEscalation bool `json:"allow_defer_escalation"`
}

// SubPolicyManager manages invocation-scoped sub-policies.
type SubPolicyManager struct {
	mu       sync.Mutex
	policies map[string]*SubPolicy // invocationID → sub-policy
}

// NewSubPolicyManager creates a sub-policy manager.
func NewSubPolicyManager() *SubPolicyManager {
	return &SubPolicyManager{
		policies: make(map[string]*SubPolicy),
	}
}

// AttachPolicy attaches an invocation-scoped sub-policy.
func (spm *SubPolicyManager) AttachPolicy(policy SubPolicy) {
	spm.mu.Lock()
	defer spm.mu.Unlock()
	spm.policies[policy.InvocationID] = &policy
}

// GetPolicy returns the sub-policy for an invocation.
func (spm *SubPolicyManager) GetPolicy(invocationID string) (SubPolicy, bool) {
	spm.mu.Lock()
	defer spm.mu.Unlock()
	p, ok := spm.policies[invocationID]
	if !ok {
		return SubPolicy{}, false
	}
	return *p, true
}

// IsToolAllowed checks if a tool is allowed under the intersection of
// base policy and invocation sub-policy (most restrictive wins).
func (spm *SubPolicyManager) IsToolAllowed(invocationID, toolID string, baseAllowed bool) bool {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	policy, ok := spm.policies[invocationID]
	if !ok {
		return baseAllowed // no sub-policy, use base
	}

	// If base denies, sub-policy can't permit.
	if !baseAllowed {
		return false
	}

	// Check blocked tools (sub-policy can add additional blocks).
	for _, pattern := range policy.BlockedTools {
		if subPolicyGlobMatch(pattern, toolID) {
			return false
		}
	}

	// If sub-policy declares allowed tools, tool must match.
	if len(policy.AllowedTools) > 0 {
		matched := false
		for _, pattern := range policy.AllowedTools {
			if subPolicyGlobMatch(pattern, toolID) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// IntersectDecision applies the most restrictive of base and sub-policy.
// Returns (allowed, reason).
func (spm *SubPolicyManager) IntersectDecision(invocationID string, baseCostUSD, subCostSoFar float64, callsSoFar int) (bool, string) {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	policy, ok := spm.policies[invocationID]
	if !ok {
		return true, ""
	}

	if policy.MaxCostUSD > 0 && subCostSoFar+baseCostUSD > policy.MaxCostUSD {
		return false, "SUB_POLICY_COST_EXCEEDED"
	}

	if policy.MaxCalls > 0 && callsSoFar >= policy.MaxCalls {
		return false, "SUB_POLICY_MAX_CALLS_EXCEEDED"
	}

	return true, ""
}

// RemovePolicy removes a sub-policy when the invocation completes.
func (spm *SubPolicyManager) RemovePolicy(invocationID string) {
	spm.mu.Lock()
	defer spm.mu.Unlock()
	delete(spm.policies, invocationID)
}

// subPolicyGlobMatch is a simple glob matcher for tool patterns.
func subPolicyGlobMatch(pattern, toolID string) bool {
	if pattern == "*" || pattern == toolID {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(toolID, prefix+"/")
	}
	if strings.HasPrefix(pattern, "*/") {
		suffix := strings.TrimPrefix(pattern, "*/")
		return strings.HasSuffix(toolID, "/"+suffix) || toolID == suffix
	}
	return false
}
