// Package multiagent — orchestrator routing governance.
//
// invoke_agent is a governed tool: the orchestrator must declare a routing
// manifest listing all permitted sub-agent invocations. Undeclared
// invocations are denied. Per-agent invocation counts and approval
// requirements are enforced.
package multiagent

import (
	"fmt"
	"sync"
)

// RoutingManifest declares which agents an orchestrator may invoke.
type RoutingManifest struct {
	OrchestratorID   string         `json:"orchestrator_id"`
	Entries          []RoutingEntry `json:"entries"`
	UndeclaredPolicy string         `json:"undeclared_policy"` // "deny" (default) or "defer"
}

// RoutingEntry declares a permitted sub-agent invocation.
type RoutingEntry struct {
	AgentID                  string `json:"agent_id"`
	MaxInvocationsPerSession int    `json:"max_invocations_per_session"`
	RequiresPriorApproval    bool   `json:"requires_prior_approval"`
}

// InvocationRecord tracks a single agent invocation.
type InvocationRecord struct {
	OrchestratorID string `json:"orchestrator_id"`
	TargetAgentID  string `json:"target_agent_id"`
	SessionID      string `json:"session_id"`
	Approved       bool   `json:"approved"`
	DPRID          string `json:"dpr_id"`
}

// RoutingGovernor enforces routing manifests for orchestrator agents.
type RoutingGovernor struct {
	mu        sync.Mutex
	manifests map[string]*RoutingManifest // orchestratorID → manifest
	counts    map[string]map[string]int   // orchestratorID:sessionID → agentID → count
}

// NewRoutingGovernor creates a routing governor.
func NewRoutingGovernor() *RoutingGovernor {
	return &RoutingGovernor{
		manifests: make(map[string]*RoutingManifest),
		counts:    make(map[string]map[string]int),
	}
}

// RegisterManifest registers a routing manifest for an orchestrator.
func (rg *RoutingGovernor) RegisterManifest(manifest RoutingManifest) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.manifests[manifest.OrchestratorID] = &manifest
}

// ReplaceManifests replaces all registered manifests (e.g. hot policy reload).
// Session invocation counters are preserved so per-session caps remain consistent.
func (rg *RoutingGovernor) ReplaceManifests(manifests []RoutingManifest) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	rg.manifests = make(map[string]*RoutingManifest, len(manifests))
	for i := range manifests {
		m := manifests[i]
		rg.manifests[m.OrchestratorID] = &m
	}
}

// HasManifest reports whether an orchestrator has a declared topology manifest.
func (rg *RoutingGovernor) HasManifest(orchestratorID string) bool {
	if rg == nil {
		return false
	}
	rg.mu.Lock()
	defer rg.mu.Unlock()
	_, ok := rg.manifests[orchestratorID]
	return ok
}

// CheckInvocation checks whether an orchestrator can invoke a target agent.
// Returns (allowed, requiresApproval, reason).
func (rg *RoutingGovernor) CheckInvocation(orchestratorID, targetAgentID, sessionID string) (bool, bool, string) {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	manifest, ok := rg.manifests[orchestratorID]
	if !ok {
		return false, false, "NO_ROUTING_MANIFEST: orchestrator has no declared routing manifest"
	}

	// Find the routing entry for this target.
	var entry *RoutingEntry
	for i := range manifest.Entries {
		if manifest.Entries[i].AgentID == targetAgentID {
			entry = &manifest.Entries[i]
			break
		}
	}

	if entry == nil {
		policy := manifest.UndeclaredPolicy
		if policy == "" {
			policy = "deny"
		}
		if policy == "deny" {
			return false, false, fmt.Sprintf("UNDECLARED_INVOCATION: %s is not declared in %s's routing manifest",
				targetAgentID, orchestratorID)
		}
		// "defer" — needs approval
		return true, true, "UNDECLARED_INVOCATION_DEFERRED"
	}

	// Check invocation count.
	key := orchestratorID + ":" + sessionID
	if entry.MaxInvocationsPerSession > 0 {
		agentCounts := rg.counts[key]
		if agentCounts != nil && agentCounts[targetAgentID] >= entry.MaxInvocationsPerSession {
			return false, false, fmt.Sprintf("MAX_INVOCATIONS_EXCEEDED: %s invoked %d times (max %d)",
				targetAgentID, agentCounts[targetAgentID], entry.MaxInvocationsPerSession)
		}
	}

	return true, entry.RequiresPriorApproval, ""
}

// RecordInvocation records that an invocation occurred.
func (rg *RoutingGovernor) RecordInvocation(orchestratorID, targetAgentID, sessionID string) {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	key := orchestratorID + ":" + sessionID
	if rg.counts[key] == nil {
		rg.counts[key] = make(map[string]int)
	}
	rg.counts[key][targetAgentID]++
}

// InvocationCount returns the number of times an agent was invoked.
func (rg *RoutingGovernor) InvocationCount(orchestratorID, targetAgentID, sessionID string) int {
	rg.mu.Lock()
	defer rg.mu.Unlock()
	key := orchestratorID + ":" + sessionID
	if rg.counts[key] == nil {
		return 0
	}
	return rg.counts[key][targetAgentID]
}
