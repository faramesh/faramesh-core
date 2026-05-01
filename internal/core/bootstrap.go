// Package core — bootstrapping enforcement.
//
// Enforces require_governance_before_network mode: if an agent makes any
// network-reaching tool call before calling govern(), the call is denied.
// This prevents governance bypass by racing past the governance check.
package core

import (
	"sync"
	"time"
)

// NetworkReachingTools is the default set of tools that reach the network.
var NetworkReachingTools = map[string]bool{
	"http/request": true,
	"api/call":     true,
	"api/post":     true,
	"api/get":      true,
	"email/send":   true,
	"webhook/call": true,
	"net/connect":  true,
	"db/query":     true,
	"db/write":     true,
	"upload":       true,
	"shell/exec":   true,
}

// BootstrapState tracks whether an agent has been governed before network access.
type BootstrapState struct {
	AgentID       string    `json:"agent_id"`
	Governed      bool      `json:"governed"` // has govern() been called?
	FirstGoverned time.Time `json:"first_governed"`
	Violations    int       `json:"violations"` // pre-governance network attempts
}

// BootstrapEnforcer enforces governance-before-network policy.
type BootstrapEnforcer struct {
	mu           sync.Mutex
	agents       map[string]*BootstrapState
	networkTools map[string]bool
	enforceMode  bool // false = log-only, true = deny
}

// NewBootstrapEnforcer creates a bootstrap enforcer.
func NewBootstrapEnforcer(enforce bool) *BootstrapEnforcer {
	return &BootstrapEnforcer{
		agents:       make(map[string]*BootstrapState),
		networkTools: NetworkReachingTools,
		enforceMode:  enforce,
	}
}

// SetNetworkTools overrides the default network-reaching tool set.
func (be *BootstrapEnforcer) SetNetworkTools(tools []string) {
	be.mu.Lock()
	defer be.mu.Unlock()
	be.networkTools = make(map[string]bool, len(tools))
	for _, t := range tools {
		be.networkTools[t] = true
	}
}

// MarkGoverned records that govern() has been called for this agent.
func (be *BootstrapEnforcer) MarkGoverned(agentID string) {
	be.mu.Lock()
	defer be.mu.Unlock()
	state := be.getOrCreate(agentID)
	if !state.Governed {
		state.Governed = true
		state.FirstGoverned = time.Now()
	}
}

// CheckBootstrap verifies that governance was called before allowing
// a potentially network-reaching tool call.
// Returns (allowed, reason).
func (be *BootstrapEnforcer) CheckBootstrap(agentID, toolID string) (bool, string) {
	be.mu.Lock()
	defer be.mu.Unlock()

	if !be.networkTools[toolID] {
		return true, "" // not a network tool
	}

	state := be.getOrCreate(agentID)
	if state.Governed {
		return true, ""
	}

	state.Violations++
	if be.enforceMode {
		return false, "BOOTSTRAP_VIOLATION: govern() must be called before network-reaching tools"
	}
	// Log-only mode: allow but flag.
	return true, "BOOTSTRAP_WARNING: govern() was not called before network-reaching tool"
}

// AgentState returns the bootstrap state for an agent.
func (be *BootstrapEnforcer) AgentState(agentID string) BootstrapState {
	be.mu.Lock()
	defer be.mu.Unlock()
	state := be.getOrCreate(agentID)
	return *state
}

// ViolationCount returns total bootstrap violations.
func (be *BootstrapEnforcer) ViolationCount() int {
	be.mu.Lock()
	defer be.mu.Unlock()
	total := 0
	for _, state := range be.agents {
		total += state.Violations
	}
	return total
}

func (be *BootstrapEnforcer) getOrCreate(agentID string) *BootstrapState {
	state, ok := be.agents[agentID]
	if !ok {
		state = &BootstrapState{AgentID: agentID}
		be.agents[agentID] = state
	}
	return state
}
