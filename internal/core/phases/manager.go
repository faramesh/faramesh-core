// Package phases implements workflow phase management for agent sessions.
//
// Phases define temporal scopes that control which tools are available at
// each stage of an agent's workflow. For example:
//   - "init" phase: only configuration tools available
//   - "analysis" phase: read-only tools + internal APIs
//   - "action" phase: all tools including mutations
//   - "cleanup" phase: only reversible tools
//
// Phase transitions are governed by policy rules and recorded in DPR.
// Using a tool outside its phase window results in OUT_OF_PHASE_TOOL_CALL
// reason code and a DENY.
package phases

import (
	"fmt"
	"sync"
	"time"
)

// Phase defines a workflow phase with its allowed tools.
type Phase struct {
	// ID is the phase identifier (e.g., "init", "analysis", "action").
	ID string `json:"id" yaml:"id"`

	// Name is the human-readable phase name.
	Name string `json:"name" yaml:"name"`

	// AllowedTools are glob patterns for tools permitted in this phase.
	AllowedTools []string `json:"allowed_tools" yaml:"allowed_tools"`

	// BlockedTools are glob patterns for tools explicitly blocked in this phase.
	// Blocked takes precedence over allowed.
	BlockedTools []string `json:"blocked_tools,omitempty" yaml:"blocked_tools"`

	// MaxDuration limits how long an agent can stay in this phase.
	// 0 means unlimited.
	MaxDuration time.Duration `json:"max_duration,omitempty" yaml:"max_duration"`

	// AllowedTransitions lists phase IDs that can be transitioned to from here.
	AllowedTransitions []string `json:"allowed_transitions" yaml:"allowed_transitions"`
}

// PhaseTransitionRecord records a phase transition for DPR.
type PhaseTransitionRecord struct {
	FromPhase    string    `json:"from_phase"`
	ToPhase      string    `json:"to_phase"`
	TransitionAt time.Time `json:"transition_at"`
	Reason       string    `json:"reason"`
	DurationInFrom time.Duration `json:"duration_in_from"`
}

// PhaseManager tracks the current phase for an agent session and
// enforces tool availability windows.
type PhaseManager struct {
	mu          sync.RWMutex
	phases      map[string]*Phase
	order       []string // ordered phase IDs for display
	current     map[string]*agentPhaseState // agentID → state
}

type agentPhaseState struct {
	phaseID   string
	enteredAt time.Time
	history   []PhaseTransitionRecord
}

// NewPhaseManager creates a new phase manager with the given phase definitions.
func NewPhaseManager(phases []Phase) *PhaseManager {
	pm := &PhaseManager{
		phases:  make(map[string]*Phase),
		current: make(map[string]*agentPhaseState),
	}
	for i := range phases {
		p := &phases[i]
		pm.phases[p.ID] = p
		pm.order = append(pm.order, p.ID)
	}
	return pm
}

// SetPhase sets the initial phase for an agent.
func (pm *PhaseManager) SetPhase(agentID, phaseID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if _, ok := pm.phases[phaseID]; !ok {
		return fmt.Errorf("unknown phase: %s", phaseID)
	}
	pm.current[agentID] = &agentPhaseState{
		phaseID:   phaseID,
		enteredAt: time.Now(),
	}
	return nil
}

// Transition moves an agent to a new phase.
// Returns a transition record for DPR, or an error if the transition is not allowed.
func (pm *PhaseManager) Transition(agentID, toPhaseID, reason string) (*PhaseTransitionRecord, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	state, ok := pm.current[agentID]
	if !ok {
		return nil, fmt.Errorf("agent %s has no active phase", agentID)
	}

	fromPhase, ok := pm.phases[state.phaseID]
	if !ok {
		return nil, fmt.Errorf("current phase %s not found", state.phaseID)
	}

	// Check if transition is allowed.
	allowed := false
	for _, t := range fromPhase.AllowedTransitions {
		if t == toPhaseID || t == "*" {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("transition from %s to %s not permitted", state.phaseID, toPhaseID)
	}

	if _, ok := pm.phases[toPhaseID]; !ok {
		return nil, fmt.Errorf("unknown target phase: %s", toPhaseID)
	}

	now := time.Now()
	record := &PhaseTransitionRecord{
		FromPhase:      state.phaseID,
		ToPhase:        toPhaseID,
		TransitionAt:   now,
		Reason:         reason,
		DurationInFrom: now.Sub(state.enteredAt),
	}

	state.history = append(state.history, *record)
	state.phaseID = toPhaseID
	state.enteredAt = now

	return record, nil
}

// CurrentPhase returns the current phase ID for an agent.
func (pm *PhaseManager) CurrentPhase(agentID string) string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if state, ok := pm.current[agentID]; ok {
		return state.phaseID
	}
	return ""
}

// IsToolAllowed checks if a tool is permitted in the agent's current phase.
func (pm *PhaseManager) IsToolAllowed(agentID, toolID string) (bool, string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	state, ok := pm.current[agentID]
	if !ok {
		return true, "" // no phase tracking = no restrictions
	}

	phase, ok := pm.phases[state.phaseID]
	if !ok {
		return true, ""
	}

	// Check blocked first (takes precedence).
	for _, pattern := range phase.BlockedTools {
		if matchToolGlob(pattern, toolID) {
			return false, fmt.Sprintf("tool %s is blocked in phase %s", toolID, phase.ID)
		}
	}

	// Check allowed.
	if len(phase.AllowedTools) == 0 {
		return true, "" // no allowed list = all tools allowed
	}
	for _, pattern := range phase.AllowedTools {
		if matchToolGlob(pattern, toolID) {
			return true, ""
		}
	}

	return false, fmt.Sprintf("tool %s not in allowed list for phase %s", toolID, phase.ID)
}

// IsToolAllowedInPhase is a compatibility alias used by pipeline integration.
// It delegates to IsToolAllowed and preserves identical semantics.
func (pm *PhaseManager) IsToolAllowedInPhase(agentID, toolID string) (bool, string) {
	return pm.IsToolAllowed(agentID, toolID)
}

// CheckMaxDuration checks if the agent has exceeded the phase's max duration.
func (pm *PhaseManager) CheckMaxDuration(agentID string) (bool, time.Duration) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	state, ok := pm.current[agentID]
	if !ok {
		return false, 0
	}
	phase, ok := pm.phases[state.phaseID]
	if !ok || phase.MaxDuration == 0 {
		return false, 0
	}

	elapsed := time.Since(state.enteredAt)
	if elapsed > phase.MaxDuration {
		return true, elapsed - phase.MaxDuration
	}
	return false, 0
}

// TransitionHistory returns the phase transition history for an agent.
func (pm *PhaseManager) TransitionHistory(agentID string) []PhaseTransitionRecord {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if state, ok := pm.current[agentID]; ok {
		result := make([]PhaseTransitionRecord, len(state.history))
		copy(result, state.history)
		return result
	}
	return nil
}

// Phases returns all defined phases in order.
func (pm *PhaseManager) Phases() []Phase {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	result := make([]Phase, 0, len(pm.order))
	for _, id := range pm.order {
		if p, ok := pm.phases[id]; ok {
			result = append(result, *p)
		}
	}
	return result
}

func matchToolGlob(pattern, toolID string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	n := len(pattern)
	if n > 0 && pattern[n-1] == '*' {
		prefix := pattern[:n-1]
		return len(toolID) >= len(prefix) && toolID[:len(prefix)] == prefix
	}
	return pattern == toolID
}
