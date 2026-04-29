// Package multiagent — phase completion verification.
//
// Before an agent transitions to the next workflow phase, this verifier
// ensures the prior phase completed all required tool calls (or patterns).
// Ties into the phases.PhaseManager for transitions.
package multiagent

import (
	"fmt"
	"strings"
	"sync"
)

// PhaseRequirement defines what must happen before a phase is considered complete.
type PhaseRequirement struct {
	PhaseID       string   `json:"phase_id"`
	RequiredTools []string `json:"required_tools"` // glob patterns
	MinCalls      int      `json:"min_calls"`      // minimum invocations (default 1)
}

// PhaseCompletionRecord tracks what tools were invoked in a phase.
type PhaseCompletionRecord struct {
	PhaseID     string         `json:"phase_id"`
	ToolCounts  map[string]int `json:"tool_counts"` // toolID → call count
	Complete    bool           `json:"complete"`
	MissingMsg  string         `json:"missing_msg,omitempty"`
}

// PhaseVerifier validates that a phase met its requirements before transition.
type PhaseVerifier struct {
	mu           sync.Mutex
	requirements map[string][]PhaseRequirement // phaseID → requirements
	records      map[string]*PhaseCompletionRecord // agentID:phaseID → record
}

// NewPhaseVerifier creates a phase completion verifier.
func NewPhaseVerifier() *PhaseVerifier {
	return &PhaseVerifier{
		requirements: make(map[string][]PhaseRequirement),
		records:      make(map[string]*PhaseCompletionRecord),
	}
}

// AddRequirement registers a completion requirement for a phase.
func (pv *PhaseVerifier) AddRequirement(req PhaseRequirement) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if req.MinCalls == 0 {
		req.MinCalls = 1
	}
	pv.requirements[req.PhaseID] = append(pv.requirements[req.PhaseID], req)
}

// RecordToolCall records that a tool was invoked in a phase for an agent.
func (pv *PhaseVerifier) RecordToolCall(agentID, phaseID, toolID string) {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	key := agentID + ":" + phaseID
	rec, ok := pv.records[key]
	if !ok {
		rec = &PhaseCompletionRecord{
			PhaseID:    phaseID,
			ToolCounts: make(map[string]int),
		}
		pv.records[key] = rec
	}
	rec.ToolCounts[toolID]++
}

// CanTransition checks whether the agent has completed all requirements for a phase.
func (pv *PhaseVerifier) CanTransition(agentID, fromPhaseID string) (bool, string) {
	pv.mu.Lock()
	defer pv.mu.Unlock()

	reqs, ok := pv.requirements[fromPhaseID]
	if !ok {
		return true, "" // no requirements defined
	}

	key := agentID + ":" + fromPhaseID
	rec := pv.records[key]

	var missing []string
	for _, req := range reqs {
		satisfied := false
		for toolID, count := range rec.toolCountsOrEmpty() {
			if matchGlob(req.RequiredTools, toolID) && count >= req.MinCalls {
				satisfied = true
				break
			}
		}
		if !satisfied {
			missing = append(missing, fmt.Sprintf("phase %s requires %v (min %d calls)",
				fromPhaseID, req.RequiredTools, req.MinCalls))
		}
	}

	if len(missing) > 0 {
		return false, strings.Join(missing, "; ")
	}
	return true, ""
}

// CompletionStatus returns the completion record for an agent's phase.
func (pv *PhaseVerifier) CompletionStatus(agentID, phaseID string) PhaseCompletionRecord {
	pv.mu.Lock()
	defer pv.mu.Unlock()
	key := agentID + ":" + phaseID
	rec, ok := pv.records[key]
	if !ok {
		return PhaseCompletionRecord{PhaseID: phaseID}
	}
	cp := *rec
	can, msg := pv.canTransitionLocked(agentID, phaseID)
	cp.Complete = can
	cp.MissingMsg = msg
	return cp
}

func (pv *PhaseVerifier) canTransitionLocked(agentID, phaseID string) (bool, string) {
	reqs, ok := pv.requirements[phaseID]
	if !ok {
		return true, ""
	}
	key := agentID + ":" + phaseID
	rec := pv.records[key]
	var missing []string
	for _, req := range reqs {
		satisfied := false
		for toolID, count := range rec.toolCountsOrEmpty() {
			if matchGlob(req.RequiredTools, toolID) && count >= req.MinCalls {
				satisfied = true
				break
			}
		}
		if !satisfied {
			missing = append(missing, fmt.Sprintf("%v (min %d)", req.RequiredTools, req.MinCalls))
		}
	}
	if len(missing) > 0 {
		return false, strings.Join(missing, "; ")
	}
	return true, ""
}

func (r *PhaseCompletionRecord) toolCountsOrEmpty() map[string]int {
	if r == nil || r.ToolCounts == nil {
		return map[string]int{}
	}
	return r.ToolCounts
}

// matchGlob checks if toolID matches any of the glob patterns.
func matchGlob(patterns []string, toolID string) bool {
	for _, p := range patterns {
		if matchToolGlobLocal(p, toolID) {
			return true
		}
	}
	return false
}

// matchToolGlobLocal is a simple glob matcher for tool patterns.
func matchToolGlobLocal(pattern, toolID string) bool {
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
