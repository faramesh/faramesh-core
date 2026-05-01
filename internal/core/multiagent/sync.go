// Package multiagent — synchronization gate.
//
// In fan-out scenarios, a sync gate governs when parallel agents' results
// can be collected. Policies define required completion states, minimum
// completion fractions, and timeout behavior.
package multiagent

import (
	"fmt"
	"sync"
	"time"
)

// AgentState represents an agent's completion status.
type AgentState int

const (
	StateRunning AgentState = iota
	StateCompleted
	StateFailed
	StateCancelled
	StateTimedOut
)

func (s AgentState) String() string {
	switch s {
	case StateRunning:
		return "running"
	case StateCompleted:
		return "completed"
	case StateFailed:
		return "failed"
	case StateCancelled:
		return "cancelled"
	case StateTimedOut:
		return "timed_out"
	default:
		return "unknown"
	}
}

// SyncPolicy defines the completion requirements for a sync gate.
type SyncPolicy struct {
	RequiredAgents        []string      `json:"required_agents"`     // must complete
	MinCompletionFrac     float64       `json:"min_completion_frac"` // e.g. 0.75 = 75%
	Timeout               time.Duration `json:"timeout"`
	OnTimeout             string        `json:"on_timeout"`               // "proceed" or "deny"
	CountFailedAsComplete bool          `json:"count_failed_as_complete"` // include failed in fraction
}

// SyncGate tracks parallel agent completion and enforces sync policies.
type SyncGate struct {
	mu       sync.Mutex
	gateID   string
	policy   SyncPolicy
	agents   map[string]AgentState
	started  time.Time
	released bool
	waitCh   chan struct{}
}

// NewSyncGate creates a synchronization gate.
func NewSyncGate(gateID string, policy SyncPolicy, agentIDs []string) *SyncGate {
	agents := make(map[string]AgentState, len(agentIDs))
	for _, id := range agentIDs {
		agents[id] = StateRunning
	}
	return &SyncGate{
		gateID:  gateID,
		policy:  policy,
		agents:  agents,
		started: time.Now(),
		waitCh:  make(chan struct{}),
	}
}

// UpdateState updates an agent's completion state and checks if the gate can release.
func (sg *SyncGate) UpdateState(agentID string, state AgentState) (bool, error) {
	sg.mu.Lock()
	defer sg.mu.Unlock()

	if _, ok := sg.agents[agentID]; !ok {
		return false, fmt.Errorf("agent %s not registered in gate %s", agentID, sg.gateID)
	}
	sg.agents[agentID] = state

	if sg.checkRelease() {
		sg.released = true
		close(sg.waitCh)
		return true, nil
	}
	return false, nil
}

// Wait blocks until the gate releases or times out.
func (sg *SyncGate) Wait() (SyncResult, error) {
	if sg.policy.Timeout > 0 {
		timer := time.NewTimer(sg.policy.Timeout)
		defer timer.Stop()
		select {
		case <-sg.waitCh:
			return sg.result(), nil
		case <-timer.C:
			sg.mu.Lock()
			defer sg.mu.Unlock()
			// Mark running agents as timed out.
			for id, state := range sg.agents {
				if state == StateRunning {
					sg.agents[id] = StateTimedOut
				}
			}
			if sg.policy.OnTimeout == "proceed" {
				sg.released = true
				return sg.resultLocked(), nil
			}
			return sg.resultLocked(), fmt.Errorf("SYNC_GATE_TIMEOUT: gate %s timed out after %v", sg.gateID, sg.policy.Timeout)
		}
	}
	<-sg.waitCh
	return sg.result(), nil
}

// Status returns the current gate status.
func (sg *SyncGate) Status() SyncResult {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	return sg.resultLocked()
}

func (sg *SyncGate) checkRelease() bool {
	if sg.released {
		return false
	}

	total := len(sg.agents)
	completed := 0
	for _, state := range sg.agents {
		if state == StateCompleted {
			completed++
		} else if sg.policy.CountFailedAsComplete && state == StateFailed {
			completed++
		}
	}

	// Check required agents.
	for _, reqID := range sg.policy.RequiredAgents {
		state, ok := sg.agents[reqID]
		if !ok {
			return false
		}
		if state != StateCompleted {
			return false
		}
	}

	// Check minimum completion fraction.
	if sg.policy.MinCompletionFrac > 0 {
		frac := float64(completed) / float64(total)
		if frac < sg.policy.MinCompletionFrac {
			return false
		}
	}

	// If no specific policy, require all completed.
	if len(sg.policy.RequiredAgents) == 0 && sg.policy.MinCompletionFrac == 0 {
		return completed == total
	}

	return true
}

func (sg *SyncGate) result() SyncResult {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	return sg.resultLocked()
}

func (sg *SyncGate) resultLocked() SyncResult {
	agents := make(map[string]string, len(sg.agents))
	completed := 0
	for id, state := range sg.agents {
		agents[id] = state.String()
		if state == StateCompleted {
			completed++
		}
	}
	return SyncResult{
		GateID:         sg.gateID,
		Released:       sg.released,
		AgentStates:    agents,
		CompletedCount: completed,
		TotalCount:     len(sg.agents),
		Elapsed:        time.Since(sg.started),
	}
}

// SyncResult is a snapshot of the gate state.
type SyncResult struct {
	GateID         string            `json:"gate_id"`
	Released       bool              `json:"released"`
	AgentStates    map[string]string `json:"agent_states"`
	CompletedCount int               `json:"completed_count"`
	TotalCount     int               `json:"total_count"`
	Elapsed        time.Duration     `json:"elapsed"`
}
