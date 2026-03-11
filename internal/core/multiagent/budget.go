// Package multiagent — fan-out budget attribution.
//
// In parallel multi-agent scenarios, the aggregate budget must be tracked
// across all concurrent agents. Each agent gets a budget slice within the
// aggregate, and exceeding any individual or aggregate limit triggers
// cost governance (cancel_remaining on exceed).
package multiagent

import (
	"fmt"
	"sync"
)

// AgentBudget represents an individual agent's budget within an aggregate.
type AgentBudget struct {
	AgentID      string  `json:"agent_id"`
	MaxCostUSD   float64 `json:"max_cost_usd"`
	SpentUSD     float64 `json:"spent_usd"`
	ReservedUSD  float64 `json:"reserved_usd"`
	Cancelled    bool    `json:"cancelled"`
}

// Remaining returns the available budget for this agent.
func (ab *AgentBudget) Remaining() float64 {
	return ab.MaxCostUSD - ab.SpentUSD - ab.ReservedUSD
}

// BudgetManager tracks aggregate and per-agent budgets for fan-out scenarios.
type BudgetManager struct {
	mu             sync.Mutex
	sessionID      string
	aggregateMax   float64
	aggregateSpent float64
	agents         map[string]*AgentBudget
	onExceed       func(agentID string, spent, limit float64) // cancel callback
}

// NewBudgetManager creates a budget manager for a fan-out session.
func NewBudgetManager(sessionID string, aggregateMaxUSD float64) *BudgetManager {
	return &BudgetManager{
		sessionID:    sessionID,
		aggregateMax: aggregateMaxUSD,
		agents:       make(map[string]*AgentBudget),
	}
}

// OnExceed registers a callback for budget exceedance.
func (bm *BudgetManager) OnExceed(fn func(agentID string, spent, limit float64)) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.onExceed = fn
}

// AllocateAgent creates a budget slice for an agent within the aggregate.
func (bm *BudgetManager) AllocateAgent(agentID string, maxCostUSD float64) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if _, exists := bm.agents[agentID]; exists {
		return fmt.Errorf("agent %s already has a budget allocation", agentID)
	}

	// Check aggregate capacity.
	totalAllocated := 0.0
	for _, ab := range bm.agents {
		totalAllocated += ab.MaxCostUSD
	}
	if totalAllocated+maxCostUSD > bm.aggregateMax {
		return fmt.Errorf("cannot allocate $%.2f for %s: would exceed aggregate limit $%.2f (already allocated $%.2f)",
			maxCostUSD, agentID, bm.aggregateMax, totalAllocated)
	}

	bm.agents[agentID] = &AgentBudget{
		AgentID:    agentID,
		MaxCostUSD: maxCostUSD,
	}
	return nil
}

// RecordCost records cost for an agent and checks limits.
// Returns whether the agent should be cancelled.
func (bm *BudgetManager) RecordCost(agentID string, costUSD float64) (bool, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	ab, ok := bm.agents[agentID]
	if !ok {
		return false, fmt.Errorf("agent %s has no budget allocation", agentID)
	}
	if ab.Cancelled {
		return true, fmt.Errorf("agent %s is already cancelled", agentID)
	}

	ab.SpentUSD += costUSD
	bm.aggregateSpent += costUSD

	shouldCancel := false

	// Check per-agent limit.
	if ab.SpentUSD > ab.MaxCostUSD {
		shouldCancel = true
	}

	// Check aggregate limit.
	if bm.aggregateSpent > bm.aggregateMax {
		shouldCancel = true
		// Cancel all remaining agents.
		for _, a := range bm.agents {
			if !a.Cancelled {
				a.Cancelled = true
				if bm.onExceed != nil {
					bm.onExceed(a.AgentID, bm.aggregateSpent, bm.aggregateMax)
				}
			}
		}
		return true, nil
	}

	if shouldCancel {
		ab.Cancelled = true
		if bm.onExceed != nil {
			bm.onExceed(agentID, ab.SpentUSD, ab.MaxCostUSD)
		}
	}

	return shouldCancel, nil
}

// Reserve reserves budget for an agent (two-phase cost).
func (bm *BudgetManager) Reserve(agentID string, costUSD float64) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	ab, ok := bm.agents[agentID]
	if !ok {
		return fmt.Errorf("agent %s has no budget allocation", agentID)
	}
	if ab.Cancelled {
		return fmt.Errorf("agent %s is cancelled", agentID)
	}
	if ab.SpentUSD+ab.ReservedUSD+costUSD > ab.MaxCostUSD {
		return fmt.Errorf("reservation $%.2f would exceed agent budget $%.2f", costUSD, ab.MaxCostUSD)
	}
	if bm.aggregateSpent+costUSD > bm.aggregateMax {
		return fmt.Errorf("reservation $%.2f would exceed aggregate budget $%.2f", costUSD, bm.aggregateMax)
	}

	ab.ReservedUSD += costUSD
	return nil
}

// Status returns the current budget status.
func (bm *BudgetManager) Status() BudgetStatus {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	agents := make([]AgentBudget, 0, len(bm.agents))
	for _, ab := range bm.agents {
		agents = append(agents, *ab)
	}
	return BudgetStatus{
		SessionID:      bm.sessionID,
		AggregateMax:   bm.aggregateMax,
		AggregateSpent: bm.aggregateSpent,
		Agents:         agents,
	}
}

// BudgetStatus is a snapshot of the budget state.
type BudgetStatus struct {
	SessionID      string        `json:"session_id"`
	AggregateMax   float64       `json:"aggregate_max_usd"`
	AggregateSpent float64       `json:"aggregate_spent_usd"`
	Agents         []AgentBudget `json:"agents"`
}
