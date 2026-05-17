package core

import (
	"fmt"
	"strings"
	"sync"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// SetStackTenantID scopes audit paths for multi-tenant deployments.
func (p *Pipeline) SetStackTenantID(tenant string) {
	if p == nil {
		return
	}
	p.stackTenantID = strings.TrimSpace(tenant)
}

// SetGovernToolResponses enables tool_response CAR evaluation.
func (p *Pipeline) SetGovernToolResponses(enabled bool) {
	if p == nil {
		return
	}
	p.governToolResponses = enabled
}

// SetBudgetPools configures shared budget ceilings across agents.
func (p *Pipeline) SetBudgetPools(pools []agentgov.BudgetPool) {
	if p == nil {
		return
	}
	p.budgetPools = append([]agentgov.BudgetPool(nil), pools...)
	if len(pools) > 0 {
		p.budgetPoolTrack = newBudgetPoolTracker(pools)
	}
}

type budgetPoolTracker struct {
	mu     sync.Mutex
	spent  map[string]float64
	limits map[string]float64
}

func newBudgetPoolTracker(pools []agentgov.BudgetPool) *budgetPoolTracker {
	t := &budgetPoolTracker{
		spent:  make(map[string]float64),
		limits: make(map[string]float64),
	}
	for _, pool := range pools {
		if pool.Name == "" || pool.Max <= 0 {
			continue
		}
		t.limits[pool.Name] = pool.Max
	}
	return t
}

func (p *Pipeline) checkBudgetPool(agentID string, costUSD float64) (bool, string, string) {
	if p == nil || p.budgetPoolTrack == nil || costUSD <= 0 {
		return false, "", ""
	}
	p.budgetPoolTrack.mu.Lock()
	defer p.budgetPoolTrack.mu.Unlock()
	for _, pool := range p.budgetPools {
		if !poolCoversAgent(pool, agentID) {
			continue
		}
		spent := p.budgetPoolTrack.spent[pool.Name] + costUSD
		if spent > pool.Max {
			return true, reasons.AggregateBudgetExceeded,
				fmt.Sprintf("budget pool %q would exceed $%.2f (max $%.2f)", pool.Name, spent, pool.Max)
		}
	}
	return false, "", ""
}

func (p *Pipeline) recordBudgetPoolSpend(agentID string, costUSD float64) {
	if p == nil || p.budgetPoolTrack == nil || costUSD <= 0 {
		return
	}
	p.budgetPoolTrack.mu.Lock()
	defer p.budgetPoolTrack.mu.Unlock()
	for _, pool := range p.budgetPools {
		if poolCoversAgent(pool, agentID) {
			p.budgetPoolTrack.spent[pool.Name] += costUSD
		}
	}
}

func poolCoversAgent(pool agentgov.BudgetPool, agentID string) bool {
	for _, a := range pool.Agents {
		if strings.TrimSpace(a) == strings.TrimSpace(agentID) {
			return true
		}
	}
	return false
}

func (p *Pipeline) rejectToolResponseIfDisabled(req CanonicalActionRequest) (Decision, bool) {
	if p == nil || !p.governToolResponses {
		if NormalizeActionType(req.ActionType) == ActionTypeToolResponse {
			return Decision{
				Effect:     EffectDeny,
				ReasonCode: reasons.RuleDeny,
				Reason:     "tool_response governance is disabled; set runtime { govern_tool_responses = true }",
			}, true
		}
	}
	return Decision{}, false
}
