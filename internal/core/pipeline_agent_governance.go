package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/governstate"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/redact"
)

func (p *Pipeline) agentSpec(agentID string) (agentgov.Spec, bool) {
	if p == nil || len(p.agentGovernance) == 0 {
		return agentgov.Spec{}, false
	}
	spec, ok := p.agentGovernance[agentID]
	return spec, ok
}

func (p *Pipeline) applyAgentRedaction(req *CanonicalActionRequest) error {
	if len(p.hmacKey) == 0 {
		return nil
	}
	spec, ok := p.agentSpec(req.AgentID)
	if !ok || len(spec.Redactions) == 0 {
		return nil
	}
	eng := redact.NewEngine(p.hmacKey, spec.Redactions)
	if eng == nil {
		return nil
	}
	out, err := eng.Apply(req.ToolID, req.Args)
	if err != nil {
		return err
	}
	req.Args = out
	return nil
}

func (p *Pipeline) checkAgentRateLimit(req CanonicalActionRequest) (bool, string, string) {
	if p.governState == nil {
		return false, "", ""
	}
	spec, ok := p.agentSpec(req.AgentID)
	if !ok || len(spec.RateLimits) == 0 {
		return false, "", ""
	}
	exceeded, rule := p.governState.CheckRate(req.AgentID, req.ToolID, spec.RateLimits, req.Timestamp)
	if !exceeded {
		return false, "", ""
	}
	return true, reasons.RateExceeded, governstate.FormatRateExceeded(rule)
}

func (p *Pipeline) checkBudgetWarnAt(agentID string, budget *policy.Budget, sessCost, dailyCost float64) (bool, string, string) {
	if budget == nil || p.governState == nil {
		return false, "", ""
	}
	spec, ok := p.agentSpec(agentID)
	if !ok {
		return false, "", ""
	}
	for _, w := range spec.BudgetWarn {
		if !budgetScopeMatches(w.Scope, budget) {
			continue
		}
		if w.WarnAt <= 0 || w.WarnAt >= 1 {
			continue
		}
		var spent, ceiling float64
		switch strings.ToLower(strings.TrimSpace(w.Scope)) {
		case "daily":
			spent, ceiling = dailyCost, budget.DailyUSD
		case "session", "":
			spent, ceiling = sessCost, budget.SessionUSD
		default:
			continue
		}
		if ceiling <= 0 {
			continue
		}
		if spent/ceiling >= w.WarnAt {
			return true, reasons.BudgetWarning,
				fmt.Sprintf("budget %.0f%% consumed ($%.4f/$%.4f %s), approval required to continue",
					w.WarnAt*100, spent, ceiling, w.Scope)
		}
	}
	return false, "", ""
}

func budgetScopeMatches(scope string, budget *policy.Budget) bool {
	scope = strings.ToLower(strings.TrimSpace(scope))
	switch scope {
	case "daily":
		return budget.DailyUSD > 0
	case "session", "":
		return budget.SessionUSD > 0
	default:
		return false
	}
}

func (p *Pipeline) persistAgentGovernance(req CanonicalActionRequest, d Decision, toolCostUSD float64) {
	if p.governState == nil {
		return
	}
	wal, ok := p.wal.(*dpr.WAL)
	if !ok {
		return
	}
	spec, ok := p.agentSpec(req.AgentID)
	if !ok {
		return
	}
	now := req.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if d.Effect == EffectPermit || d.Effect == EffectShadow || d.Effect == EffectShadowPermit {
		for _, rule := range spec.RateLimits {
			if !rateRuleMatchesTool(rule, req.ToolID) {
				continue
			}
			count := p.governState.RecordRate(req.AgentID, rule, now)
			_ = wal.WriteControl(governstate.RateControlFrame(req.AgentID, rule, count))
		}
		if toolCostUSD > 0 {
			art := p.currentArtifacts()
			if art.engine == nil {
				return
			}
			doc := art.engine.Doc()
			if doc != nil && doc.Budget != nil {
				sess := p.sessions.Get(req.AgentID)
				if doc.Budget.SessionUSD > 0 {
					spent := sess.CurrentCostUSD()
					_ = wal.WriteControl(governstate.BudgetControlFrame(req.AgentID, "session", spent, doc.Budget.SessionUSD))
					p.governState.SetBudget(req.AgentID, "session", spent, doc.Budget.SessionUSD)
				}
				if doc.Budget.DailyUSD > 0 {
					spent := sess.DailyCostUSD()
					_ = wal.WriteControl(governstate.BudgetControlFrame(req.AgentID, "daily", spent, doc.Budget.DailyUSD))
					p.governState.SetBudget(req.AgentID, "daily", spent, doc.Budget.DailyUSD)
				}
			}
		}
	}
}

func rateRuleMatchesTool(rule agentgov.RateLimit, toolID string) bool {
	return governstate.ToolMatches(rule.Tool, toolID)
}
