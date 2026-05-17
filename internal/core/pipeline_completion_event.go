package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func (p *Pipeline) checkCompletionGateForEvent(req CanonicalActionRequest) (Decision, bool) {
	spec, ok := p.agentSpec(req.AgentID)
	if !ok || spec.CompletionGate == nil {
		return Decision{}, false
	}
	var records []*dpr.Record
	if p.store != nil {
		recs, err := p.store.RecentByAgent(req.AgentID, 500)
		if err == nil {
			for _, rec := range recs {
				if rec != nil && rec.SessionID == req.SessionID {
					records = append(records, rec)
				}
			}
		}
	}
	if spec.CompletionGate.CompletionSatisfied(records) {
		return Decision{}, false
	}
	pending := pendingApprovalIDs(records)
	human := fmt.Sprintf("agent cannot complete: %d approvals pending", len(pending))
	if len(pending) == 0 {
		human = "agent cannot complete: completion_gate requirements not satisfied"
	}
	obj := denial.CompletionBlocked(human, pending)
	return p.decide(req, Decision{
		Effect:           EffectDeny,
		ReasonCode:       reasons.CompletionBlocked,
		Reason:           obj.HumanMessage,
		StructuredDenial: &obj,
	}, p.sessions.Get(req.AgentID), time.Now(), nil), true
}

func pendingApprovalIDs(records []*dpr.Record) []string {
	var ids []string
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if strings.EqualFold(rec.Effect, string(EffectDefer)) && strings.TrimSpace(rec.DeferToken) != "" {
			ids = append(ids, rec.DeferToken)
		}
	}
	return ids
}
