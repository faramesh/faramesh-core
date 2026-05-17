package core

import (
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func isSessionStopTool(toolID string) bool {
	t := strings.ToLower(strings.TrimSpace(toolID))
	return t == "faramesh/session/stop" || t == "session/stop" || strings.HasSuffix(t, "/session/stop")
}

func (p *Pipeline) checkCompletionGate(req CanonicalActionRequest) (Decision, bool) {
	if !isSessionStopTool(req.ToolID) {
		return Decision{}, false
	}
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
	if !spec.CompletionGate.CompletionSatisfied(records) {
		obj := denial.Object{
			Code:         reasons.CompletionBlocked,
			HumanMessage: "session stop blocked until completion_gate requirements are satisfied",
		}
		return p.decide(req, Decision{
			Effect:           EffectDeny,
			ReasonCode:       reasons.CompletionBlocked,
			Reason:           obj.HumanMessage,
			StructuredDenial: &obj,
		}, p.sessions.Get(req.AgentID), time.Now(), nil), true
	}
	return Decision{}, false
}
