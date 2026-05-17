package core

import (
	"strings"

	"go.uber.org/zap"
)

// evaluateAgentAlerts runs deterministic alert predicates after a decision (DPR already written).
func (p *Pipeline) evaluateAgentAlerts(req CanonicalActionRequest, d Decision) {
	spec, ok := p.agentSpec(req.AgentID)
	if !ok || len(spec.Alerts) == 0 || p.log == nil {
		return
	}
	effect := strings.ToUpper(string(d.Effect))
	for _, al := range spec.Alerts {
		when := strings.ToLower(strings.TrimSpace(al.When))
		if when == "" {
			continue
		}
		triggered := false
		switch when {
		case "deny":
			triggered = effect == "DENY"
		case "defer":
			triggered = effect == "DEFER"
		case "permit":
			triggered = effect == "PERMIT" || effect == "SHADOW_PERMIT"
		default:
			if strings.HasPrefix(when, "reason:") {
				triggered = strings.EqualFold(d.ReasonCode, strings.TrimPrefix(when, "reason:"))
			}
		}
		if triggered {
			p.log.Warn("agent alert",
				zap.String("agent", req.AgentID),
				zap.String("alert", al.Name),
				zap.String("on_trigger", al.OnTrigger),
				zap.String("effect", effect),
				zap.String("reason_code", d.ReasonCode),
			)
		}
	}
}
