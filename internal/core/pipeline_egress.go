package core

import (
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func (p *Pipeline) checkAgentEgress(req CanonicalActionRequest) (Decision, bool) {
	spec, ok := p.agentSpec(req.AgentID)
	if !ok || spec.Egress == nil {
		return Decision{}, false
	}
	host := extractEgressHost(req)
	if host == "" {
		return Decision{}, false
	}
	if spec.Egress.AllowsEgress(host) {
		return Decision{}, false
	}
	obj := denial.Object{
		Code:         reasons.EgressDenied,
		HumanMessage: "egress to " + host + " is not permitted for this agent",
	}
	return p.decide(req, Decision{
		Effect:           EffectDeny,
		ReasonCode:       reasons.EgressDenied,
		Reason:           obj.HumanMessage,
		StructuredDenial: &obj,
	}, p.sessions.Get(req.AgentID), time.Now(), nil), true
}

func extractEgressHost(req CanonicalActionRequest) string {
	if req.ActionType == ActionTypeModelCall {
		if h := hostFromModelArgs(req.Args); h != "" {
			return h
		}
	}
	return agentgov.HostFromRequest(req.Args)
}

func hostFromModelArgs(args map[string]any) string {
	if args == nil {
		return ""
	}
	for _, key := range []string{"model", "provider", "base_url", "api_base"} {
		if v, ok := args[key]; ok {
			if s, ok := v.(string); ok && strings.Contains(s, ".") {
				return agentgov.HostFromRequest(map[string]any{"url": s})
			}
		}
	}
	return agentgov.HostFromRequest(args)
}
