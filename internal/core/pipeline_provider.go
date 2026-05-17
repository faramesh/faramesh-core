package core

import (
	"time"

	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// ProviderHealthChecker reports whether all declared providers are healthy.
type ProviderHealthChecker interface {
	AllHealthy() bool
	UnhealthyDetail() string
}

func (p *Pipeline) SetProviderHealth(h ProviderHealthChecker) {
	p.providerHealth = h
}

func (p *Pipeline) checkProviderHealth(req CanonicalActionRequest) (Decision, bool) {
	if p.providerHealth == nil || p.providerHealth.AllHealthy() {
		return Decision{}, false
	}
	detail := p.providerHealth.UnhealthyDetail()
	if detail == "" {
		detail = "one or more providers are unhealthy"
	}
	obj := denial.Object{
		Code:         reasons.ProviderUnhealthy,
		HumanMessage: "denied: " + detail,
	}
	return p.decide(req, Decision{
		Effect:           EffectDeny,
		ReasonCode:       reasons.ProviderUnhealthy,
		Reason:           obj.HumanMessage,
		StructuredDenial: &obj,
	}, p.sessions.Get(req.AgentID), time.Now(), nil), true
}
