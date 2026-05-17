package core

import (
	"time"

	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// GovernanceLifecycle gates evaluation until the daemon is READY.
type GovernanceLifecycle interface {
	AcceptsGovernance() bool
	ColdStartExceeded() bool
}

func (p *Pipeline) SetLifecycle(lc GovernanceLifecycle) {
	p.lifecycle = lc
}

func (p *Pipeline) lifecycleDeny(req CanonicalActionRequest, start time.Time) (Decision, bool) {
	if p.lifecycle == nil {
		return Decision{}, false
	}
	if p.lifecycle.ColdStartExceeded() {
		obj := denial.DaemonNotReady(0)
		return p.decide(req, Decision{
			Effect:           EffectDeny,
			ReasonCode:       reasons.DaemonNotReady,
			Reason:           obj.HumanMessage,
			StructuredDenial: &obj,
		}, p.sessions.Get(req.AgentID), start, nil), true
	}
	if !p.lifecycle.AcceptsGovernance() {
		obj := denial.DaemonNotReady(2)
		return p.decide(req, Decision{
			Effect:           EffectDeny,
			ReasonCode:       reasons.DaemonNotReady,
			Reason:           obj.HumanMessage,
			StructuredDenial: &obj,
		}, p.sessions.Get(req.AgentID), start, nil), true
	}
	return Decision{}, false
}
