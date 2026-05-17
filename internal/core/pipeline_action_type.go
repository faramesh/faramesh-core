package core

import (
	"fmt"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// evaluateByActionType applies action-type-specific gates before standard policy eval.
func (p *Pipeline) evaluateByActionType(req CanonicalActionRequest, start time.Time) (Decision, bool) {
	switch NormalizeActionType(req.ActionType) {
	case ActionTypeToolCall:
		return Decision{}, false
	case ActionTypeAgentDelegation, ActionTypeInboundDelegation:
		obj := denial.PolicyDeny("POLICY_DENY", "agent delegation governance not yet enforced", "")
		return p.decide(req, Decision{
			Effect:           EffectDeny,
			ReasonCode:       reasons.RuleDeny,
			Reason:           obj.HumanMessage,
			StructuredDenial: &obj,
		}, p.sessions.Get(req.AgentID), start, nil), true
	case ActionTypeCompletionEvent:
		if d, blocked := p.checkCompletionGateForEvent(req); blocked {
			return d, true
		}
		return Decision{}, false
	case ActionTypeModelCall:
		return Decision{}, false
	case ActionTypeSessionSpawn:
		return Decision{}, false
	case ActionTypeToolResponse:
		return Decision{}, false
	default:
		return p.decide(req, Decision{
			Effect:     EffectDeny,
			ReasonCode: reasons.SchemaValidationFail,
			Reason:     fmt.Sprintf("unknown action_type %q", req.ActionType),
		}, p.sessions.Get(req.AgentID), start, nil), true
	}
}
