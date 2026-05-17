package core

import (
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/denial"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func (p *Pipeline) enrichStructuredDenial(req CanonicalActionRequest, d *Decision) {
	if d == nil || d.StructuredDenial != nil {
		return
	}
	if d.Effect != EffectDeny && d.Effect != EffectDefer {
		return
	}
	code := mapReasonToDenialCode(d.ReasonCode)
	obj := denial.Attach(code, d.Reason, d.RuleID, ruleRefFromDecision(*d), d.DeferToken, 0, d.DeferExpiresAt, nil)
	d.StructuredDenial = &obj
}

func mapReasonToDenialCode(reasonCode string) string {
	switch reasons.Normalize(reasonCode) {
	case reasons.DaemonNotReady:
		return "DAEMON_NOT_READY"
	case reasons.RateExceeded:
		return "RATE_EXCEEDED"
	case reasons.AggregateBudgetExceeded, reasons.BudgetDailyExceeded, reasons.BudgetSessionExceeded:
		return "BUDGET_EXCEEDED"
	case reasons.BudgetWarning:
		return "BUDGET_WARNING"
	case reasons.CompletionBlocked:
		return "COMPLETION_BLOCKED"
	case reasons.RuleDeny:
		return "POLICY_DENY"
	default:
		if strings.HasPrefix(reasonCode, "BUDGET") {
			return "BUDGET_EXCEEDED"
		}
		return "POLICY_DENY"
	}
}

func ruleRefFromDecision(d Decision) string {
	if strings.TrimSpace(d.PolicyVersion) != "" {
		return "governance.policy.fpl"
	}
	return ""
}
