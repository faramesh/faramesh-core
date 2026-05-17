// Package denial builds structured denial objects for adapters (FARAMESH.md §12.2).
package denial

import "time"

// Object is returned to adapters on deny/defer paths.
type Object struct {
	Code          string      `json:"code"`
	RuleID        string      `json:"rule_id,omitempty"`
	RuleRef       string      `json:"rule_ref,omitempty"`
	HumanMessage  string      `json:"human_message"`
	Resolution    *Resolution `json:"resolution,omitempty"`
}

// Resolution carries machine-actionable next steps.
type Resolution struct {
	Type              string   `json:"type"`
	RetryAfterSeconds int      `json:"retry_after_seconds,omitempty"`
	ResetsAt          string   `json:"resets_at,omitempty"`
	ApprovalID        string   `json:"approval_id,omitempty"`
	ApprovalIDs       []string `json:"approval_ids,omitempty"`
}

// DaemonNotReady builds DAEMON_NOT_READY.
func DaemonNotReady(retrySec int) Object {
	if retrySec <= 0 {
		retrySec = 2
	}
	return Object{
		Code:         "DAEMON_NOT_READY",
		HumanMessage: "denied: daemon is initializing, retry in a moment",
		Resolution:   &Resolution{Type: "retry_after", RetryAfterSeconds: retrySec},
	}
}

// RateExceeded builds RATE_EXCEEDED.
func RateExceeded(human string, retrySec int) Object {
	return Object{
		Code:         "RATE_EXCEEDED",
		HumanMessage: human,
		Resolution:   &Resolution{Type: "retry_after", RetryAfterSeconds: retrySec},
	}
}

// BudgetWarning builds BUDGET_WARNING.
func BudgetWarning(human, approvalID string) Object {
	res := &Resolution{Type: "pending_approval"}
	if approvalID != "" {
		res.ApprovalID = approvalID
	}
	return Object{
		Code:         "BUDGET_WARNING",
		HumanMessage: human,
		Resolution:   res,
	}
}

// CompletionBlocked builds COMPLETION_BLOCKED.
func CompletionBlocked(human string, approvalIDs []string) Object {
	return Object{
		Code:         "COMPLETION_BLOCKED",
		HumanMessage: human,
		Resolution:   &Resolution{Type: "pending_approvals", ApprovalIDs: approvalIDs},
	}
}

// PolicyDeny builds POLICY_DENY-style structured denial.
func PolicyDeny(code, human, ruleRef string) Object {
	return Object{
		Code:         code,
		RuleRef:      ruleRef,
		HumanMessage: human,
	}
}

// BudgetExceeded builds BUDGET_EXCEEDED with optional reset hint.
func BudgetExceeded(human string, resetsAt time.Time) Object {
	obj := Object{
		Code:         "BUDGET_EXCEEDED",
		HumanMessage: human,
		Resolution:   &Resolution{Type: "budget_reset"},
	}
	if !resetsAt.IsZero() {
		obj.Resolution.ResetsAt = resetsAt.UTC().Format(time.RFC3339)
	}
	return obj
}
