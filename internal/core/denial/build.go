package denial

import (
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

// Attach fills StructuredDenial on a deny/defer decision when absent (FARAMESH.md §12.2).
func Attach(code, human, ruleID, ruleRef string, approvalID string, retryAfter int, resetsAt time.Time, approvalIDs []string) Object {
	code = strings.TrimSpace(code)
	if code == "" {
		code = "POLICY_DENY"
	}
	obj := Object{
		Code:         code,
		RuleID:       strings.TrimSpace(ruleID),
		RuleRef:      strings.TrimSpace(ruleRef),
		HumanMessage: strings.TrimSpace(human),
	}
	switch code {
	case "DAEMON_NOT_READY":
		if retryAfter <= 0 {
			retryAfter = 2
		}
		obj.Resolution = &Resolution{Type: "retry_after", RetryAfterSeconds: retryAfter}
	case "RATE_EXCEEDED":
		if retryAfter <= 0 {
			retryAfter = 60
		}
		obj.Resolution = &Resolution{Type: "retry_after", RetryAfterSeconds: retryAfter}
	case "BUDGET_EXCEEDED":
		obj.Resolution = &Resolution{Type: "budget_reset"}
		if !resetsAt.IsZero() {
			obj.Resolution.ResetsAt = resetsAt.UTC().Format(time.RFC3339)
		}
	case "BUDGET_WARNING":
		obj.Resolution = &Resolution{Type: "pending_approval"}
		if approvalID != "" {
			obj.Resolution.ApprovalID = approvalID
		}
	case "COMPLETION_BLOCKED":
		obj.Resolution = &Resolution{Type: "pending_approvals", ApprovalIDs: approvalIDs}
	case "POLICY_DENY", reasons.RuleDeny:
		obj.Code = "POLICY_DENY"
		obj.Resolution = &Resolution{Type: "pending_approval"}
		if approvalID != "" {
			obj.Resolution.ApprovalID = approvalID
		} else if retryAfter > 0 {
			obj.Resolution = &Resolution{Type: "retry_after", RetryAfterSeconds: retryAfter}
		} else {
			obj.Resolution = nil
		}
	default:
		if strings.HasPrefix(code, "BUDGET") {
			obj.Code = "BUDGET_EXCEEDED"
			obj.Resolution = &Resolution{Type: "budget_reset"}
		}
	}
	return obj
}

// ForDefer builds structured denial for defer outcomes (pending approval).
func ForDefer(human, ruleRef, approvalID string) Object {
	return Object{
		Code:         "POLICY_DENY",
		RuleRef:      ruleRef,
		HumanMessage: human,
		Resolution:   &Resolution{Type: "pending_approval", ApprovalID: approvalID},
	}
}
