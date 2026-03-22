// Package core defines the invariant types that flow through the decision
// pipeline identically regardless of which adapter delivers the request.
package core

import (
	"time"

	"github.com/faramesh/faramesh-core/internal/core/principal"
)

// Effect is the outcome of a governance decision.
type Effect string

const (
	EffectPermit       Effect = "PERMIT"
	EffectDeny         Effect = "DENY"
	EffectDefer        Effect = "DEFER"
	EffectShadow       Effect = "SHADOW"
	EffectShadowPermit Effect = "SHADOW_PERMIT"
)

// CARVersion is the current Canonical Action Request specification version.
const CARVersion = "car/1.0"

// CanonicalActionRequest is the normalized representation of a tool call
// delivered by any adapter. All fields are set before the pipeline runs.
type CanonicalActionRequest struct {
	// CallID is a UUID v4 assigned by the adapter for idempotency.
	CallID string `json:"call_id"`

	// AgentID is the identity of the agent making the call.
	// In A1 mode this is self-reported. In production it is
	// infrastructure-injected and read from /proc/1/environ.
	AgentID string `json:"agent_id"`

	// SessionID groups calls within a single agent session.
	SessionID string `json:"session_id"`

	// ToolID identifies the tool being called, e.g. "stripe/refund".
	ToolID string `json:"tool_id"`

	// Args are the raw arguments to the tool call.
	Args map[string]any `json:"args"`

	// Timestamp is when the adapter received the call.
	Timestamp time.Time `json:"timestamp"`

	// InterceptAdapter identifies which adapter delivered this request.
	// "sdk" for A1, "proxy" for A3, "mcp" for A5, "ebpf" for A6.
	InterceptAdapter string `json:"intercept_adapter"`

	// WorkflowStep is optional workflow-step context used for step-scoped
	// tool visibility enforcement within the active phase.
	WorkflowStep string `json:"workflow_step,omitempty"`

	// ExecutionEnvironment is the runtime isolation environment in which the
	// tool will execute (e.g. "none", "docker", "gvisor", "firecracker").
	// When policy execution_isolation marks a tool as required, this field is
	// enforced pre-execution.
	ExecutionEnvironment string `json:"execution_environment,omitempty"`

	// ExecutionTimeoutMS is the requested tool execution timeout in milliseconds.
	// Adapters should map runtime-specific timeout contracts to this canonical
	// field. The pipeline enforces sane bounds and optional policy requirements.
	ExecutionTimeoutMS int `json:"execution_timeout_ms,omitempty"`

	// Principal is the invoking human/system identity (optional).
	// Policy rules can reference principal.tier, principal.role, etc.
	Principal *principal.Identity `json:"principal,omitempty"`

	// Delegation is the delegation chain if this is a delegated call (optional).
	// Policy rules can reference delegation.depth, delegation.origin_org, etc.
	Delegation *principal.DelegationChain `json:"delegation,omitempty"`

	// Invocation carries invocation-scoped context for delegated sub-agent calls.
	// When present, runtime can intersect base policy with invocation sub-policy.
	Invocation *InvocationContext `json:"invocation,omitempty"`
}

// InvocationContext identifies an invocation-scoped execution context.
type InvocationContext struct {
	// ID is the stable invocation identifier used to look up sub-policies.
	ID string `json:"id"`
}

// Decision is the output of the evaluation pipeline.
type Decision struct {
	// Effect is the governance outcome.
	Effect Effect `json:"effect"`

	// RuleID is the ID of the first rule that matched, or "" for default deny.
	RuleID string `json:"rule_id"`

	// ReasonCode is a machine-readable reason token.
	ReasonCode string `json:"reason_code"`

	// Reason is a human-readable explanation.
	Reason string `json:"reason"`

	// DenialToken is an opaque token for operator lookup when Effect == DENY.
	// No policy structure is exposed to the agent — oracle attack prevention.
	DenialToken string `json:"denial_token,omitempty"`

	// RetryPermitted indicates whether the agent may retry this action.
	// False = categorical deny (policy forbids this). True = state-dependent
	// deny (budget exhausted, context stale — state may change).
	RetryPermitted bool `json:"retry_permitted,omitempty"`

	// DeferToken is set when Effect == DEFER. The SDK polls this token
	// to discover when the approval resolves.
	DeferToken string `json:"defer_token,omitempty"`

	// DeferExpiresAt is when the DEFER auto-denies if unresolved.
	DeferExpiresAt time.Time `json:"defer_expires_at,omitempty"`

	// DeferPollIntervalSecs is the suggested poll interval for check_approval().
	DeferPollIntervalSecs int `json:"defer_poll_interval_secs,omitempty"`

	// ShadowActualOutcome is set when Effect == SHADOW_PERMIT, indicating
	// what would have happened under enforcement mode.
	ShadowActualOutcome Effect `json:"shadow_actual_outcome,omitempty"`

	// IncidentCategory classifies the governance event for observability.
	IncidentCategory string `json:"incident_category,omitempty"`

	// IncidentSeverity grades the governance event.
	IncidentSeverity string `json:"incident_severity,omitempty"`

	// PolicyVersion is the version string of the active policy.
	PolicyVersion string `json:"policy_version"`

	// DPRRecordID is the ID of the DPR record created for this decision.
	DPRRecordID string `json:"dpr_record_id,omitempty"`

	// AgentID is the request agent ID associated with this decision.
	AgentID string `json:"agent_id,omitempty"`

	// ToolID is the request tool ID associated with this decision.
	ToolID string `json:"tool_id,omitempty"`

	// SessionID is the request session ID associated with this decision.
	SessionID string `json:"session_id,omitempty"`

	// Timestamp is when the adapter received this request.
	Timestamp time.Time `json:"timestamp,omitempty"`

	// Latency is how long the pipeline took.
	Latency time.Duration `json:"-"`
}

// GovernanceError is the base error type for governance infrastructure failures.
// When the governance layer itself fails, actions are DENIED (fail-closed).
type GovernanceError struct {
	Outcome     Effect `json:"outcome"`
	DenialToken string `json:"denial_token"`
	Err         error  `json:"-"`
}

func (e *GovernanceError) Error() string { return e.Err.Error() }
func (e *GovernanceError) Unwrap() error { return e.Err }

// GovernanceTimeoutError indicates policy evaluation exceeded the 50ms timeout.
type GovernanceTimeoutError struct{ GovernanceError }

// GovernanceUnavailableError indicates the governance layer is unavailable.
type GovernanceUnavailableError struct{ GovernanceError }

// DeferResolution is the outcome when a DEFERed call is resolved.
type DeferResolution struct {
	DeferToken string    `json:"defer_token"`
	Approved   bool      `json:"approved"`
	Reason     string    `json:"reason"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// DeferStatus is the current state of a pending DEFER.
type DeferStatus string

const (
	DeferStatusPending  DeferStatus = "pending"
	DeferStatusApproved DeferStatus = "approved"
	DeferStatusDenied   DeferStatus = "denied"
	DeferStatusExpired  DeferStatus = "expired"
)
