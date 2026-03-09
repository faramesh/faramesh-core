// Package core defines the invariant types that flow through the decision
// pipeline identically regardless of which adapter delivers the request.
package core

import "time"

// Effect is the outcome of a governance decision.
type Effect string

const (
	EffectPermit Effect = "PERMIT"
	EffectDeny   Effect = "DENY"
	EffectDefer  Effect = "DEFER"
	EffectShadow Effect = "SHADOW"
)

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

	// DeferToken is set when Effect == DEFER. The SDK polls this token
	// to discover when the approval resolves.
	DeferToken string `json:"defer_token,omitempty"`

	// PolicyVersion is the version string of the active policy.
	PolicyVersion string `json:"policy_version"`

	// Latency is how long the pipeline took.
	Latency time.Duration `json:"-"`
}

// DeferResolution is the outcome when a DEFERed call is resolved.
type DeferResolution struct {
	DeferToken string `json:"defer_token"`
	Approved   bool   `json:"approved"`
	Reason     string `json:"reason"`
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
