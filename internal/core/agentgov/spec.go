// Package agentgov holds per-agent governance extensions compiled from governance.fms.
package agentgov

// Spec is the runtime view of agent body extensions compiled from governance.fms.
type Spec struct {
	RateLimits     []RateLimit     `json:"rate_limits,omitempty"`
	Redactions     []Redaction     `json:"redactions,omitempty"`
	BudgetWarn     []BudgetWarn    `json:"budget_warn,omitempty"`
	Egress         *EgressPolicy   `json:"egress,omitempty"`
	CompletionGate *CompletionGate `json:"completion_gate,omitempty"`
	Alerts         []AlertRule     `json:"alerts,omitempty"`
	MCPProxyPort   int             `json:"mcp_proxy_port,omitempty"`
}

// BudgetPool shares a USD ceiling across listed agents (Phase 12).
type BudgetPool struct {
	Name   string   `json:"name"`
	Agents []string `json:"agents"`
	Max    float64  `json:"max"`
}

// EgressPolicy controls outbound host allow/deny lists.
type EgressPolicy struct {
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// CompletionGate blocks session stop until DPR predicates hold.
type CompletionGate struct {
	Requires []string `json:"requires,omitempty"`
}

// AlertRule is a deterministic DPR predicate that fires structured warnings.
type AlertRule struct {
	Name      string `json:"name"`
	When      string `json:"when"`
	OnTrigger string `json:"on_trigger,omitempty"`
}

type RateLimit struct {
	Tool   string `json:"tool"`
	Limit  int64  `json:"limit"`
	Window string `json:"window"`
}

type Redaction struct {
	Tool  string   `json:"tool"`
	Paths []string `json:"paths"`
}

// BudgetWarn ties a budget scope to a warn_at fraction (0,1).
type BudgetWarn struct {
	Scope  string  `json:"scope"`
	WarnAt float64 `json:"warn_at"`
}
