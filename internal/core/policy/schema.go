// Package policy handles loading, compiling, and evaluating Faramesh Policy
// Language (FPL) v1.0 files. Policy files are YAML. Conditions are compiled
// to expr-lang bytecode at load time and evaluated at ~1μs per rule.
package policy

import (
	"time"

	"github.com/faramesh/faramesh-core/internal/core/postcondition"
)

// Doc is the top-level structure of a faramesh policy file.
type Doc struct {
	FarameshVersion string                      `yaml:"faramesh-version"`
	AgentID         string                      `yaml:"agent-id"`
	Vars            map[string]any              `yaml:"vars"`
	Tools           map[string]Tool             `yaml:"tools"`
	Phases          map[string]Phase            `yaml:"phases"`
	Rules           []Rule                      `yaml:"rules"`
	PostRules       []postcondition.PostRule    `yaml:"post_rules"`
	Budget          *Budget                     `yaml:"budget"`
	Session         *SessionConfig              `yaml:"session"`
	DefaultEffect   string                      `yaml:"default_effect"`
	ContextGuards   []ContextGuard              `yaml:"context_guards"`
	Webhooks        *WebhookConfig              `yaml:"webhooks"`
	MaxOutputBytes  int                         `yaml:"max_output_bytes"`
	Compensation    map[string]CompensationMeta `yaml:"compensation"`

	// ── v1.0 Extensions ──

	// PhaseTransitions defines rules for transitioning between workflow phases.
	PhaseTransitions []PhaseTransition `yaml:"phase_transitions"`

	// PhaseEnforcement configures behavior when a tool is called outside its phase.
	PhaseEnforcement *PhaseEnforcementConfig `yaml:"phase_enforcement"`

	// SessionStatePolicy governs reads/writes to shared session state (multi-agent).
	SessionStatePolicy *SessionStatePolicy `yaml:"session_state_policy"`

	// CrossSessionGuards detect accumulation attacks across sessions.
	CrossSessionGuards []CrossSessionGuard `yaml:"cross_session_guards"`

	// DeferPriority configures DEFER triage and prioritization tiers.
	DeferPriority *DeferPriorityConfig `yaml:"defer_priority"`

	// ParallelBudget configures aggregate budget across parallel agents.
	ParallelBudget *ParallelBudget `yaml:"parallel_budget"`

	// LoopGovernance configures critique/loop pattern governance.
	LoopGovernance *LoopGovernance `yaml:"loop_governance"`

	// OrchestratorManifest declares all permitted sub-agent invocations.
	OrchestratorManifest *OrchestratorManifest `yaml:"orchestrator_manifest"`

	// ToolSchemas declares versioned schemas for governed tools.
	ToolSchemas map[string]ToolSchema `yaml:"tool_schemas"`

	// ChainPolicies are evaluated post-hoc over complete session history (lazy validation).
	ChainPolicies []ChainPolicy `yaml:"chain_policies"`

	// OutputPolicies govern synthesized/aggregated LLM outputs.
	OutputPolicies []OutputPolicy `yaml:"output_policies"`

	// ExecutionIsolation configures sandbox/microVM requirements per tool.
	ExecutionIsolation *ExecutionIsolation `yaml:"execution_isolation"`

	// FPLInline is raw FPL source merged into rules after YAML rules (see internal/core/fpl).
	// Cleared after successful load.
	FPLInline string `yaml:"fpl_inline,omitempty"`
	// FPLFiles lists paths to .fpl files relative to the policy YAML file, merged after YAML rules.
	// Requires LoadFile (not LoadBytes alone). Cleared after successful load.
	FPLFiles []string `yaml:"fpl_files,omitempty"`
}

// Tool declares metadata about a governed tool.
type Tool struct {
	Reversibility   string   `yaml:"reversibility"`
	BlastRadius     string   `yaml:"blast_radius"`
	ShadowSafe      bool     `yaml:"shadow_safe"`
	Tags            []string `yaml:"tags"`
	EndpointPattern string   `yaml:"endpoint_pattern"`

	// CostUSD is the estimated cost in USD per successful call to this tool.
	// Used by the pipeline to call sess.AddCost() after a PERMIT, enabling
	// accurate session and daily budget enforcement.
	// For dynamic-cost tools, set this to the base/minimum cost; the agent
	// can call sess.AddCost() with the actual cost after the call returns.
	CostUSD float64 `yaml:"cost_usd"`
}

// Phase defines a workflow phase that scopes which tools are visible.
type Phase struct {
	Tools    []string `yaml:"tools"`
	Duration string   `yaml:"duration"`
	Next     string   `yaml:"next"`
}

// Rule is a single governance rule. Rules are evaluated in document order.
// The first matching rule's effect is applied (first-match-wins).
type Rule struct {
	ID               string `yaml:"id"`
	Match            Match  `yaml:"match"`
	Effect           string `yaml:"effect"`
	Notify           string `yaml:"notify,omitempty"`
	Reason           string `yaml:"reason"`
	ReasonCode       string `yaml:"reason_code"`
	IncidentCategory string `yaml:"incident_category"`
	IncidentSeverity string `yaml:"incident_severity"`
}

// Match defines the conditions under which a rule fires.
type Match struct {
	// Tool is a glob pattern matched against the tool ID.
	// Examples: "stripe/*", "shell/run", "*"
	Tool string `yaml:"tool"`

	// When is an expr-lang expression evaluated against the call context.
	// Available variables: args, vars, session, tool, principal, delegation, time
	When string `yaml:"when"`
}

// Budget defines cost and call limits enforced pre-execution.
type Budget struct {
	// DailyUSD is the maximum USD spend per calendar day (persisted, survives restarts).
	DailyUSD float64 `yaml:"daily_usd"`
	// SessionUSD is the maximum USD spend per session.
	SessionUSD float64 `yaml:"session_usd"`
	// MaxCalls is the maximum total tool calls per session (all tools).
	MaxCalls int64 `yaml:"max_calls"`
	// OnExceed is the effect when a limit is hit: "deny" or "defer".
	OnExceed string `yaml:"on_exceed"`
}

// ContextGuard defines a freshness/completeness check on external context
// sources. Before high-stakes actions, these guards verify that the agent's
// context is fresh, complete, and consistent.
type ContextGuard struct {
	// Source is a human-readable name for the context source.
	Source string `yaml:"source"`

	// Endpoint is the HTTP URL to check for context freshness.
	Endpoint string `yaml:"endpoint"`

	// RequiredFields are fields that must be present in the context response.
	RequiredFields []string `yaml:"required_fields"`

	// MaxAgeSecs is the maximum age (in seconds) before context is considered stale.
	MaxAgeSecs int `yaml:"max_age_seconds"`

	// OnStale is the effect when context is stale (deny or defer).
	OnStale string `yaml:"on_stale"`

	// OnMissing is the effect when required fields are missing.
	OnMissing string `yaml:"on_missing"`

	// OnInconsistent is the effect when context values are contradictory.
	OnInconsistent string `yaml:"on_inconsistent"`
}

// WebhookConfig defines which events trigger webhook delivery.
type WebhookConfig struct {
	// URL is the destination for webhook POSTs.
	URL string `yaml:"url"`

	// Events lists which event types trigger the webhook.
	// Valid: "deny", "defer", "defer_resolved", "permit", "policy_activated", "kill_switch"
	Events []string `yaml:"events"`

	// Secret is an HMAC-SHA256 signing secret for webhook payloads.
	Secret string `yaml:"secret"`

	// TimeoutMs is the HTTP timeout for webhook delivery (default: 5000).
	TimeoutMs int `yaml:"timeout_ms"`
}

// CompensationMeta defines how a tool's actions can be reversed.
type CompensationMeta struct {
	// CompensationTool is the tool ID to call for reversal.
	CompensationTool string `yaml:"compensation_tool"`

	// ArgMapping maps compensation tool args from original action result.
	// Keys are compensation arg names, values are JSONPath into original result.
	ArgMapping map[string]string `yaml:"arg_mapping"`
}

// ── v1.0 Extension Types ──

// PhaseTransition defines conditions for moving between workflow phases.
type PhaseTransition struct {
	From       string `yaml:"from"`
	To         string `yaml:"to"`
	Conditions string `yaml:"conditions"` // expr-lang expression
	Effect     string `yaml:"effect"`     // "permit_transition" or "defer"
	Reason     string `yaml:"reason"`
}

// PhaseEnforcementConfig configures what happens when a tool is called
// outside its declared workflow phase.
type PhaseEnforcementConfig struct {
	OnOutOfPhaseCall string `yaml:"on_out_of_phase_call"` // "deny" or "defer"
	ReasonCode       string `yaml:"reason_code"`
}

// SessionStatePolicy governs writes/reads to shared session state (multi-agent).
type SessionStatePolicy struct {
	AgentID             string                `yaml:"agent_id"`
	DeclaredKeys        []SessionStateDeclKey `yaml:"declared_keys"`
	UndeclaredKeyPolicy string                `yaml:"undeclared_key_policy"` // "deny" or "permit"
	WriteScan           *WriteScanConfig      `yaml:"write_scan"`
	ReadSanitization    *ReadSanitizationConf `yaml:"read_sanitization"`
}

// SessionStateDeclKey declares an allowed key in shared session state.
type SessionStateDeclKey struct {
	Key       string   `yaml:"key"`
	Type      string   `yaml:"type"`
	MaxLength int      `yaml:"max_length"`
	Scan      []string `yaml:"scan"` // "injection", "pii", "secret"
}

// WriteScanConfig configures scans applied to session state writes.
type WriteScanConfig struct {
	InjectionDetection bool `yaml:"injection_detection"`
	PIIScan            bool `yaml:"pii_scan"`
	SecretScan         bool `yaml:"secret_scan"`
}

// ReadSanitizationConf configures sanitization of session state reads.
type ReadSanitizationConf struct {
	StripInjectionPatterns bool `yaml:"strip_injection_patterns"`
	MaxInterpolationDepth  int  `yaml:"max_interpolation_depth"`
}

// CrossSessionGuard detects accumulation attacks across sessions.
type CrossSessionGuard struct {
	Scope            string `yaml:"scope"` // "principal"
	ToolPattern      string `yaml:"tool_pattern"`
	Metric           string `yaml:"metric"` // "unique_record_count", "call_count"
	Window           string `yaml:"window"` // e.g. "24h"
	MaxUniqueRecords int    `yaml:"max_unique_records"`
	OnExceed         string `yaml:"on_exceed"` // "deny" or "defer"
	Reason           string `yaml:"reason"`
}

// DeferPriorityConfig configures triage tiers for DEFER events.
type DeferPriorityConfig struct {
	Critical *DeferTier `yaml:"critical"`
	High     *DeferTier `yaml:"high"`
	Normal   *DeferTier `yaml:"normal"`
}

// DeferTier defines SLA and routing for a DEFER priority level.
type DeferTier struct {
	Criteria            string `yaml:"criteria"` // expr-lang expression
	SLASeconds          int    `yaml:"sla_seconds"`
	Channel             string `yaml:"channel"` // "pagerduty", "slack", etc.
	EscalationAfterSecs int    `yaml:"escalation_after_seconds"`
	AutoDenyAfterSecs   int    `yaml:"auto_deny_after_seconds"`
}

// ParallelBudget configures aggregate cost limits across parallel agents.
type ParallelBudget struct {
	OrchestrationID     string   `yaml:"orchestration_id"`
	Agents              []string `yaml:"agents"`
	AggregateMaxCostUSD float64  `yaml:"aggregate_max_cost_usd"`
	PerAgentMaxCostUSD  float64  `yaml:"per_agent_max_cost_usd"`
	OnAggregateExceed   string   `yaml:"on_aggregate_exceed"` // "cancel_remaining", "deny"
}

// LoopGovernance configures critique/loop pattern governance.
type LoopGovernance struct {
	AgentID          string             `yaml:"agent_id"`
	MaxIterations    int                `yaml:"max_iterations"`
	MaxTotalCostUSD  float64            `yaml:"max_total_cost_usd"`
	MaxDurationSecs  int                `yaml:"max_duration_seconds"`
	OnMaxReached     string             `yaml:"on_max_reached"` // "deny" or "defer"
	ConvergenceTrack *ConvergenceConfig `yaml:"convergence_tracking"`
}

// ConvergenceConfig detects when a loop is optimizing against governance.
type ConvergenceConfig struct {
	ScanResultsAcrossIterations bool    `yaml:"scan_results_across_iterations"`
	RepeatedScanThreshold       int     `yaml:"repeated_scan_threshold"`
	ImprovementThreshold        float64 `yaml:"improvement_threshold"`
	OnEvasion                   string  `yaml:"on_evasion"` // "deny" or "defer"
}

// OrchestratorManifest declares all permitted sub-agent invocations.
type OrchestratorManifest struct {
	AgentID                    string            `yaml:"agent_id"`
	PermittedInvocations       []AgentInvocation `yaml:"permitted_invocations"`
	UndeclaredInvocationPolicy string            `yaml:"undeclared_invocation_policy"` // "deny"
}

// AgentInvocation declares a permitted sub-agent invocation.
type AgentInvocation struct {
	AgentID                  string `yaml:"agent_id"`
	MaxInvocationsPerSession int    `yaml:"max_invocations_per_session"`
	RequiresPriorApproval    bool   `yaml:"requires_prior_approval"`
}

// ToolSchema declares a versioned schema for a governed tool.
type ToolSchema struct {
	Name       string                 `yaml:"name"`
	Version    string                 `yaml:"version"`
	Parameters map[string]ParamSchema `yaml:"parameters"`
}

// ParamSchema describes a tool parameter's type and constraints.
type ParamSchema struct {
	Type     string `yaml:"type"`
	Required bool   `yaml:"required"`
}

// ChainPolicy is evaluated post-hoc over complete session history (lazy validation).
type ChainPolicy struct {
	ID          string           `yaml:"id"`
	Description string           `yaml:"description"`
	Type        string           `yaml:"type"` // "session_aggregate"
	Conditions  []ChainCondition `yaml:"conditions"`
	Severity    string           `yaml:"severity"`
	FindingCode string           `yaml:"finding_code"`
}

// ChainCondition is a single condition in a chain-level policy rule.
type ChainCondition struct {
	Metric               string `yaml:"metric"`
	ToolPattern          string `yaml:"tool_pattern"`
	Tool                 string `yaml:"tool"`
	Window               string `yaml:"window"`
	Threshold            int    `yaml:"threshold"`
	DomainNotInAllowlist bool   `yaml:"domain_not_in_allowlist"`
	OccurredAfter        string `yaml:"occurred_after"`
	OccurredWithinMins   int    `yaml:"occurred_within_minutes"`
}

// OutputPolicy governs synthesized/aggregated LLM outputs (not tool calls).
type OutputPolicy struct {
	OutputType string       `yaml:"output_type"`
	Rules      []OutputRule `yaml:"rules"`
}

// OutputRule is a single rule in an output policy.
type OutputRule struct {
	ID        string          `yaml:"id"`
	Scan      map[string]bool `yaml:"scan"`      // e.g. "entity_extraction": true
	Condition string          `yaml:"condition"` // expr-lang
	OnMatch   string          `yaml:"on_match"`  // "deny" or "defer"
	Reason    string          `yaml:"reason"`
}

// ExecutionIsolation configures sandbox/microVM requirements.
type ExecutionIsolation struct {
	Enabled        bool                        `yaml:"enabled"`
	DefaultBackend string                      `yaml:"default_backend"`       // "firecracker", "gvisor", "docker_sandbox"
	ToolPolicy     map[string]string           `yaml:"tool_isolation_policy"` // tool pattern -> "required"|"optional"|"none"
	Backends       map[string]IsolationBackend `yaml:"backends"`
}

// IsolationBackend configures a specific sandbox backend.
type IsolationBackend struct {
	Runtime     string `yaml:"runtime"`
	Platform    string `yaml:"platform"`
	NetworkMode string `yaml:"network_mode"`
	ReadOnly    bool   `yaml:"read_only"`
	MemSizeMB   int    `yaml:"mem_size_mb"`
	VCPUCount   int    `yaml:"vcpu_count"`
}

// SessionConfig configures session behavior.
type SessionConfig struct {
	Identity     string        `yaml:"identity"`
	Expiry       time.Duration `yaml:"expiry"`
	HistoryCalls int           `yaml:"history_calls"`
	HistorySecs  int           `yaml:"history_secs"`
}
