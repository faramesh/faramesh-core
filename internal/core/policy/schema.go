// Package policy handles loading, compiling, and evaluating Faramesh Policy
// Language (FPL) v1.0 files. Policy files are YAML. Conditions are compiled
// to expr-lang bytecode at load time and evaluated at ~1μs per rule.
package policy

import "time"

// Doc is the top-level structure of a faramesh policy file.
type Doc struct {
	FarameshVersion string            `yaml:"faramesh-version"`
	AgentID         string            `yaml:"agent-id"`
	Vars            map[string]any    `yaml:"vars"`
	Tools           map[string]Tool   `yaml:"tools"`
	Phases          map[string]Phase  `yaml:"phases"`
	Rules           []Rule            `yaml:"rules"`
	Budget          *Budget           `yaml:"budget"`
	Session         *Session          `yaml:"session"`
	DefaultEffect   string            `yaml:"default_effect"`
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
	ID           string `yaml:"id"`
	Match        Match  `yaml:"match"`
	Effect       string `yaml:"effect"`
	Reason       string `yaml:"reason"`
	ReasonCode   string `yaml:"reason_code"`
	IncidentCategory string `yaml:"incident_category"`
	IncidentSeverity string `yaml:"incident_severity"`
}

// Match defines the conditions under which a rule fires.
type Match struct {
	// Tool is a glob pattern matched against the tool ID.
	// Examples: "stripe/*", "shell/run", "*"
	Tool string `yaml:"tool"`

	// When is an expr-lang expression evaluated against the call context.
	// Available variables: args, vars, session, tool
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

// Session configures session behavior.
type Session struct {
	Identity     string        `yaml:"identity"`
	Expiry       time.Duration `yaml:"expiry"`
	HistoryCalls int           `yaml:"history_calls"`
	HistorySecs  int           `yaml:"history_secs"`
}
