package parse

// structuredDocument is the YAML/JSON interchange shape for governance stacks.
// Field names align with FARAMESH.md §3 multi-syntax equivalence.
type structuredDocument struct {
	Imports    []structuredImport            `json:"imports" yaml:"imports"`
	Runtime    map[string]any                `json:"runtime" yaml:"runtime"`
	Providers  map[string]map[string]any     `json:"providers" yaml:"providers"`
	Identities map[string]map[string]any     `json:"identities" yaml:"identities"`
	Trust      *structuredTrust              `json:"trust" yaml:"trust"`
	Agents     map[string]structuredAgent      `json:"agents" yaml:"agents"`
	Systems    map[string]structuredSystem     `json:"systems" yaml:"systems"`
	Rules      []structuredRule                `json:"rules" yaml:"rules"`
}

type structuredImport struct {
	Ref   string `json:"ref" yaml:"ref"`
	Alias string `json:"alias,omitempty" yaml:"alias,omitempty"`
}

type structuredTrust struct {
	Delegations []map[string]any `json:"delegations" yaml:"delegations"`
	Inbound     []map[string]any `json:"inbound" yaml:"inbound"`
}

type structuredRateLimit struct {
	Tool   string `json:"tool" yaml:"tool"`
	Limit  int64  `json:"limit" yaml:"limit"`
	Window string `json:"window" yaml:"window"`
}

type structuredRedaction struct {
	Tool  string   `json:"tool" yaml:"tool"`
	Paths []string `json:"paths" yaml:"paths"`
}

type structuredAgent struct {
	Default        string                `json:"default,omitempty" yaml:"default,omitempty"`
	Model          string                `json:"model,omitempty" yaml:"model,omitempty"`
	Framework      string                `json:"framework,omitempty" yaml:"framework,omitempty"`
	Version        string                `json:"version,omitempty" yaml:"version,omitempty"`
	Vars           map[string]string     `json:"vars,omitempty" yaml:"vars,omitempty"`
	Rules          []structuredRule      `json:"rules,omitempty" yaml:"rules,omitempty"`
	Budgets        []map[string]any      `json:"budgets,omitempty" yaml:"budgets,omitempty"`
	Phases         []map[string]any      `json:"phases,omitempty" yaml:"phases,omitempty"`
	RateLimits     []structuredRateLimit `json:"rate_limits,omitempty" yaml:"rate_limits,omitempty"`
	Redactions     []structuredRedaction `json:"redactions,omitempty" yaml:"redactions,omitempty"`
	Egress         map[string]any        `json:"egress,omitempty" yaml:"egress,omitempty"`
	ModelPolicy    map[string]any        `json:"model_policy,omitempty" yaml:"model_policy,omitempty"`
	Session        map[string]any        `json:"session,omitempty" yaml:"session,omitempty"`
	Spawn          map[string]any        `json:"spawn,omitempty" yaml:"spawn,omitempty"`
	CompletionGate map[string]any        `json:"completion_gate,omitempty" yaml:"completion_gate,omitempty"`
	Enforcement    map[string]any        `json:"enforcement,omitempty" yaml:"enforcement,omitempty"`
	Alerts         []map[string]any      `json:"alerts,omitempty" yaml:"alerts,omitempty"`
	BudgetPools    []map[string]any      `json:"budget_pools,omitempty" yaml:"budget_pools,omitempty"`
}

type structuredSystem struct {
	Version             string `json:"version,omitempty" yaml:"version,omitempty"`
	OnPolicyLoadFailure string `json:"on_policy_load_failure,omitempty" yaml:"on_policy_load_failure,omitempty"`
	MaxOutputBytes      int    `json:"max_output_bytes,omitempty" yaml:"max_output_bytes,omitempty"`
}

type structuredRule struct {
	Effect            string            `json:"effect" yaml:"effect"`
	Tool              string            `json:"tool,omitempty" yaml:"tool,omitempty"`
	DenyUnconditional string            `json:"deny_unconditional,omitempty" yaml:"deny_unconditional,omitempty"`
	When              string            `json:"when,omitempty" yaml:"when,omitempty"`
	Notify            string            `json:"notify,omitempty" yaml:"notify,omitempty"`
	Reason            string            `json:"reason,omitempty" yaml:"reason,omitempty"`
	Host              string            `json:"host,omitempty" yaml:"host,omitempty"`
	Port              string            `json:"port,omitempty" yaml:"port,omitempty"`
	Method            string            `json:"method,omitempty" yaml:"method,omitempty"`
	Path              string            `json:"path,omitempty" yaml:"path,omitempty"`
	Query             map[string]string `json:"query,omitempty" yaml:"query,omitempty"`
	Headers           map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`
}
