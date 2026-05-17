// Package ast defines the unified governance stack document model.
// FPL, YAML, and JSON parsers in internal/core/governance/parse produce this AST.
package ast

// Syntax identifies which surface syntax produced a document.
type Syntax string

const (
	SyntaxFPL  Syntax = "fpl"
	SyntaxYAML Syntax = "yaml"
	SyntaxJSON Syntax = "json"
)

// Document is a compiled governance stack (governance.fms and equivalents).
type Document struct {
	Syntax     Syntax
	SourcePath string

	Imports    []Import
	Runtime    *Runtime
	Providers  map[string]*Provider
	Identities map[string]*Identity
	Trust      *Trust
	Agents     map[string]*Agent

	// Legacy FPL constructs preserved for policy compilation paths.
	Systems   []*System
	FlatRules []Rule
	Topo      []TopoStatement
}

type Import struct {
	Ref     string
	Alias   string
	Line    int
	Column  int
}

type Runtime struct {
	Mode                         string
	WALDir                       string
	Backend                      string
	DSN                          string
	OTLP                         string
	Network                      string
	SessionBackend               string
	SessionDSN                     string
	ColdStartDenyWindow          string
	Socket                       string
	LogLevel                     string
	ImmutableConfig              bool
	RequireGovernanceBeforeNet   bool
	DeferBackend                 string
	DeferRedisPrefix             string
	GRPCPort                     int
	Admin                        map[string]string
	Observability                map[string]string
	TLS                          map[string]string
	Preflight                    map[string]string
	Horizon                      map[string]string
	TenantID                     string
	DPRSigner                    string
	DPRKMSProvider               string
	DPRKMSKeyRef                 string
	GovernToolResponses          bool
	OSTier                       bool
	StripAmbientCredentials      bool
	AgentEnforceProfile          string
	SupervisedCommand            string
	Extra                        map[string]string
}

type Provider struct {
	Name         string
	Type         string
	Source       string
	Config       map[string]Value
	Capabilities []string
}

type Identity struct {
	Name        string
	Type        string
	Socket      string
	TrustDomain string
	Domain      string
	JWKSURL     string
	Audience    string
	Config      map[string]Value
}

type Trust struct {
	Delegations []TrustDelegation
	Inbound     []TrustInbound
}

type TrustDelegation struct {
	From    string
	To      string
	Ceiling string
	Scope   []string
}

type TrustInbound struct {
	AgentID   string
	Auth      string
	Endpoints []string
	Scope     []string
}

type Agent struct {
	Name          string
	WorkloadID    string
	Default       string
	Model         string
	Framework     string
	Version       string
	Vars          map[string]string
	Budgets       []Budget
	Phases        []Phase
	Rules         []Rule
	Delegates     []Delegate
	Ambients      []Ambient
	Selectors     []Selector
	Credentials   []Credential
	Enforcement   map[string]Value
	RateLimits    []RateLimit
	Redactions    []Redact
	Egress        *Egress
	ModelPolicy   *ModelPolicy
	Session       *SessionLimits
	Spawn         *Spawn
	CompletionGate *CompletionGate
	Alerts        []Alert
	BudgetPools   []BudgetPool
}

// BudgetPool shares a spend ceiling across peer agents.
type BudgetPool struct {
	Name   string
	Agents []string
	Max    float64
}

type Budget struct {
	Scope    string
	Max      float64
	Daily    float64
	MaxCalls int64
	WarnAt   float64
	OnExceed string
}

type Phase struct {
	ID       string
	Tools    []string
	Rules    []Rule
	Duration string
	Next     string
}

type Delegate struct {
	Target  string
	Scope   string
	TTL     string
	Ceiling string
}

type Ambient struct {
	Limits   map[string]string
	OnExceed string
}

type Selector struct {
	ID            string
	Source        string
	Cache         string
	OnUnavailable string
	OnTimeout     string
}

type Credential struct {
	Name     string
	Backend  string
	Path     string
	Scope    []string
	MaxScope string
	TTL      string
}

type RateLimit struct {
	Tool    string
	Limit   int64
	Window  string
	Unit    string
}

type Redact struct {
	Tool  string
	Paths []string
}

type Egress struct {
	Allow []string
	Deny  []string
}

type ModelPolicy struct {
	Allow []string
}

type SessionLimits struct {
	MaxDuration string
	IdleTimeout string
}

type Spawn struct {
	MaxConcurrent int
	AllowedTypes  []string
}

type CompletionGate struct {
	Requires []string
}

type Alert struct {
	On     string
	Notify string
}

type System struct {
	ID                  string
	Version             string
	OnPolicyLoadFailure string
	MaxOutputBytes      int
}

// Rule is a policy rule (shared with legacy FPL).
type Rule struct {
	Effect    string
	Tool      string
	Condition string
	Notify    string
	Reason    string
	Host      string
	Port      string
	Method    string
	Path      string
	Query     map[string]string
	Headers   map[string]string
}

type TopoStatement struct {
	Kind string
	Args []string
}
