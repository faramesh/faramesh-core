package governance

import (
	"strconv"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

// FromFPL converts a parsed FPL document into the unified governance AST.
func FromFPL(doc *fpl.Document, sourcePath string) *ast.Document {
	if doc == nil {
		return nil
	}
	out := &ast.Document{
		Syntax:     ast.SyntaxFPL,
		SourcePath: sourcePath,
		Providers:  make(map[string]*ast.Provider),
		Identities: make(map[string]*ast.Identity),
		Agents:     make(map[string]*ast.Agent),
	}
	for _, imp := range doc.Imports {
		out.Imports = append(out.Imports, ast.Import{
			Ref:   imp.Ref,
			Alias: imp.Alias,
			Line:  imp.Line,
		})
	}
	if doc.Runtime != nil {
		out.Runtime = runtimeFromFields(doc.Runtime.Fields)
	}
	for _, pb := range doc.Providers {
		out.Providers[pb.Name] = providerFromFields(pb.Name, pb.Fields)
	}
	for _, ib := range doc.Identities {
		out.Identities[ib.Name] = identityFromFields(ib.Name, ib.Fields)
	}
	if doc.Trust != nil {
		out.Trust = trustFromFPL(doc.Trust)
	}
	for _, ab := range doc.Agents {
		out.Agents[ab.ID] = agentFromBlock(ab)
	}
	for _, sb := range doc.Systems {
		out.Systems = append(out.Systems, &ast.System{
			ID:                  sb.ID,
			Version:             sb.Version,
			OnPolicyLoadFailure: sb.OnPolicyLoadFailure,
			MaxOutputBytes:      sb.MaxOutputBytes,
		})
	}
	for _, r := range doc.FlatRules {
		out.FlatRules = append(out.FlatRules, ruleFromFPL(r))
	}
	for _, t := range doc.Topo {
		out.Topo = append(out.Topo, topoToAST(t))
	}
	return out
}

func runtimeFromFields(fields map[string]fpl.ConfigValue) *ast.Runtime {
	if len(fields) == 0 {
		return nil
	}
	rt := &ast.Runtime{Extra: make(map[string]string)}
	for k, v := range fields {
		switch k {
		case "mode":
			rt.Mode = configString(v)
		case "wal_dir":
			rt.WALDir = configString(v)
		case "backend":
			rt.Backend = configString(v)
		case "dsn":
			rt.DSN = configString(v)
		case "otlp":
			rt.OTLP = configString(v)
		case "network":
			rt.Network = configString(v)
		case "session_backend":
			rt.SessionBackend = configString(v)
		case "session_dsn":
			rt.SessionDSN = configString(v)
		case "cold_start_deny_window":
			rt.ColdStartDenyWindow = configString(v)
		case "socket":
			rt.Socket = configString(v)
		case "log_level":
			rt.LogLevel = configString(v)
		case "immutable_config":
			rt.ImmutableConfig = configBool(v)
		case "require_governance_before_net":
			rt.RequireGovernanceBeforeNet = configBool(v)
		case "defer_backend":
			rt.DeferBackend = configString(v)
		case "defer_redis_prefix":
			rt.DeferRedisPrefix = configString(v)
		case "grpc_port":
			rt.GRPCPort = int(configNumber(v))
		case "tenant_id", "tenant":
			rt.TenantID = configString(v)
		case "dpr_signer":
			rt.DPRSigner = configString(v)
		case "dpr_kms_provider":
			rt.DPRKMSProvider = configString(v)
		case "dpr_kms_key_ref":
			rt.DPRKMSKeyRef = configString(v)
		case "govern_tool_responses":
			rt.GovernToolResponses = configBool(v)
		default:
			rt.Extra[k] = configString(v)
		}
	}
	return rt
}

func providerFromFields(name string, fields map[string]fpl.ConfigValue) *ast.Provider {
	p := &ast.Provider{Name: name, Config: make(map[string]ast.Value)}
	for k, v := range fields {
		switch k {
		case "type":
			p.Type = configString(v)
		case "source":
			p.Source = configString(v)
		case "capabilities":
			if v.Kind == fpl.ConfigIdent {
				p.Capabilities = append(p.Capabilities, v.String)
			}
		default:
			p.Config[k] = configValueToAST(v)
		}
	}
	return p
}

func identityFromFields(name string, fields map[string]fpl.ConfigValue) *ast.Identity {
	id := &ast.Identity{Name: name, Config: make(map[string]ast.Value)}
	for k, v := range fields {
		switch k {
		case "type":
			id.Type = configString(v)
		case "socket":
			id.Socket = configString(v)
		case "trust_domain":
			id.TrustDomain = configString(v)
		case "domain":
			id.Domain = configString(v)
		case "jwks_url":
			id.JWKSURL = configString(v)
		case "audience":
			id.Audience = configString(v)
		default:
			id.Config[k] = configValueToAST(v)
		}
	}
	return id
}

func agentFromBlock(ab *fpl.AgentBlock) *ast.Agent {
	a := &ast.Agent{
		Name:    ab.ID,
		Default: ab.Default,
		Model:   ab.Model,
		Framework: ab.Framework,
		Version: ab.Version,
		Vars:    ab.Vars,
	}
	for _, b := range ab.Budgets {
		a.Budgets = append(a.Budgets, ast.Budget{
			Scope:    b.ID,
			Max:      b.Max,
			Daily:    b.Daily,
			MaxCalls: b.MaxCalls,
			WarnAt:   b.WarnAt,
			OnExceed: b.OnExceed,
		})
	}
	for _, ph := range ab.Phases {
		var rules []ast.Rule
		for _, r := range ph.Rules {
			rules = append(rules, ruleFromFPL(r))
		}
		a.Phases = append(a.Phases, ast.Phase{
			ID: ph.ID, Tools: ph.Tools, Rules: rules,
			Duration: ph.Duration, Next: ph.Next,
		})
	}
	for _, r := range ab.Rules {
		a.Rules = append(a.Rules, ruleFromFPL(r))
	}
	for _, d := range ab.Delegates {
		a.Delegates = append(a.Delegates, ast.Delegate{
			Target: d.TargetAgent, Scope: d.Scope, TTL: d.TTL, Ceiling: d.Ceiling,
		})
	}
	for _, amb := range ab.Ambients {
		a.Ambients = append(a.Ambients, ast.Ambient{Limits: amb.Limits, OnExceed: amb.OnExceed})
	}
	for _, sel := range ab.Selectors {
		a.Selectors = append(a.Selectors, ast.Selector{
			ID: sel.ID, Source: sel.Source, Cache: sel.Cache,
			OnUnavailable: sel.OnUnavailable, OnTimeout: sel.OnTimeout,
		})
	}
	for _, c := range ab.Credentials {
		a.Credentials = append(a.Credentials, ast.Credential{
			Name: c.ID, Backend: c.Backend, Path: c.Path,
			Scope: c.Scope, MaxScope: c.MaxScope, TTL: c.TTL,
		})
	}
	for _, rl := range ab.RateLimits {
		a.RateLimits = append(a.RateLimits, ast.RateLimit{
			Tool: rl.Pattern, Limit: rl.Limit, Window: rl.Window,
		})
	}
	for _, rd := range ab.Redactions {
		a.Redactions = append(a.Redactions, ast.Redact{Tool: rd.Tool, Paths: rd.Paths})
	}
	if ab.Egress != nil {
		a.Egress = &ast.Egress{Allow: ab.Egress.Allow, Deny: ab.Egress.Deny}
	}
	if ab.ModelPolicy != nil {
		a.ModelPolicy = &ast.ModelPolicy{Allow: ab.ModelPolicy.Allow}
	}
	if ab.Session != nil {
		a.Session = &ast.SessionLimits{
			MaxDuration: ab.Session.MaxDuration,
			IdleTimeout: ab.Session.IdleTimeout,
		}
	}
	if ab.Spawn != nil {
		a.Spawn = &ast.Spawn{
			MaxConcurrent: ab.Spawn.MaxConcurrent,
			AllowedTypes:  ab.Spawn.AllowedTypes,
		}
	}
	if ab.CompletionGate != nil {
		a.CompletionGate = &ast.CompletionGate{Requires: ab.CompletionGate.Requires}
	}
	if ab.Enforcement != nil {
		a.Enforcement = make(map[string]ast.Value)
		for k, v := range ab.Enforcement.Fields {
			a.Enforcement[k] = configValueToAST(v)
		}
	}
	for _, al := range ab.Alerts {
		a.Alerts = append(a.Alerts, ast.Alert{On: al.On, Notify: al.Notify})
	}
	return a
}

func ruleFromFPL(r *fpl.Rule) ast.Rule {
	if r == nil {
		return ast.Rule{}
	}
	return ast.Rule{
		Effect: r.Effect, Tool: r.Tool, Condition: r.Condition,
		Notify: r.Notify, Reason: r.Reason,
		Host: r.Host, Port: r.Port, Method: r.Method, Path: r.Path,
		Query: r.Query, Headers: r.Headers,
	}
}

func configValueToAST(v fpl.ConfigValue) ast.Value {
	switch v.Kind {
	case fpl.ConfigEnv:
		return ast.EnvValue(v.EnvVar)
	case fpl.ConfigString:
		return ast.StringValue(v.String)
	case fpl.ConfigNumber:
		return ast.NumberValue(v.Number)
	case fpl.ConfigBool:
		return ast.BoolValue(v.Bool)
	case fpl.ConfigIdent:
		return ast.IdentValue(v.String)
	default:
		return ast.StringValue(v.String)
	}
}

func configString(v fpl.ConfigValue) string {
	switch v.Kind {
	case fpl.ConfigString, fpl.ConfigIdent:
		return v.String
	case fpl.ConfigEnv:
		return "env(\"" + v.EnvVar + "\")"
	case fpl.ConfigNumber:
		return ast.NumberValue(v.Number).Display()
	case fpl.ConfigBool:
		if v.Bool {
			return "true"
		}
		return "false"
	default:
		return v.String
	}
}

func configNumber(v fpl.ConfigValue) float64 {
	if v.Kind == fpl.ConfigNumber {
		return v.Number
	}
	return 0
}

func configBool(v fpl.ConfigValue) bool {
	return v.Kind == fpl.ConfigBool && v.Bool
}

func topoToAST(t fpl.TopoStatement) ast.TopoStatement {
	switch t.Kind {
	case fpl.TopoOrchestrator:
		return ast.TopoStatement{
			Kind: "orchestrator",
			Args: []string{t.OrchID, t.UndeclaredPolicy},
		}
	case fpl.TopoAllow:
		args := []string{t.AllowOrchID, t.TargetAgentID, strconv.Itoa(t.MaxPerSession)}
		if t.RequiresApproval {
			args = append(args, "approval")
		}
		return ast.TopoStatement{Kind: "grant", Args: args}
	default:
		return ast.TopoStatement{}
	}
}
