package parse

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

func documentFromStructured(syntax ast.Syntax, path string, raw *structuredDocument) (*ast.Document, error) {
	if raw == nil {
		return &ast.Document{Syntax: syntax, SourcePath: path}, nil
	}
	doc := &ast.Document{
		Syntax:     syntax,
		SourcePath: path,
		Providers:  make(map[string]*ast.Provider),
		Identities: make(map[string]*ast.Identity),
		Agents:     make(map[string]*ast.Agent),
	}
	for _, imp := range raw.Imports {
		doc.Imports = append(doc.Imports, ast.Import{Ref: imp.Ref, Alias: imp.Alias})
	}
	if raw.Runtime != nil {
		doc.Runtime = runtimeFromMap(raw.Runtime)
	}
	for name, fields := range raw.Providers {
		doc.Providers[name] = providerFromMap(name, fields)
	}
	for name, fields := range raw.Identities {
		doc.Identities[name] = identityFromMap(name, fields)
	}
	if raw.Trust != nil {
		doc.Trust = &ast.Trust{}
	}
	for name, ag := range raw.Agents {
		doc.Agents[name] = agentFromStructured(name, ag)
	}
	for id, sys := range raw.Systems {
		doc.Systems = append(doc.Systems, &ast.System{
			ID: id, Version: sys.Version,
			OnPolicyLoadFailure: sys.OnPolicyLoadFailure,
			MaxOutputBytes:      sys.MaxOutputBytes,
		})
	}
	for _, r := range raw.Rules {
		rule, err := ruleFromStructured(r)
		if err != nil {
			return nil, err
		}
		doc.FlatRules = append(doc.FlatRules, rule)
	}
	return doc, nil
}

func runtimeFromMap(m map[string]any) *ast.Runtime {
	rt := &ast.Runtime{Extra: make(map[string]string)}
	for k, v := range m {
		s := scalarString(v)
		switch k {
		case "mode":
			rt.Mode = s
		case "wal_dir":
			rt.WALDir = s
		case "backend":
			rt.Backend = s
		case "dsn":
			rt.DSN = s
		case "otlp":
			rt.OTLP = s
		case "network":
			rt.Network = s
		case "session_backend":
			rt.SessionBackend = s
		case "session_dsn":
			rt.SessionDSN = s
		case "cold_start_deny_window":
			rt.ColdStartDenyWindow = s
		case "socket":
			rt.Socket = s
		case "log_level":
			rt.LogLevel = s
		case "immutable_config":
			rt.ImmutableConfig = scalarBool(v)
		case "require_governance_before_net":
			rt.RequireGovernanceBeforeNet = scalarBool(v)
		case "defer_backend":
			rt.DeferBackend = s
		case "defer_redis_prefix":
			rt.DeferRedisPrefix = s
		case "grpc_port":
			rt.GRPCPort = int(scalarNumber(v))
		case "tenant_id", "tenant":
			rt.TenantID = s
		case "dpr_signer":
			rt.DPRSigner = s
		case "dpr_kms_provider":
			rt.DPRKMSProvider = s
		case "dpr_kms_key_ref":
			rt.DPRKMSKeyRef = s
		case "os_tier":
			rt.OSTier = scalarBool(v)
		case "strip_ambient_credentials":
			rt.StripAmbientCredentials = scalarBool(v)
		case "agent_enforce_profile":
			rt.AgentEnforceProfile = s
		case "supervised_command":
			rt.SupervisedCommand = s
		case "govern_tool_responses":
			rt.GovernToolResponses = scalarBool(v)
		default:
			rt.Extra[k] = s
		}
	}
	return rt
}

func providerFromMap(name string, fields map[string]any) *ast.Provider {
	p := &ast.Provider{Name: name, Config: make(map[string]ast.Value)}
	for k, v := range fields {
		switch k {
		case "type":
			p.Type = scalarString(v)
		case "source":
			p.Source = scalarString(v)
		case "capabilities":
			p.Capabilities = stringSlice(v)
		default:
			val, err := valueFromAny(v)
			if err == nil {
				p.Config[k] = val
			}
		}
	}
	return p
}

func identityFromMap(name string, fields map[string]any) *ast.Identity {
	id := &ast.Identity{Name: name, Config: make(map[string]ast.Value)}
	for k, v := range fields {
		switch k {
		case "type":
			id.Type = scalarString(v)
		case "socket":
			id.Socket = scalarString(v)
		case "trust_domain":
			id.TrustDomain = scalarString(v)
		case "domain":
			id.Domain = scalarString(v)
		case "jwks_url":
			id.JWKSURL = scalarString(v)
		case "audience":
			id.Audience = scalarString(v)
		default:
			val, err := valueFromAny(v)
			if err == nil {
				id.Config[k] = val
			}
		}
	}
	return id
}

func agentFromStructured(name string, ag structuredAgent) *ast.Agent {
	a := &ast.Agent{
		Name: name, Default: ag.Default, Model: ag.Model,
		Framework: ag.Framework, Version: ag.Version, Vars: ag.Vars,
	}
	for _, r := range ag.Rules {
		rule, err := ruleFromStructured(r)
		if err == nil {
			a.Rules = append(a.Rules, rule)
		}
	}
	applyAgentExtensions(a, ag)
	return a
}

func ruleFromStructured(r structuredRule) (ast.Rule, error) {
	effect := r.Effect
	tool := r.Tool
	if r.DenyUnconditional != "" {
		effect = "deny!"
		tool = r.DenyUnconditional
	}
	if effect == "" && tool == "" {
		return ast.Rule{}, fmt.Errorf("rule requires effect or deny_unconditional")
	}
	return ast.Rule{
		Effect: effect, Tool: tool, Condition: r.When,
		Notify: r.Notify, Reason: r.Reason,
		Host: r.Host, Port: r.Port, Method: r.Method, Path: r.Path,
		Query: r.Query, Headers: r.Headers,
	}, nil
}

func valueFromAny(v any) (ast.Value, error) {
	switch x := v.(type) {
	case string:
		if env, ok := parseEnvSubstitution(x); ok {
			return ast.EnvValue(env), nil
		}
		return ast.StringValue(x), nil
	case bool:
		return ast.BoolValue(x), nil
	case float64:
		return ast.NumberValue(x), nil
	case int:
		return ast.NumberValue(float64(x)), nil
	case int64:
		return ast.NumberValue(float64(x)), nil
	default:
		return ast.Value{}, fmt.Errorf("unsupported value type %T", v)
	}
}

func parseEnvSubstitution(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "${") || !strings.HasSuffix(s, "}") {
		return "", false
	}
	inner := strings.TrimSpace(s[2 : len(s)-1])
	if inner == "" {
		return "", false
	}
	return inner, true
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		if env, ok := parseEnvSubstitution(x); ok {
			return "env(\"" + env + "\")"
		}
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return fmt.Sprint(v)
	}
}

func scalarBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	default:
		return false
	}
}

func scalarNumber(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	default:
		return 0
	}
}

func stringSlice(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, item := range x {
			out = append(out, scalarString(item))
		}
		return out
	case []string:
		return x
	default:
		return nil
	}
}
