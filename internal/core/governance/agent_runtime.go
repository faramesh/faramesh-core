package governance

import (
	"fmt"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

// AgentRuntimeFromDocument extracts per-agent extension specs for the compiled artifact.
func AgentRuntimeFromDocument(doc *ast.Document) map[string]agentgov.Spec {
	if doc == nil || len(doc.Agents) == 0 {
		return nil
	}
	out := make(map[string]agentgov.Spec, len(doc.Agents))
	for name, ag := range doc.Agents {
		if ag == nil {
			continue
		}
		spec := agentgov.Spec{}
		for _, rl := range ag.RateLimits {
			spec.RateLimits = append(spec.RateLimits, agentgov.RateLimit{
				Tool: rl.Tool, Limit: rl.Limit, Window: rl.Window,
			})
		}
		for _, rd := range ag.Redactions {
			spec.Redactions = append(spec.Redactions, agentgov.Redaction{
				Tool: rd.Tool, Paths: append([]string(nil), rd.Paths...),
			})
		}
		for _, b := range ag.Budgets {
			if b.WarnAt > 0 && b.WarnAt < 1 {
				spec.BudgetWarn = append(spec.BudgetWarn, agentgov.BudgetWarn{
					Scope: b.Scope, WarnAt: b.WarnAt,
				})
			}
		}
		if ag.Egress != nil {
			spec.Egress = &agentgov.EgressPolicy{
				Allow: append([]string(nil), ag.Egress.Allow...),
				Deny:  append([]string(nil), ag.Egress.Deny...),
			}
		}
		if ag.CompletionGate != nil {
			spec.CompletionGate = &agentgov.CompletionGate{
				Requires: append([]string(nil), ag.CompletionGate.Requires...),
			}
		}
		for _, al := range ag.Alerts {
			spec.Alerts = append(spec.Alerts, agentgov.AlertRule{
				Name: al.On, When: al.On, OnTrigger: al.Notify,
			})
		}
		if port := enforcementMCPPort(ag.Enforcement); port > 0 {
			spec.MCPProxyPort = port
		}
		if specNonEmpty(spec) {
			out[name] = spec
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func enforcementMCPPort(fields map[string]ast.Value) int {
	if fields == nil {
		return 0
	}
	if v, ok := fields["mcp_proxy_port"]; ok {
		switch v.Kind {
		case ast.ValueNumber:
			return int(v.Number)
		case ast.ValueString:
			var n int
			_, _ = fmt.Sscanf(v.String, "%d", &n)
			return n
		}
	}
	return 0
}

func specNonEmpty(s agentgov.Spec) bool {
	return len(s.RateLimits)+len(s.Redactions)+len(s.BudgetWarn)+len(s.Alerts) > 0 ||
		s.Egress != nil || s.CompletionGate != nil || s.MCPProxyPort > 0
}
