package governance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

// MaterializePolicyFPL renders the primary agent policy as FPL for the daemon loader.
func MaterializePolicyFPL(doc *ast.Document) (string, string, error) {
	if doc == nil {
		return "", "", fmt.Errorf("empty document")
	}
	fplDoc, agentID, err := astToRuntimeFPL(doc)
	if err != nil {
		return "", "", err
	}
	return EmitFPLDocument(fplDoc), agentID, nil
}

func astToRuntimeFPL(doc *ast.Document) (*fpl.Document, string, error) {
	if len(doc.Agents) == 0 {
		if len(doc.FlatRules) > 0 {
			out := &fpl.Document{}
			for _, r := range doc.FlatRules {
				out.FlatRules = append(out.FlatRules, astRuleToFPL(r))
			}
			return out, "", nil
		}
		return nil, "", fmt.Errorf("no agents to materialize")
	}
	names := make([]string, 0, len(doc.Agents))
	for n := range doc.Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	primary := names[0]
	ag := doc.Agents[primary]
	out := &fpl.Document{}
	out.Agents = []*fpl.AgentBlock{astAgentToFPL(primary, ag)}
	for _, sb := range doc.Systems {
		out.Systems = append(out.Systems, &fpl.SystemBlock{
			ID: sb.ID, Version: sb.Version,
			OnPolicyLoadFailure: sb.OnPolicyLoadFailure,
			MaxOutputBytes:      sb.MaxOutputBytes,
		})
	}
	for _, r := range doc.FlatRules {
		out.FlatRules = append(out.FlatRules, astRuleToFPL(r))
	}
	return out, primary, nil
}

func astAgentToFPL(name string, ag *ast.Agent) *fpl.AgentBlock {
	if ag == nil {
		return &fpl.AgentBlock{ID: name}
	}
	ab := &fpl.AgentBlock{
		ID: name, Default: ag.Default, Model: ag.Model,
		Framework: ag.Framework, Version: ag.Version, Vars: ag.Vars,
	}
	for _, b := range ag.Budgets {
		ab.Budgets = append(ab.Budgets, &fpl.BudgetBlock{
			ID: b.Scope, Max: b.Max, Daily: b.Daily, MaxCalls: b.MaxCalls,
			WarnAt: b.WarnAt, OnExceed: b.OnExceed,
		})
	}
	for _, rl := range ag.RateLimits {
		ab.RateLimits = append(ab.RateLimits, &fpl.RateLimitLine{
			Pattern: rl.Tool, Limit: rl.Limit, Window: rl.Window,
		})
	}
	for _, rd := range ag.Redactions {
		ab.Redactions = append(ab.Redactions, &fpl.RedactLine{
			Tool: rd.Tool, Paths: append([]string(nil), rd.Paths...),
		})
	}
	if ag.Egress != nil {
		ab.Egress = &fpl.EgressBlock{Allow: ag.Egress.Allow, Deny: ag.Egress.Deny}
	}
	if ag.ModelPolicy != nil {
		ab.ModelPolicy = &fpl.ModelPolicyBlock{Allow: ag.ModelPolicy.Allow}
	}
	if ag.Session != nil {
		ab.Session = &fpl.SessionBlock{
			MaxDuration: ag.Session.MaxDuration, IdleTimeout: ag.Session.IdleTimeout,
		}
	}
	if ag.Spawn != nil {
		ab.Spawn = &fpl.SpawnBlock{
			MaxConcurrent: ag.Spawn.MaxConcurrent, AllowedTypes: ag.Spawn.AllowedTypes,
		}
	}
	if ag.CompletionGate != nil {
		ab.CompletionGate = &fpl.CompletionGateBlock{Requires: ag.CompletionGate.Requires}
	}
	for _, al := range ag.Alerts {
		ab.Alerts = append(ab.Alerts, &fpl.AlertBlock{On: al.On, Notify: al.Notify})
	}
	for _, ph := range ag.Phases {
		var rules []*fpl.Rule
		for _, r := range ph.Rules {
			rules = append(rules, astRuleToFPL(r))
		}
		ab.Phases = append(ab.Phases, &fpl.PhaseBlock{
			ID: ph.ID, Tools: ph.Tools, Rules: rules, Duration: ph.Duration, Next: ph.Next,
		})
	}
	for _, r := range ag.Rules {
		ab.Rules = append(ab.Rules, astRuleToFPL(r))
	}
	for _, d := range ag.Delegates {
		ab.Delegates = append(ab.Delegates, &fpl.DelegateBlock{
			TargetAgent: d.Target, Scope: d.Scope, TTL: d.TTL, Ceiling: d.Ceiling,
		})
	}
	for _, c := range ag.Credentials {
		ab.Credentials = append(ab.Credentials, &fpl.CredentialBlock{
			ID: c.Name, Backend: c.Backend, Path: c.Path,
			Scope: c.Scope, MaxScope: c.MaxScope, TTL: c.TTL,
		})
	}
	return ab
}

func astRuleToFPL(r ast.Rule) *fpl.Rule {
	return &fpl.Rule{
		Effect: r.Effect, Tool: r.Tool, Condition: r.Condition,
		Notify: r.Notify, Reason: r.Reason,
		Host: r.Host, Port: r.Port, Method: r.Method, Path: r.Path,
		Query: r.Query, Headers: r.Headers,
	}
}

// EmitFPLDocument serializes a runtime-loadable FPL document.
func EmitFPLDocument(doc *fpl.Document) string {
	if doc == nil {
		return ""
	}
	var b strings.Builder
	for _, r := range doc.FlatRules {
		emitFlatRule(&b, r)
		b.WriteByte('\n')
	}
	for _, ag := range doc.Agents {
		emitAgentBlock(&b, ag)
		b.WriteByte('\n')
	}
	for _, sys := range doc.Systems {
		emitSystemBlock(&b, sys)
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String()) + "\n"
}

func emitAgentBlock(b *strings.Builder, ag *fpl.AgentBlock) {
	if ag == nil {
		return
	}
	b.WriteString("agent ")
	b.WriteString(quoteIdent(ag.ID))
	b.WriteString(" {\n")
	if ag.Default != "" {
		fmt.Fprintf(b, "  default %s\n", ag.Default)
	}
	if len(ag.Rules) > 0 {
		b.WriteString("\n  rules {\n")
		for _, r := range ag.Rules {
			b.WriteString("    ")
			emitFlatRule(b, r)
			b.WriteByte('\n')
		}
		b.WriteString("  }\n")
	}
	for _, bud := range ag.Budgets {
		if bud == nil {
			continue
		}
		scope := bud.ID
		if scope == "" {
			scope = "session"
		}
		fmt.Fprintf(b, "\n  budget %s {\n", scope)
		if bud.Max > 0 {
			fmt.Fprintf(b, "    max $%.2f\n", bud.Max)
		}
		if bud.Daily > 0 {
			fmt.Fprintf(b, "    daily $%.2f\n", bud.Daily)
		}
		if bud.WarnAt > 0 {
			fmt.Fprintf(b, "    warn_at %.2f\n", bud.WarnAt)
		}
		if bud.OnExceed != "" {
			fmt.Fprintf(b, "    on_exceed %s\n", bud.OnExceed)
		}
		b.WriteString("  }\n")
	}
	for _, rl := range ag.RateLimits {
		if rl == nil {
			continue
		}
		fmt.Fprintf(b, "  rate_limit %s: %d per %s\n", quoteIdent(rl.Pattern), rl.Limit, rl.Window)
	}
	for _, rd := range ag.Redactions {
		if rd == nil {
			continue
		}
		b.WriteString("  redact ")
		b.WriteString(quoteIdent(rd.Tool))
		b.WriteString(" args: [")
		for i, p := range rd.Paths {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(b, "%q", p)
		}
		b.WriteString("]\n")
	}
	if ag.Egress != nil {
		b.WriteString("  egress {\n")
		if len(ag.Egress.Allow) > 0 {
			b.WriteString("    allow = [")
			for i, v := range ag.Egress.Allow {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(b, "%q", v)
			}
			b.WriteString("]\n")
		}
		if len(ag.Egress.Deny) > 0 {
			b.WriteString("    deny = [")
			for i, v := range ag.Egress.Deny {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(b, "%q", v)
			}
			b.WriteString("]\n")
		}
		b.WriteString("  }\n")
	}
	for _, c := range ag.Credentials {
		if c == nil {
			continue
		}
		fmt.Fprintf(b, "\n  credential %s {\n", quoteIdent(c.ID))
		if c.Backend != "" {
			fmt.Fprintf(b, "    backend = %s\n", c.Backend)
		}
		if c.Path != "" {
			fmt.Fprintf(b, "    path = %q\n", c.Path)
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
}

func emitSystemBlock(b *strings.Builder, sys *fpl.SystemBlock) {
	if sys == nil {
		return
	}
	fmt.Fprintf(b, "system %s {\n", quoteIdent(sys.ID))
	if sys.Version != "" {
		fmt.Fprintf(b, "  version %q\n", sys.Version)
	}
	b.WriteString("}\n")
}

func emitFlatRule(b *strings.Builder, r *fpl.Rule) {
	if r == nil {
		return
	}
	b.WriteString(r.Effect)
	b.WriteByte(' ')
	b.WriteString(r.Tool)
	if r.Condition != "" {
		b.WriteString(" when ")
		b.WriteString(r.Condition)
	}
	if r.Notify != "" {
		fmt.Fprintf(b, " notify: %q", r.Notify)
	}
	if r.Reason != "" {
		fmt.Fprintf(b, " reason: %q", r.Reason)
	}
}

func quoteIdent(id string) string {
	if strings.ContainsAny(id, " \t/-") {
		return `"` + id + `"`
	}
	return id
}
