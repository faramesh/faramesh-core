package parse

import (
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance/ast"
)

func applyAgentExtensions(a *ast.Agent, ag structuredAgent) {
	if a == nil {
		return
	}
	for _, bm := range ag.Budgets {
		if b := budgetFromMap(bm); b.Scope != "" || b.Max > 0 || b.Daily > 0 || b.MaxCalls > 0 || b.WarnAt > 0 {
			a.Budgets = append(a.Budgets, b)
		}
	}
	for _, rl := range ag.RateLimits {
		if rl.Tool == "" {
			continue
		}
		a.RateLimits = append(a.RateLimits, ast.RateLimit{
			Tool: rl.Tool, Limit: rl.Limit, Window: rl.Window,
		})
	}
	for _, rd := range ag.Redactions {
		if rd.Tool == "" {
			continue
		}
		a.Redactions = append(a.Redactions, ast.Redact{
			Tool: rd.Tool, Paths: append([]string(nil), rd.Paths...),
		})
	}
	if ag.Egress != nil {
		a.Egress = &ast.Egress{
			Allow: stringSlice(ag.Egress["allow"]),
			Deny:  stringSlice(ag.Egress["deny"]),
		}
	}
	if ag.ModelPolicy != nil {
		a.ModelPolicy = &ast.ModelPolicy{Allow: stringSlice(ag.ModelPolicy["allow"])}
	}
	if ag.Session != nil {
		a.Session = &ast.SessionLimits{
			MaxDuration: scalarString(ag.Session["max_duration"]),
			IdleTimeout: scalarString(ag.Session["idle_timeout"]),
		}
	}
	if ag.Spawn != nil {
		a.Spawn = &ast.Spawn{
			MaxConcurrent: int(scalarNumber(ag.Spawn["max_concurrent"])),
			AllowedTypes:  stringSlice(ag.Spawn["allowed_types"]),
		}
	}
	if ag.CompletionGate != nil {
		a.CompletionGate = &ast.CompletionGate{
			Requires: stringSlice(ag.CompletionGate["require"]),
		}
		if len(a.CompletionGate.Requires) == 0 {
			a.CompletionGate.Requires = stringSlice(ag.CompletionGate["requires"])
		}
	}
	if len(ag.Enforcement) > 0 {
		a.Enforcement = make(map[string]ast.Value, len(ag.Enforcement))
		for k, v := range ag.Enforcement {
			if val, err := valueFromAny(v); err == nil {
				a.Enforcement[k] = val
			}
		}
	}
	for _, al := range ag.Alerts {
		on := scalarString(al["on"])
		notify := scalarString(al["notify"])
		if on != "" {
			a.Alerts = append(a.Alerts, ast.Alert{On: on, Notify: notify})
		}
	}
	for _, bp := range ag.BudgetPools {
		if pool := budgetPoolFromMap(bp); pool.Name != "" {
			a.BudgetPools = append(a.BudgetPools, pool)
		}
	}
}

func budgetPoolFromMap(m map[string]any) ast.BudgetPool {
	if m == nil {
		return ast.BudgetPool{}
	}
	return ast.BudgetPool{
		Name:   scalarString(m["name"]),
		Agents: stringSlice(m["agents"]),
		Max:    scalarNumber(m["max"]),
	}
}

func budgetFromMap(m map[string]any) ast.Budget {
	if m == nil {
		return ast.Budget{}
	}
	scope := scalarString(m["scope"])
	if scope == "" {
		scope = scalarString(m["id"])
	}
	b := ast.Budget{
		Scope:    scope,
		Max:      scalarNumber(m["max"]),
		Daily:    scalarNumber(m["daily"]),
		MaxCalls: int64(scalarNumber(m["max_calls"])),
		WarnAt:   scalarNumber(m["warn_at"]),
		OnExceed: scalarString(m["on_exceed"]),
	}
	if b.Max == 0 {
		if v := scalarNumber(m["session_usd"]); v > 0 {
			b.Max = v
		}
	}
	if b.Daily == 0 {
		if v := scalarNumber(m["daily_usd"]); v > 0 {
			b.Daily = v
		}
	}
	if strings.EqualFold(scope, "daily") && b.Max > 0 && b.Daily == 0 {
		b.Daily = b.Max
		b.Max = 0
	}
	return b
}
