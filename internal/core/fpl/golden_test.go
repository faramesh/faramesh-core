package fpl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenFPLFile(t *testing.T) {
	path := filepath.Join("testdata", "golden.fpl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	out, err := ParseAndCompileRules(string(raw))
	if err != nil {
		t.Fatalf("parse+compile golden: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 compiled rules, got %d", len(out))
	}
	if out[0].Effect != EffectPermit || out[0].Tool != "safe/read" {
		t.Fatalf("rule0: %+v", out[0])
	}
	if out[1].Effect != EffectDeny || !out[1].StrictDeny || out[1].Tool != "shell/exec" {
		t.Fatalf("rule1: %+v", out[1])
	}
	if out[2].Effect != EffectDefer || out[2].Tool != "payment/charge" {
		t.Fatalf("rule2: %+v", out[2])
	}
	if out[2].Notify == nil || out[2].Notify.Target != "finance" {
		t.Fatalf("rule2 notify: %+v", out[2].Notify)
	}
}

func TestStructuredFPLFile(t *testing.T) {
	path := filepath.Join("testdata", "structured.fpl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read structured: %v", err)
	}

	doc, err := ParseDocument(string(raw))
	if err != nil {
		t.Fatalf("parse structured: %v", err)
	}

	if len(doc.Agents) != 1 {
		t.Fatalf("expected 1 agent block, got %d", len(doc.Agents))
	}
	ag := doc.Agents[0]
	if ag.ID != "payment-bot" {
		t.Fatalf("agent ID: %q", ag.ID)
	}
	if ag.Default != "deny" {
		t.Fatalf("default: %q", ag.Default)
	}
	if ag.Model != "gpt-4o" {
		t.Fatalf("model: %q", ag.Model)
	}
	if ag.Framework != "langgraph" {
		t.Fatalf("framework: %q", ag.Framework)
	}

	if len(ag.Budgets) != 1 {
		t.Fatalf("expected 1 budget, got %d", len(ag.Budgets))
	}
	bgt := ag.Budgets[0]
	if bgt.ID != "session" || bgt.Max != 500 || bgt.Daily != 2000 || bgt.MaxCalls != 100 {
		t.Fatalf("budget: %+v", bgt)
	}

	if len(ag.Phases) != 2 {
		t.Fatalf("expected 2 phases, got %d", len(ag.Phases))
	}
	if ag.Phases[0].ID != "intake" || len(ag.Phases[0].Tools) != 2 {
		t.Fatalf("phase0: %+v", ag.Phases[0])
	}

	if len(ag.Rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(ag.Rules))
	}
	if ag.Rules[0].Effect != "deny!" || ag.Rules[0].Tool != "shell/*" {
		t.Fatalf("rule0: %+v", ag.Rules[0])
	}

	if len(ag.Delegates) != 1 || ag.Delegates[0].TargetAgent != "fraud-check-bot" {
		t.Fatalf("delegates: %+v", ag.Delegates)
	}

	if len(ag.Ambients) != 1 {
		t.Fatalf("expected 1 ambient, got %d", len(ag.Ambients))
	}
	if ag.Ambients[0].Limits["max_customers_per_day"] != "1000" {
		t.Fatalf("ambient: %+v", ag.Ambients[0])
	}

	if len(ag.Selectors) != 1 || ag.Selectors[0].ID != "account" {
		t.Fatalf("selectors: %+v", ag.Selectors)
	}

	if len(ag.Credentials) != 1 || ag.Credentials[0].ID != "stripe" {
		t.Fatalf("credentials: %+v", ag.Credentials)
	}
	if len(ag.Credentials[0].Scope) != 2 {
		t.Fatalf("credential scope: %+v", ag.Credentials[0].Scope)
	}

	if len(doc.Systems) != 1 || doc.Systems[0].ID != "global" {
		t.Fatalf("systems: %+v", doc.Systems)
	}
	if doc.Systems[0].MaxOutputBytes != 1048576 {
		t.Fatalf("max_output_bytes: %d", doc.Systems[0].MaxOutputBytes)
	}

	// Compile the document to IR.
	ir, err := CompileDocument(doc)
	if err != nil {
		t.Fatalf("compile document: %v", err)
	}
	if len(ir.Agents) != 1 {
		t.Fatalf("IR agents: %d", len(ir.Agents))
	}
	if len(ir.Agents[0].Rules) != 4 {
		t.Fatalf("IR agent rules: %d", len(ir.Agents[0].Rules))
	}
	if ir.Agents[0].Rules[0].StrictDeny != true {
		t.Fatalf("IR rule0 strict: %v", ir.Agents[0].Rules[0].StrictDeny)
	}
}

func TestDecompileToFPL(t *testing.T) {
	rules := []DecompileRule{
		{Effect: "deny", Tool: "shell/*", StrictDeny: true, Reason: "never shell"},
		{Effect: "defer", Tool: "stripe/refund", When: "args.amount > 500", Notify: "finance", Reason: "high value"},
		{Effect: "permit", Tool: "stripe/*", When: "args.amount <= 500"},
	}
	budget := &DecompileBudget{SessionUSD: 500, DailyUSD: 2000}
	delegates := []DecompileDelegate{{TargetAgent: "fraud-check-bot", Scope: "refund", TTL: "5m", Ceiling: "approval"}}
	ambient := &DecompileAmbient{
		Limits: map[string]string{
			"max_customers_per_day": "1000",
		},
		OnExceed: "defer",
	}
	selectors := []DecompileSelector{{ID: "account", Source: "https://context.internal/account", Cache: "60s", OnUnavailable: "deny", OnTimeout: "defer"}}
	phases := map[string][]string{
		"intake": {"read_customer", "get_order"},
	}

	out := DecompileToFPL("payment-bot", "deny", nil, phases, rules, budget, delegates, ambient, selectors)

	if out == "" {
		t.Fatal("decompile returned empty")
	}

	// Round-trip: parse the decompiled output.
	doc, err := ParseDocument(out)
	if err != nil {
		t.Fatalf("re-parse decompiled: %v", err)
	}
	if len(doc.Agents) != 1 || doc.Agents[0].ID != "payment-bot" {
		t.Fatalf("round-trip agent: %+v", doc.Agents)
	}
	ag := doc.Agents[0]
	if len(ag.Delegates) != 1 || ag.Delegates[0].TargetAgent != "fraud-check-bot" {
		t.Fatalf("round-trip delegates: %+v", ag.Delegates)
	}
	if len(ag.Ambients) != 1 || ag.Ambients[0].Limits["max_customers_per_day"] != "1000" {
		t.Fatalf("round-trip ambient: %+v", ag.Ambients)
	}
	if len(ag.Selectors) != 1 || ag.Selectors[0].ID != "account" || ag.Selectors[0].OnTimeout != "defer" {
		t.Fatalf("round-trip selectors: %+v", ag.Selectors)
	}
}
