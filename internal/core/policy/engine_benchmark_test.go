package policy

import "testing"

func BenchmarkEngineEvaluateSimplePermit(b *testing.B) {
	doc := &Doc{
		FarameshVersion: "1.0",
		AgentID:         "bench-simple",
		DefaultEffect:   "deny",
		Rules: []Rule{
			{ID: "allow-http", Match: Match{Tool: "http/get"}, Effect: "permit", ReasonCode: "RULE_PERMIT"},
			{ID: "deny-shell", Match: Match{Tool: "shell/*"}, Effect: "deny", ReasonCode: "RULE_DENY"},
		},
	}

	engine, err := NewEngine(doc, "bench-simple")
	if err != nil {
		b.Fatalf("compile benchmark policy: %v", err)
	}

	ctx := EvalContext{
		Args: map[string]any{
			"endpoint": "https://safe.example",
		},
		Time: TimeCtx{Hour: 12, Weekday: 2, Month: 1, Day: 15},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := engine.Evaluate("http/get", ctx)
		if d.Effect != "permit" {
			b.Fatalf("unexpected effect: %s", d.Effect)
		}
	}
}

func BenchmarkEngineEvaluateConditionalMatch(b *testing.B) {
	doc := &Doc{
		FarameshVersion: "1.0",
		AgentID:         "bench-conditional",
		DefaultEffect:   "deny",
		Rules: []Rule{
			{ID: "allow-safe-refund", Match: Match{Tool: "stripe/refund", When: `amount <= 500 && principal.role == "analyst"`}, Effect: "permit", ReasonCode: "RULE_PERMIT"},
			{ID: "defer-large-refund", Match: Match{Tool: "stripe/refund", When: "amount > 500"}, Effect: "defer", ReasonCode: "RULE_DEFER"},
			{ID: "deny-shell", Match: Match{Tool: "shell/*"}, Effect: "deny", ReasonCode: "RULE_DENY"},
		},
	}

	engine, err := NewEngine(doc, "bench-conditional")
	if err != nil {
		b.Fatalf("compile benchmark policy: %v", err)
	}

	ctx := EvalContext{
		Args: map[string]any{
			"amount": 250,
		},
		Principal: &PrincipalCtx{
			Role: "analyst",
		},
		Time: TimeCtx{Hour: 12, Weekday: 2, Month: 1, Day: 15},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := engine.Evaluate("stripe/refund", ctx)
		if d.Effect != "permit" {
			b.Fatalf("unexpected effect: %s", d.Effect)
		}
	}
}
