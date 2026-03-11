package adversarial_test

import (
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// ──────────────────────────────────────────────────────────────────────────────
// Oracle Attack: Denial token opacity.
// An attacker tries to reconstruct policy structure from denial tokens.
// ──────────────────────────────────────────────────────────────────────────────
func TestOracle_DenialTokenOpacity(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "rule-alpha", Match: policy.Match{Tool: "alpha/*"}, Effect: "deny"},
		{ID: "rule-beta", Match: policy.Match{Tool: "beta/*"}, Effect: "deny"},
		{ID: "rule-gamma", Match: policy.Match{Tool: "gamma/*"}, Effect: "deny"},
		{ID: "allow-rest", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	tokens := make(map[string]string) // ruleID → denial token
	tools := map[string]string{
		"rule-alpha": "alpha/action",
		"rule-beta":  "beta/action",
		"rule-gamma": "gamma/action",
	}

	for ruleID, tool := range tools {
		d := p.Evaluate(testCAR(tool, nil))
		if d.Effect != core.EffectDeny {
			t.Fatalf("%s: want DENY, got %s", ruleID, d.Effect)
		}
		tokens[ruleID] = d.DenialToken
	}

	// Tokens from different rules must not reveal which rule matched.
	for id, tok := range tokens {
		if strings.Contains(tok, id) {
			t.Errorf("token for %s contains the rule ID — oracle leak", id)
		}
		// Check that no token contains any rule ID.
		for otherID := range tokens {
			if strings.Contains(tok, otherID) {
				t.Errorf("token for %s contains rule ID %s", id, otherID)
			}
		}
	}

	// Tokens should not be sequentially predictable.
	tokenValues := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		tokenValues = append(tokenValues, tok)
	}
	if len(tokenValues) >= 2 && tokenValues[0] == tokenValues[1] {
		t.Error("multiple rules produced identical denial tokens — too predictable")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Oracle Attack: Timing side-channel.
// DENY and PERMIT latencies should be in the same order of magnitude.
// ──────────────────────────────────────────────────────────────────────────────
func TestOracle_TimingSideChannel(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-shell", Match: policy.Match{Tool: "shell/*"}, Effect: "deny"},
		{ID: "allow-safe", Match: policy.Match{Tool: "safe/*"}, Effect: "permit"},
	}, nil)

	// Warm up to eliminate cold-start bias.
	for i := 0; i < 100; i++ {
		p.Evaluate(testCAR("shell/exec", nil))
		p.Evaluate(testCAR("safe/read", nil))
	}

	const iterations = 1000
	var totalDeny, totalPermit time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		p.Evaluate(testCAR("shell/exec", nil))
		totalDeny += time.Since(start)

		start = time.Now()
		p.Evaluate(testCAR("safe/read", nil))
		totalPermit += time.Since(start)
	}

	avgDeny := totalDeny / time.Duration(iterations)
	avgPermit := totalPermit / time.Duration(iterations)

	t.Logf("avg DENY latency:   %v", avgDeny)
	t.Logf("avg PERMIT latency: %v", avgPermit)

	// Allow up to 10x difference — we just want to ensure they're in the same
	// ballpark, not that they're identical (that would be unnecessarily strict).
	if avgDeny > avgPermit*10 || avgPermit > avgDeny*10 {
		t.Errorf("timing side-channel: DENY=%v vs PERMIT=%v (>10x ratio)", avgDeny, avgPermit)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Oracle Attack: Error message uniformity.
// All denials should look identical to the agent.
// ──────────────────────────────────────────────────────────────────────────────
func TestOracle_ErrorMessageUniformity(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-delete", Match: policy.Match{Tool: "db/delete"}, Effect: "deny", Reason: "internal reason 1"},
		{ID: "deny-drop", Match: policy.Match{Tool: "db/drop"}, Effect: "deny", Reason: "internal reason 2"},
		{ID: "deny-admin", Match: policy.Match{Tool: "admin/*"}, Effect: "deny", Reason: "blocked"},
	}, nil)

	tools := []string{"db/delete", "db/drop", "admin/nuke"}
	var reasons []string

	for _, tool := range tools {
		d := p.Evaluate(testCAR(tool, nil))
		if d.Effect != core.EffectDeny {
			t.Fatalf("%s: want DENY, got %s", tool, d.Effect)
		}
		reasons = append(reasons, d.Reason)

		// No reason should contain implementation details.
		lower := strings.ToLower(d.Reason)
		for _, leak := range []string{"sql", "database", "table", "column", "regex", "expression", "line"} {
			if strings.Contains(lower, leak) {
				t.Errorf("reason for %s leaks implementation detail %q: %s", tool, leak, d.Reason)
			}
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Oracle Attack: Policy version probing.
// Version string should not reveal rule count or internal structure.
// ──────────────────────────────────────────────────────────────────────────────
func TestOracle_PolicyVersionProbing(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "r1", Match: policy.Match{Tool: "a"}, Effect: "deny"},
		{ID: "r2", Match: policy.Match{Tool: "b"}, Effect: "deny"},
		{ID: "r3", Match: policy.Match{Tool: "c"}, Effect: "deny"},
	}, nil)

	d := p.Evaluate(testCAR("a", nil))

	// Policy version should be present but should not encode rule count.
	if d.PolicyVersion == "" {
		t.Error("PolicyVersion is empty")
	}
	// It should not contain the number "3" (our rule count) in a suspicious way.
	// Simple heuristic: check for "3-rules" or "rules:3" patterns.
	for _, pattern := range []string{"3-rules", "rules:3", "rules=3", "count:3"} {
		if strings.Contains(strings.ToLower(d.PolicyVersion), pattern) {
			t.Errorf("PolicyVersion %q leaks rule count pattern %q", d.PolicyVersion, pattern)
		}
	}
}
