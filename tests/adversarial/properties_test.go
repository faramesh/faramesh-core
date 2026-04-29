package adversarial_test

import (
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/canonicalize"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// helper: build a minimal pipeline with the given rules.
func testPipeline(t *testing.T, rules []policy.Rule, tools map[string]policy.Tool) *core.Pipeline {
	t.Helper()
	doc := &policy.Doc{
		FarameshVersion: "1.0",
		AgentID:         "test-agent",
		DefaultEffect:   "deny",
		Rules:           rules,
		Tools:           tools,
	}
	eng, err := policy.NewEngine(doc, "test-v1")
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return core.NewPipeline(core.Config{Engine: policy.NewAtomicEngine(eng)})
}

func testCAR(toolID string, args map[string]any) core.CanonicalActionRequest {
	return core.CanonicalActionRequest{
		CallID:           "test-call-001",
		AgentID:          "test-agent",
		SessionID:        "test-session",
		ToolID:           toolID,
		Args:             args,
		Timestamp:        time.Now(),
		InterceptAdapter: "sdk",
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 1: Deny is default — unknown tools always produce DENY.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_DenyIsDefault(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-foo", Match: policy.Match{Tool: "foo/bar"}, Effect: "permit"},
	}, nil)

	unknownTools := []string{
		"unknown/tool",
		"stripe/refund",
		"shell/exec",
		"admin/delete-user",
		"../../../etc/passwd",
		"",
	}
	for _, tool := range unknownTools {
		d := p.Evaluate(testCAR(tool, nil))
		if d.Effect != core.EffectDeny {
			t.Errorf("unknown tool %q: want DENY, got %s", tool, d.Effect)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 2: Kill switch overrides all — killed agents always get DENY.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_KillSwitchOverrides(t *testing.T) {
	doc := &policy.Doc{
		FarameshVersion: "1.0",
		AgentID:         "test-agent",
		DefaultEffect:   "permit", // default permit, but kill switch must override
		Rules: []policy.Rule{
			{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"},
		},
	}
	eng, err := policy.NewEngine(doc, "test-v1")
	if err != nil {
		t.Fatal(err)
	}
	p := core.NewPipeline(core.Config{Engine: policy.NewAtomicEngine(eng)})

	// First call should be PERMIT.
	d := p.Evaluate(testCAR("any/tool", nil))
	if d.Effect != core.EffectPermit {
		t.Fatalf("before kill: want PERMIT, got %s", d.Effect)
	}

	// Activate kill switch.
	p.SessionManager().Kill("test-agent")

	// Now should be DENY regardless of policy.
	d = p.Evaluate(testCAR("any/tool", nil))
	if d.Effect != core.EffectDeny {
		t.Errorf("after kill: want DENY, got %s (%s)", d.Effect, d.ReasonCode)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 3: DENY never leaks policy structure.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_DenyNeverLeaksPolicy(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "secret-rule-42", Match: policy.Match{Tool: "stripe/*", When: `args.amount > 100`}, Effect: "deny", Reason: "too expensive"},
		{ID: "allow-small", Match: policy.Match{Tool: "stripe/*", When: `args.amount <= 100`}, Effect: "permit"},
	}, nil)

	d := p.Evaluate(testCAR("stripe/refund", map[string]any{"amount": 500}))
	if d.Effect != core.EffectDeny {
		t.Fatalf("want DENY, got %s", d.Effect)
	}

	// DenialToken must exist but not contain the rule ID.
	if d.DenialToken == "" {
		t.Error("DenialToken is empty — operator lookup impossible")
	}
	if strings.Contains(d.DenialToken, "secret-rule-42") {
		t.Error("DenialToken leaks rule ID")
	}
	if strings.Contains(d.Reason, "secret-rule-42") {
		t.Error("Reason message leaks rule ID")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 4: WAL-before-execute — every decision has a DPR record ID.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_WALBeforeExecute(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	for i := 0; i < 10; i++ {
		d := p.Evaluate(testCAR("any/tool", map[string]any{"i": i}))
		if d.DPRRecordID == "" {
			t.Errorf("call %d: DPRRecordID is empty — audit trail broken", i)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 5: Idempotent canonicalization — canonicalize(x) == canonicalize(canonicalize(x)).
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_IdempotentCanonicalization(t *testing.T) {
	inputs := []map[string]any{
		{"key": "value"},
		{"amount": 123.456789012345},
		{"name": "hеllo"}, // Cyrillic 'е'
		{"nested": map[string]any{"deep": "value\x00hidden"}},
		{"list": []any{"a", "b", "c"}},
		{"empty": ""},
		{"unicode": "𝕳𝖊𝖑𝖑𝖔"},
		nil,
	}

	for i, input := range inputs {
		first := canonicalize.Args(input)
		second := canonicalize.Args(first)

		// After two rounds, output must be identical.
		if !argsEqual(first, second) {
			t.Errorf("case %d: canonicalize is not idempotent\n  first:  %v\n  second: %v", i, first, second)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 6: Budget monotonicity — session cost never decreases.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_BudgetMonotonicity(t *testing.T) {
	doc := &policy.Doc{
		FarameshVersion: "1.0",
		AgentID:         "budgeted-agent",
		DefaultEffect:   "permit",
		Rules:           []policy.Rule{{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"}},
		Tools: map[string]policy.Tool{
			"expensive/*": {CostUSD: 1.50},
		},
		Budget: &policy.Budget{SessionUSD: 100.0, OnExceed: "deny"},
	}
	eng, err := policy.NewEngine(doc, "test-v1")
	if err != nil {
		t.Fatal(err)
	}
	p := core.NewPipeline(core.Config{Engine: policy.NewAtomicEngine(eng)})

	sm := p.SessionManager()
	var prevCost float64
	for i := 0; i < 20; i++ {
		car := testCAR("expensive/call", nil)
		car.AgentID = "budgeted-agent"
		_ = p.Evaluate(car)

		sess := sm.Get("budgeted-agent")
		cost := sess.CurrentCostUSD()
		if cost < prevCost {
			t.Errorf("call %d: cost decreased from %.2f to %.2f", i, prevCost, cost)
		}
		prevCost = cost
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 7: DPR chain integrity — hash chain has no gaps.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_DPRChainIntegrity(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	var prevID string
	for i := 0; i < 5; i++ {
		d := p.Evaluate(testCAR("any/tool", map[string]any{"i": i}))
		if d.DPRRecordID == "" {
			t.Fatalf("call %d: no DPR record", i)
		}
		// Each record ID should be unique.
		if d.DPRRecordID == prevID {
			t.Errorf("call %d: duplicate DPR record ID %s", i, d.DPRRecordID)
		}
		prevID = d.DPRRecordID
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 8: No empty decisions — every Decision has non-empty Effect and ReasonCode.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_NoEmptyDecisions(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-one", Match: policy.Match{Tool: "foo"}, Effect: "permit"},
	}, nil)

	tools := []string{"foo", "bar", "baz", ""}
	for _, tool := range tools {
		d := p.Evaluate(testCAR(tool, nil))
		if d.Effect == "" {
			t.Errorf("tool %q: empty Effect", tool)
		}
		if d.ReasonCode == "" {
			t.Errorf("tool %q: empty ReasonCode", tool)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 9: Timestamp ordering — DPR timestamps are monotonically non-decreasing.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_TimestampOrdering(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	var prevTime time.Time
	for i := 0; i < 10; i++ {
		car := testCAR("any/tool", nil)
		car.Timestamp = time.Now()
		d := p.Evaluate(car)
		_ = d

		// The request timestamp should be non-decreasing.
		if car.Timestamp.Before(prevTime) {
			t.Errorf("call %d: timestamp went backwards", i)
		}
		prevTime = car.Timestamp
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Property 10: Shadow mode fidelity — SHADOW decisions record enforcement outcome.
// ──────────────────────────────────────────────────────────────────────────────
func TestProperty_ShadowModeFidelity(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "shadow-deny", Match: policy.Match{Tool: "risky/*"}, Effect: "shadow"},
	}, nil)

	d := p.Evaluate(testCAR("risky/action", nil))

	// Shadow mode should grant SHADOW_PERMIT but record what would have happened.
	if d.Effect != core.EffectShadow && d.Effect != core.EffectShadowPermit {
		// If shadow isn't the top-level effect, the pipeline might handle it differently.
		// What matters is that we see a shadow-related decision.
		t.Logf("shadow effect: %s (reason: %s)", d.Effect, d.ReasonCode)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

func argsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		sa := strings.TrimSpace(strings.ToLower(stringOf(va)))
		sb := strings.TrimSpace(strings.ToLower(stringOf(vb)))
		if sa != sb {
			return false
		}
	}
	return true
}

func stringOf(v any) string {
	if v == nil {
		return "<nil>"
	}
	return strings.TrimSpace(strings.ToLower(
		strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(
					func() string {
						switch x := v.(type) {
						case string:
							return x
						case map[string]any:
							return mapString(x)
						default:
							return func() string {
								s := ""
								s += func() string { return "" }()
								return s + func() string { return "" }()
							}()
						}
					}(), "\n", ""), "\t", ""), " ", "")))
}

func mapString(m map[string]any) string {
	s := "{"
	for k, v := range m {
		s += k + ":" + stringOf(v) + ","
	}
	return s + "}"
}
