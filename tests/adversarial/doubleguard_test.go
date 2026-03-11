package adversarial_test

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

// ──────────────────────────────────────────────────────────────────────────────
// Double-Govern: Same CAR evaluated twice produces same decision.
// ──────────────────────────────────────────────────────────────────────────────
func TestDoubleGuard_SameDecision(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-danger", Match: policy.Match{Tool: "danger/*"}, Effect: "deny"},
		{ID: "allow-safe", Match: policy.Match{Tool: "safe/*"}, Effect: "permit"},
	}, nil)

	tools := []struct {
		tool   string
		expect core.Effect
	}{
		{"danger/action", core.EffectDeny},
		{"safe/read", core.EffectPermit},
		{"unknown/tool", core.EffectDeny},
	}

	for _, tc := range tools {
		car := testCAR(tc.tool, map[string]any{"key": "value"})

		d1 := p.Evaluate(car)
		d2 := p.Evaluate(car)

		if d1.Effect != d2.Effect {
			t.Errorf("tool %q: first=%s, second=%s — governance is non-deterministic",
				tc.tool, d1.Effect, d2.Effect)
		}
		if d1.Effect != tc.expect {
			t.Errorf("tool %q: want %s, got %s", tc.tool, tc.expect, d1.Effect)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Double-Govern: Resubmission generates distinct DPR records.
// ──────────────────────────────────────────────────────────────────────────────
func TestDoubleGuard_DistinctDPRRecords(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "allow-all", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	car := testCAR("any/tool", nil)
	d1 := p.Evaluate(car)
	d2 := p.Evaluate(car)

	// Each evaluation must produce a unique DPR record.
	if d1.DPRRecordID != "" && d2.DPRRecordID != "" && d1.DPRRecordID == d2.DPRRecordID {
		t.Error("double-evaluation produced identical DPR record IDs — audit trail compromised")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Double-Govern: Concurrent evaluation doesn't corrupt state.
// ──────────────────────────────────────────────────────────────────────────────
func TestDoubleGuard_ConcurrentEvaluation(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-danger", Match: policy.Match{Tool: "danger/*"}, Effect: "deny"},
		{ID: "allow-rest", Match: policy.Match{Tool: "*"}, Effect: "permit"},
	}, nil)

	const goroutines = 50
	results := make(chan core.Decision, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			car := testCAR("danger/action", nil)
			results <- p.Evaluate(car)
		}()
	}

	for i := 0; i < goroutines; i++ {
		d := <-results
		if d.Effect != core.EffectDeny {
			t.Errorf("concurrent eval %d: want DENY, got %s", i, d.Effect)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Double-Govern: Interleaved permit/deny doesn't bleed state.
// ──────────────────────────────────────────────────────────────────────────────
func TestDoubleGuard_InterleavedDecisions(t *testing.T) {
	p := testPipeline(t, []policy.Rule{
		{ID: "deny-bad", Match: policy.Match{Tool: "bad/*"}, Effect: "deny"},
		{ID: "allow-good", Match: policy.Match{Tool: "good/*"}, Effect: "permit"},
	}, nil)

	// Alternate between denied and permitted calls.
	for i := 0; i < 100; i++ {
		if i%2 == 0 {
			d := p.Evaluate(testCAR("bad/action", nil))
			if d.Effect != core.EffectDeny {
				t.Fatalf("iteration %d: bad tool got %s", i, d.Effect)
			}
		} else {
			d := p.Evaluate(testCAR("good/action", nil))
			if d.Effect != core.EffectPermit {
				t.Fatalf("iteration %d: good tool got %s", i, d.Effect)
			}
		}
	}
}
