package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

// seqPolicy is a minimal policy used for sequence enforcement tests.
const seqPolicy = `
faramesh-version: "1.0"
agent-id: "test-agent"

rules:
  - id: defer-delete-after-exfil
    match:
      tool: "delete_*"
      when: "history_contains_within('http/post', 60)"
    effect: defer
    reason: "Exfil then delete pattern detected"
    reason_code: SEQUENCE_EXFIL_DETECTED

  - id: deny-shell-sequence
    match:
      tool: "shell/*"
      when: "history_sequence('read_file', 'http/post')"
    effect: deny
    reason: "Dangerous trajectory: read + exfil before shell"
    reason_code: SEQUENCE_TRAJECTORY_DANGEROUS

  - id: defer-stripe-burst
    match:
      tool: "stripe/*"
      when: "history_tool_count('stripe/*') >= 3"
    effect: defer
    reason: "Stripe burst anomaly"
    reason_code: SEQUENCE_RATE_ANOMALY

  - id: default-permit
    match:
      tool: "*"
    effect: permit
    reason: "Default permit"

default_effect: deny
`

func buildSeqPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(seqPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   eng,
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func req(agent, tool string, args map[string]any) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    "test-" + tool,
		AgentID:   agent,
		SessionID: "sess1",
		ToolID:    tool,
		Args:      args,
		Timestamp: time.Now(),
	}
}

// TestSequenceExfilThenDelete verifies the exfil→delete pattern is deferred.
func TestSequenceExfilThenDelete(t *testing.T) {
	p := buildSeqPipeline(t)
	const agent = "agent-exfil"

	// Step 1: http/post (permit, no history yet)
	d1 := p.Evaluate(req(agent, "http/post", nil))
	if d1.Effect != EffectPermit {
		t.Fatalf("step1 http/post: want PERMIT, got %s", d1.Effect)
	}
	// Give history goroutine time to write.
	time.Sleep(5 * time.Millisecond)

	// Step 2: delete_record — should now DEFER because http/post is in history.
	d2 := p.Evaluate(req(agent, "delete_record", nil))
	if d2.Effect != EffectDefer {
		t.Fatalf("step2 delete_record after http/post: want DEFER, got %s (%s)", d2.Effect, d2.Reason)
	}
}

// TestSequenceNaive verifies that without prior http/post, delete is allowed.
func TestSequenceDeleteWithoutExfil(t *testing.T) {
	p := buildSeqPipeline(t)
	const agent = "agent-innocent"

	d := p.Evaluate(req(agent, "delete_record", nil))
	if d.Effect != EffectPermit {
		t.Fatalf("delete without prior exfil: want PERMIT, got %s (%s)", d.Effect, d.Reason)
	}
}

// TestHistorySequenceRule verifies read_file → http/post → shell/exec is denied.
func TestHistorySequenceDangerous(t *testing.T) {
	p := buildSeqPipeline(t)
	const agent = "agent-dangerous"

	p.Evaluate(req(agent, "read_file", nil))
	time.Sleep(5 * time.Millisecond)
	p.Evaluate(req(agent, "http/post", nil))
	time.Sleep(5 * time.Millisecond)

	d := p.Evaluate(req(agent, "shell/exec", nil))
	if d.Effect != EffectDeny {
		t.Fatalf("shell after read+post sequence: want DENY, got %s (%s)", d.Effect, d.Reason)
	}
}

// TestHistoryToolCountBurst verifies stripe burst detection.
func TestHistoryToolCountBurst(t *testing.T) {
	p := buildSeqPipeline(t)
	const agent = "agent-burst"

	for i := 0; i < 3; i++ {
		p.Evaluate(req(agent, "stripe/refund", map[string]any{"amount": float64(10)}))
		time.Sleep(5 * time.Millisecond)
	}

	d := p.Evaluate(req(agent, "stripe/charge", nil))
	if d.Effect != EffectDefer {
		t.Fatalf("stripe after 3 stripe calls: want DEFER, got %s (%s)", d.Effect, d.Reason)
	}
}

// TestArgsNullStripping verifies that null-valued keys are stripped.
func TestArgsNullStripping(t *testing.T) {
	args := map[string]any{
		"amount":     float64(500),
		"extra_null": nil,
		"nested": map[string]any{
			"keep": "value",
			"drop": nil,
		},
	}
	canon := canonicalizeArgs(args)
	if _, has := canon["extra_null"]; has {
		t.Fatal("null key 'extra_null' should be stripped")
	}
	nested, _ := canon["nested"].(map[string]any)
	if nested == nil {
		t.Fatal("nested map should be retained")
	}
	if _, has := nested["drop"]; has {
		t.Fatal("null key 'drop' in nested map should be stripped")
	}
	if nested["keep"] != "value" {
		t.Fatal("non-null key 'keep' should be retained")
	}
}

// TestFloatNormalization verifies IEEE 754 artifact elimination.
func TestFloatNormalization(t *testing.T) {
	args := map[string]any{
		"amount": 0.1 + 0.2, // = 0.30000000000000004
	}
	canon := canonicalizeArgs(args)
	v, _ := canon["amount"].(float64)
	// After normalization should equal 0.3 to 9 decimal places.
	if v < 0.29999999 || v > 0.30000001 {
		t.Fatalf("float normalization failed: got %v, want ~0.3", v)
	}
}
