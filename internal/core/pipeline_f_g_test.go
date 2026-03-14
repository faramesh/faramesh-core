package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const fgPolicy = `
faramesh-version: "1.0"
agent-id: "fg-test-agent"

rules:
  - id: deny-dangerous-tools
    match:
      tool: "danger/*"
    effect: deny
    reason: "dangerous tool denied"
    reason_code: RULE_DENY

  - id: defer-on-deny-burst
    match:
      tool: "*"
      when: "deny_count_within(120) >= 2"
    effect: defer
    reason: "too many denies in short window"
    reason_code: SESSION_ATTEMPT_LIMIT

  - id: deny-large-recipient-array
    match:
      tool: "email/send"
      when: "args_array_len('recipients') > 3"
    effect: deny
    reason: "too many recipients"
    reason_code: ARRAY_CARDINALITY_EXCEEDED

  - id: deny-external-domain-recipient
    match:
      tool: "email/send"
      when: "args_array_any_match('recipients', '*@external.com')"
    effect: deny
    reason: "external recipient denied"
    reason_code: RULE_DENY

  - id: permit-default
    match:
      tool: "*"
    effect: permit
    reason: "default permit"

default_effect: deny
`

func buildFGPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(fgPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

func fgReq(agent, tool string, args map[string]any) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    "fg-" + tool + "-" + time.Now().Format("150405.000000"),
		AgentID:   agent,
		SessionID: "fg-sess",
		ToolID:    tool,
		Args:      args,
		Timestamp: time.Now(),
	}
}

func TestCategoryFDenyEscalationControl(t *testing.T) {
	p := buildFGPipeline(t)
	const agent = "agent-f"

	d1 := p.Evaluate(fgReq(agent, "danger/one", nil))
	if d1.Effect != EffectDeny {
		t.Fatalf("first dangerous call: want DENY, got %s", d1.Effect)
	}
	d2 := p.Evaluate(fgReq(agent, "danger/two", nil))
	if d2.Effect != EffectDeny {
		t.Fatalf("second dangerous call: want DENY, got %s", d2.Effect)
	}

	d3 := p.Evaluate(fgReq(agent, "safe/read", nil))
	if d3.Effect != EffectDefer {
		t.Fatalf("deny burst escalation: want DEFER, got %s (%s)", d3.Effect, d3.Reason)
	}
}

func TestCategoryGArrayCardinalityControl(t *testing.T) {
	p := buildFGPipeline(t)
	const agent = "agent-g-cardinality"

	d := p.Evaluate(fgReq(agent, "email/send", map[string]any{
		"recipients": []any{"a@company.com", "b@company.com", "c@company.com", "d@company.com"},
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("array cardinality guard: want DENY, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestCategoryGArrayPatternControl(t *testing.T) {
	p := buildFGPipeline(t)
	const agent = "agent-g-pattern"

	d := p.Evaluate(fgReq(agent, "email/send", map[string]any{
		"recipients": []any{"ops@company.com", "vendor@external.com"},
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("array pattern guard: want DENY, got %s (%s)", d.Effect, d.Reason)
	}
}
