package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const sessionWritePolicy = `
faramesh-version: "1.0"
agent-id: "session-write-agent"

rules:
  - id: permit-session-write
    match:
      tool: "session/write*"
    effect: permit
    reason: "session write permitted"

  - id: permit-other
    match:
      tool: "*"
    effect: permit
    reason: "permit everything else"

default_effect: deny
`

const sessionIntentPolicy = `
faramesh-version: "1.0"
agent-id: "session-intent-agent"

rules:
  - id: permit-session-write
    match:
      tool: "session/write*"
    effect: permit
    reason: "session write permitted"

  - id: defer-admin-on-high-risk-intent
    match:
      tool: "admin/*"
      when: "session.intent_class == 'potentially_adversarial' || session.intent_class == 'high_risk_intent'"
    effect: defer
    reason: "high-risk intent requires approval"

  - id: permit-admin
    match:
      tool: "admin/*"
    effect: permit
    reason: "admin action permitted"

  - id: permit-other
    match:
      tool: "*"
    effect: permit
    reason: "permit everything else"

default_effect: deny
`

func buildSessionWritePipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(sessionWritePolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:          policy.NewAtomicEngine(eng),
		Sessions:        session.NewManager(),
		SessionGovernor: session.NewGovernor(),
		Defers:          deferwork.NewWorkflow(""),
	})
}

func buildSessionIntentPipeline(t *testing.T) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(sessionIntentPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:          policy.NewAtomicEngine(eng),
		Sessions:        session.NewManager(),
		SessionGovernor: session.NewGovernor(),
		Defers:          deferwork.NewWorkflow(""),
	})
}

func sessionWriteReq(agent, tool, key string, value any) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    "session-write-" + tool + "-" + time.Now().Format("150405.000000"),
		AgentID:   agent,
		SessionID: "session-write-sess",
		ToolID:    tool,
		Args: map[string]any{
			"key":   key,
			"value": value,
		},
		Timestamp: time.Now(),
	}
}

func TestSessionWriteGovernorAllowsAgentNamespace(t *testing.T) {
	p := buildSessionWritePipeline(t)
	d := p.Evaluate(sessionWriteReq("agent-1", "session/write", "agent-1/profile/theme", "dark"))
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestSessionWriteGovernorBlocksNamespaceViolation(t *testing.T) {
	p := buildSessionWritePipeline(t)
	d := p.Evaluate(sessionWriteReq("agent-1", "session/write", "agent-2/profile/theme", "dark"))
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.SessionStateNamespaceViolation {
		t.Fatalf("expected reason %s, got %s", reasons.SessionStateNamespaceViolation, d.ReasonCode)
	}
}

func TestSessionWriteGovernorBlocksInjectionLikeValue(t *testing.T) {
	p := buildSessionWritePipeline(t)
	d := p.Evaluate(sessionWriteReq("agent-1", "session/write", "agent-1/profile/note", "hello; DROP TABLE sessions"))
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.CodeExecutionInArgs {
		t.Fatalf("expected reason %s, got %s", reasons.CodeExecutionInArgs, d.ReasonCode)
	}
}

func TestSessionWriteGovernorBlocksSecretLikeValue(t *testing.T) {
	p := buildSessionWritePipeline(t)
	d := p.Evaluate(sessionWriteReq("agent-1", "session/write", "agent-1/creds/token", "password=supersecret"))
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.HighEntropySecret {
		t.Fatalf("expected reason %s, got %s", reasons.HighEntropySecret, d.ReasonCode)
	}
}

func TestSessionWriteGovernorDoesNotAffectNonSessionTools(t *testing.T) {
	p := buildSessionWritePipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "non-session-tool",
		AgentID:   "agent-1",
		SessionID: "session-write-sess",
		ToolID:    "profile/update",
		Args: map[string]any{
			"key":   "agent-2/profile/theme",
			"value": "dark",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("expected permit for non-session tool, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestSessionIntentClassWriteInfluencesPolicyEvaluation(t *testing.T) {
	p := buildSessionIntentPipeline(t)
	write := CanonicalActionRequest{
		CallID:    "session-intent-write",
		AgentID:   "agent-1",
		SessionID: "session-write-sess",
		ToolID:    "session/write",
		Args: map[string]any{
			"key":         "agent-1/intent/class",
			"value":       "high_risk_intent",
			"ttl_seconds": 300,
		},
		Timestamp: time.Now(),
	}
	if d := p.Evaluate(write); d.Effect != EffectPermit {
		t.Fatalf("expected permit writing intent class, got %s (%s)", d.Effect, d.Reason)
	}

	decision := p.Evaluate(CanonicalActionRequest{
		CallID:    "admin-call-after-intent",
		AgentID:   "agent-1",
		SessionID: "session-write-sess",
		ToolID:    "admin/delete_customer",
		Args:      map[string]any{"id": "cust-123"},
		Timestamp: time.Now(),
	})
	if decision.Effect != EffectDefer {
		t.Fatalf("expected admin call to defer after high-risk intent, got %s (%s)", decision.Effect, decision.Reason)
	}
}

func TestSessionIntentClassWriteRejectsUnknownClass(t *testing.T) {
	p := buildSessionIntentPipeline(t)
	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "session-intent-write-invalid",
		AgentID:   "agent-1",
		SessionID: "session-write-sess",
		ToolID:    "session/write",
		Args: map[string]any{
			"key":   "agent-1/intent/class",
			"value": "totally_safe",
		},
		Timestamp: time.Now(),
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny for unsupported intent class, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.SessionStateWriteBlocked {
		t.Fatalf("expected reason %s, got %s", reasons.SessionStateWriteBlocked, d.ReasonCode)
	}
}
