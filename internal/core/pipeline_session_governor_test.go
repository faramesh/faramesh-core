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
