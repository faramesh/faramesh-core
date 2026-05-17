package core

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/governstate"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func TestPipelineAgentRedactionDeniesOnMissingPath(t *testing.T) {
	p := buildPipelineFromFPL(t, `
agent "bot" {
  default deny
  rules { permit * }
}
`, false)
	p.hmacKey = []byte("test-hmac-key-32-bytes-long!!")
	p.agentGovernance = map[string]agentgov.Spec{
		"bot": {Redactions: []agentgov.Redaction{{Tool: "*", Paths: []string{"secret"}}}},
	}

	d := p.Evaluate(CanonicalActionRequest{
		AgentID:          "bot",
		SessionID:        "s1",
		ToolID:           "tool/x",
		Args:             map[string]any{"other": "value"},
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	})
	if d.Effect != EffectDeny || d.ReasonCode != reasons.RedactionFailure {
		t.Fatalf("effect=%s code=%s", d.Effect, d.ReasonCode)
	}
}

func TestPipelineAgentRateLimitExceeded(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal")
	wal, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	p := buildPipelineFromFPL(t, `
agent "bot" {
  default deny
  rules { permit * }
}
`, false)
	p.wal = wal
	p.agentGovernance = map[string]agentgov.Spec{
		"bot": {RateLimits: []agentgov.RateLimit{{Tool: "tool/x", Limit: 1, Window: "minute"}}},
	}
	p.governState = governstate.New()

	req := CanonicalActionRequest{
		AgentID:          "bot",
		SessionID:        "s1",
		ToolID:           "tool/x",
		Args:             map[string]any{},
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	}
	if d := p.Evaluate(req); d.Effect != EffectPermit {
		t.Fatalf("first call: %s %s", d.Effect, d.ReasonCode)
	}
	d := p.Evaluate(req)
	if d.Effect != EffectDeny || d.ReasonCode != reasons.RateExceeded {
		t.Fatalf("second call: effect=%s code=%s", d.Effect, d.ReasonCode)
	}
}

func TestPipelineBudgetWarnAtDefers(t *testing.T) {
	p := buildPipelineFromFPL(t, `
agent "bot" {
  budget session {
    max $10.00
  }
  rules { permit * }
}
`, false)
	p.agentGovernance = map[string]agentgov.Spec{
		"bot": {BudgetWarn: []agentgov.BudgetWarn{{Scope: "session", WarnAt: 0.5}}},
	}
	p.governState = governstate.New()
	sess := p.sessions.Get("bot")
	sess.AddCost(6.0)

	d := p.Evaluate(CanonicalActionRequest{
		AgentID:          "bot",
		SessionID:        "s1",
		ToolID:           "tool/x",
		Args:             map[string]any{},
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	})
	if d.Effect != EffectDefer || d.ReasonCode != reasons.BudgetWarning {
		t.Fatalf("effect=%s code=%s reason=%s", d.Effect, d.ReasonCode, d.Reason)
	}
}

func TestPipelineRedactionHMACBeforeWAL(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal")
	wal, err := dpr.OpenWAL(walPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wal.Close() })

	p := buildPipelineFromFPL(t, `
agent "bot" {
  default deny
  rules { permit * }
}
`, false)
	p.wal = wal
	p.hmacKey = []byte("test-hmac-key-32-bytes-long!!")
	p.agentGovernance = map[string]agentgov.Spec{
		"bot": {Redactions: []agentgov.Redaction{{Tool: "tool/x", Paths: []string{"token"}}}},
	}

	d := p.Evaluate(CanonicalActionRequest{
		AgentID:          "bot",
		SessionID:        "s1",
		ToolID:           "tool/x",
		Args:             map[string]any{"token": "secret-value"},
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	})
	if d.Effect != EffectPermit {
		t.Fatalf("effect=%s", d.Effect)
	}
	var rec *dpr.Record
	if err := wal.Replay(func(r *dpr.Record) error {
		rec = r
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("no wal record")
	}
	token, ok := rec.SelectorSnapshot["token"].(string)
	if !ok || len(token) < 5 || token[:5] != "hmac:" {
		t.Fatalf("expected hmac redacted token in selector snapshot, got %#v", rec.SelectorSnapshot["token"])
	}
}