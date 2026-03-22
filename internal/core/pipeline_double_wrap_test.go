package core

import (
	"sync"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

func TestEvaluateSingleWrapAllowed(t *testing.T) {
	p := newPermitPipeline(t, &dpr.NullWAL{})
	decision := p.Evaluate(CanonicalActionRequest{
		CallID:           "call-single-wrap",
		AgentID:          "agent-single",
		SessionID:        "session-single",
		ToolID:           "tool.echo",
		Args:             map[string]any{"q": "ok"},
		Timestamp:        time.Now(),
		InterceptAdapter: "sdk",
	})
	if decision.Effect != EffectPermit {
		t.Fatalf("expected PERMIT, got %s (%s)", decision.Effect, decision.ReasonCode)
	}
	if decision.ReasonCode == reasons.GovernanceDoubleWrapDenied {
		t.Fatalf("single-wrap should not be denied with %s", reasons.GovernanceDoubleWrapDenied)
	}
}

func TestEvaluateDoubleWrapDenied(t *testing.T) {
	w := &reentrantWAL{callID: "call-double-wrap"}
	p := newPermitPipeline(t, w)
	w.p = p

	_ = p.Evaluate(CanonicalActionRequest{
		CallID:           w.callID,
		AgentID:          "agent-double",
		SessionID:        "session-double",
		ToolID:           "tool.echo",
		Args:             map[string]any{"q": "outer"},
		Timestamp:        time.Now(),
		InterceptAdapter: "sdk",
	})

	if w.nested.Effect != EffectDeny {
		t.Fatalf("expected nested request DENY, got %s", w.nested.Effect)
	}
	if w.nested.ReasonCode != reasons.GovernanceDoubleWrapDenied {
		t.Fatalf("expected reason code %s, got %s", reasons.GovernanceDoubleWrapDenied, w.nested.ReasonCode)
	}
}

func TestEvaluateSeparateRequestsUnaffected(t *testing.T) {
	p := newPermitPipeline(t, &dpr.NullWAL{})

	first := p.Evaluate(CanonicalActionRequest{
		CallID:           "call-separate-1",
		AgentID:          "agent-separate",
		SessionID:        "session-separate",
		ToolID:           "tool.echo",
		Args:             map[string]any{"q": "one"},
		Timestamp:        time.Now(),
		InterceptAdapter: "proxy",
	})
	second := p.Evaluate(CanonicalActionRequest{
		CallID:           "call-separate-2",
		AgentID:          "agent-separate",
		SessionID:        "session-separate",
		ToolID:           "tool.echo",
		Args:             map[string]any{"q": "two"},
		Timestamp:        time.Now(),
		InterceptAdapter: "daemon",
	})

	if first.Effect != EffectPermit || second.Effect != EffectPermit {
		t.Fatalf("expected separate requests to be PERMIT, got %s and %s", first.Effect, second.Effect)
	}
	if first.ReasonCode == reasons.GovernanceDoubleWrapDenied || second.ReasonCode == reasons.GovernanceDoubleWrapDenied {
		t.Fatalf("separate requests should not hit %s", reasons.GovernanceDoubleWrapDenied)
	}
}

func newPermitPipeline(t *testing.T, wal dpr.Writer) *Pipeline {
	t.Helper()
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: test-agent
default_effect: permit
rules: []
`))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engine),
		WAL:      wal,
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})
}

type reentrantWAL struct {
	p         *Pipeline
	callID    string
	mu        sync.Mutex
	triggered bool
	nested    Decision
}

func (w *reentrantWAL) Write(rec *dpr.Record) error {
	w.mu.Lock()
	if w.triggered {
		w.mu.Unlock()
		return nil
	}
	w.triggered = true
	w.mu.Unlock()
	w.nested = w.p.Evaluate(CanonicalActionRequest{
		CallID:           w.callID,
		AgentID:          rec.AgentID,
		SessionID:        rec.SessionID,
		ToolID:           rec.ToolID,
		Args:             map[string]any{"q": "nested"},
		Timestamp:        time.Now(),
		InterceptAdapter: rec.InterceptAdapter,
	})
	return nil
}

func (w *reentrantWAL) Close() error {
	return nil
}
