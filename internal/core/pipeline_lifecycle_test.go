package core

import (
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

type stubLifecycle struct {
	accepts bool
	exceeded bool
}

func (s stubLifecycle) AcceptsGovernance() bool { return s.accepts }
func (s stubLifecycle) ColdStartExceeded() bool { return s.exceeded }

func TestPipeline_lifecycleDenyBeforeReady(t *testing.T) {
	doc := &policy.Doc{AgentID: "agent-1", DefaultEffect: "permit"}
	eng, err := policy.NewEngine(doc, "v1")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
	})
	p.SetLifecycle(stubLifecycle{accepts: false})

	req := CanonicalActionRequest{
		AgentID:          "agent-1",
		SessionID:        "s1",
		ToolID:           "search_docs",
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	}
	d := p.Evaluate(req)
	if d.Effect != EffectDeny {
		t.Fatalf("want DENY before READY, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.DaemonNotReady {
		t.Fatalf("want %s, got %s", reasons.DaemonNotReady, d.ReasonCode)
	}
	if d.StructuredDenial == nil || d.StructuredDenial.Code != "DAEMON_NOT_READY" {
		t.Fatalf("expected structured DAEMON_NOT_READY, got %#v", d.StructuredDenial)
	}
}

func TestPipeline_lifecycleAllowsWhenReady(t *testing.T) {
	doc := &policy.Doc{AgentID: "agent-1", DefaultEffect: "permit"}
	eng, err := policy.NewEngine(doc, "v1")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(eng),
		Sessions: session.NewManager(),
	})
	p.SetLifecycle(stubLifecycle{accepts: true})

	req := CanonicalActionRequest{
		AgentID:          "agent-1",
		SessionID:        "s1",
		ToolID:           "search_docs",
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	}
	d := p.Evaluate(req)
	if d.Effect != EffectPermit {
		t.Fatalf("want PERMIT when READY, got %s (%s)", d.Effect, d.ReasonCode)
	}
}
