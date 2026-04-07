package core

import (
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

func BenchmarkPipelineEvaluateSimplePermit(b *testing.B) {
	doc := &policy.Doc{
		FarameshVersion: "1.0",
		AgentID:         "bench-simple",
		DefaultEffect:   "deny",
		Rules: []policy.Rule{
			{ID: "allow-http", Match: policy.Match{Tool: "http/get"}, Effect: "permit", ReasonCode: "RULE_PERMIT"},
			{ID: "deny-shell", Match: policy.Match{Tool: "shell/*"}, Effect: "deny", ReasonCode: "RULE_DENY"},
		},
	}

	engine, err := policy.NewEngine(doc, "bench-simple")
	if err != nil {
		b.Fatalf("compile benchmark policy: %v", err)
	}

	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	req := CanonicalActionRequest{
		AgentID:   "bench-agent",
		SessionID: "bench-session",
		ToolID:    "http/get",
		Args: map[string]any{
			"endpoint": "https://safe.example",
		},
		Timestamp: time.Date(2026, time.April, 6, 12, 0, 0, 0, time.UTC),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d := p.Evaluate(req)
		if d.Effect != EffectPermit {
			b.Fatalf("unexpected effect: %s", d.Effect)
		}
	}
}
