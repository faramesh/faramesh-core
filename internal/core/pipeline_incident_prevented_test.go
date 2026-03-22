package core

import (
	"testing"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

func TestDenyWithIncidentMetadataIncrementsPreventedMetric(t *testing.T) {
	doc, version, err := policy.LoadBytes([]byte(`
faramesh-version: "1.0"
agent-id: "incident-agent"
rules:
  - id: block-destructive
    match:
      tool: "shell/rm"
    effect: deny
    reason: "destructive command blocked"
    reason_code: RULE_DENY
    incident_category: destructive_command
    incident_severity: high
default_effect: deny
`))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		t.Fatal(err)
	}

	before := observe.Default.TotalIncidentsPrevented()

	p := NewPipeline(Config{
		Engine:   policy.NewAtomicEngine(engine),
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(""),
	})

	d := p.Evaluate(CanonicalActionRequest{
		CallID:    "inc-1",
		AgentID:   "agent-1",
		SessionID: "session-1",
		ToolID:    "shell/rm",
		Args:      map[string]any{"path": "/"},
	})
	if d.Effect != EffectDeny {
		t.Fatalf("expected deny, got %v", d.Effect)
	}
	if d.IncidentCategory != "destructive_command" || d.IncidentSeverity != "high" {
		t.Fatalf("incident metadata: %+v", d)
	}

	after := observe.Default.TotalIncidentsPrevented()
	if after != before+1 {
		t.Fatalf("expected incident prevented counter +1, before=%d after=%d", before, after)
	}
}
