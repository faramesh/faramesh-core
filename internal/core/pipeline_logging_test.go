package core

import (
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const timeoutRequiredPolicy = `
faramesh-version: "1.0"
agent-id: "log-timeout-agent"
tools:
  job/run:
    tags: ["timeout:required"]
rules:
  - id: permit-default
    match:
      tool: "*"
    effect: permit
default_effect: deny
`

func TestExecutionTimeoutDenialEmitsStructuredGovernanceLog(t *testing.T) {
	doc, ver, err := policy.LoadBytes([]byte(timeoutRequiredPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	coreObs, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(coreObs)
	p := NewPipeline(Config{
		Engine: policy.NewAtomicEngine(eng),
		Log:    logger,
	})

	_ = p.Evaluate(CanonicalActionRequest{
		CallID:    "call-timeout-1",
		AgentID:   "agent-timeout-1",
		SessionID: "sess-timeout-1",
		ToolID:    "job/run",
		Args:      map[string]any{"x": 1},
		Timestamp: time.Now(),
	})

	entries := logs.FilterMessage("execution timeout denied").All()
	if len(entries) == 0 {
		t.Fatalf("expected execution timeout denied log entry")
	}
	fields := entries[len(entries)-1].ContextMap()
	if fields["log_schema"] != observe.GovernanceLogSchema {
		t.Fatalf("log_schema=%v", fields["log_schema"])
	}
	if fields["log_schema_version"] != observe.GovernanceLogSchemaVersion {
		t.Fatalf("log_schema_version=%v", fields["log_schema_version"])
	}
	if fields["event"] != observe.EventExecutionTimeoutDeny {
		t.Fatalf("event=%v", fields["event"])
	}
	for _, k := range []string{"agent_id", "session_id", "call_id", "tool_id", "reason_code", "reason"} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("missing required field %q in timeout denial structured log", k)
		}
	}
}
