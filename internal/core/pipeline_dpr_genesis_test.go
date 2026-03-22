package core

import (
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

func TestDPRGenesisCreatedOnFirstRecord(t *testing.T) {
	p := NewPipeline(Config{})
	rec := p.buildRecord(CanonicalActionRequest{
		AgentID:          "agent-ak",
		SessionID:        "sess-1",
		ToolID:           "tool/read",
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	}, Decision{
		Effect:        EffectPermit,
		ReasonCode:    reasons.RulePermit,
		PolicyVersion: "test",
	}, nil)

	want := dpr.GenesisPrevHash("agent-ak")
	if rec.PrevRecordHash != want {
		t.Fatalf("first record prev hash should be genesis marker: got %q want %q", rec.PrevRecordHash, want)
	}
}

func TestDPRSubsequentRecordsRequirePrevHashContinuity(t *testing.T) {
	p := NewPipeline(Config{})
	first := p.buildRecord(CanonicalActionRequest{
		AgentID:          "agent-ak",
		SessionID:        "sess-1",
		ToolID:           "tool/read",
		InterceptAdapter: "sdk",
		Timestamp:        time.Now(),
	}, Decision{
		Effect:        EffectPermit,
		ReasonCode:    reasons.RulePermit,
		PolicyVersion: "test",
	}, nil)

	second := p.buildRecord(CanonicalActionRequest{
		AgentID:          "agent-ak",
		SessionID:        "sess-2",
		ToolID:           "tool/write",
		InterceptAdapter: "sdk",
		Timestamp:        time.Now().Add(time.Millisecond),
	}, Decision{
		Effect:        EffectPermit,
		ReasonCode:    reasons.RulePermit,
		PolicyVersion: "test",
	}, nil)

	if second.PrevRecordHash != first.RecordHash {
		t.Fatalf("subsequent record prev hash must match prior record hash: got %q want %q", second.PrevRecordHash, first.RecordHash)
	}
}
