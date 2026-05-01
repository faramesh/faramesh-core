package dpr

import (
	"testing"
	"time"
)

func TestRecordCanonicalizationModes(t *testing.T) {
	rec := &Record{
		SchemaVersion:     SchemaVersion,
		CARVersion:        "car/1.0",
		RecordID:          "rec-1",
		PrevRecordHash:    GenesisPrevHash("agent-1"),
		AgentID:           "agent-1",
		SessionID:         "sess-1",
		ToolID:            "tool-1",
		InterceptAdapter:  "sdk",
		Effect:            "PERMIT",
		MatchedRuleID:     "rule-1",
		ReasonCode:        "RULE_PERMIT",
		Reason:            "ok",
		PolicyVersion:     "v1",
		ArgsStructuralSig: "sig-1",
		CreatedAt:         time.Unix(1, 0).UTC(),
	}

	legacy := string(rec.CanonicalBytes())
	if legacy == "" {
		t.Fatalf("expected legacy canonical bytes")
	}

	rec.CanonicalizationAlgorithm = CanonicalizationJCS
	jcs := string(rec.CanonicalBytes())
	if jcs == "" {
		t.Fatalf("expected jcs canonical bytes")
	}
	if legacy == jcs {
		t.Fatalf("expected legacy and jcs canonical bytes to differ")
	}

	rec.CanonicalizationAlgorithm = ""
	if got := string(rec.CanonicalBytes()); got != legacy {
		t.Fatalf("empty canonicalization algorithm should default to legacy bytes")
	}
}
