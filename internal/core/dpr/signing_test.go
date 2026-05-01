package dpr

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func testSignedRecord(t *testing.T) *Record {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec := &Record{
		SchemaVersion:             SchemaVersion,
		CARVersion:                "car/1.0",
		CanonicalizationAlgorithm: CanonicalizationJCS,
		RecordID:                  "rec-sign-1",
		PrevRecordHash:            GenesisPrevHash("agent-1"),
		AgentID:                   "agent-1",
		SessionID:                 "sess-1",
		ToolID:                    "tool-1",
		InterceptAdapter:          "sdk",
		Effect:                    "PERMIT",
		MatchedRuleID:             "rule-1",
		ReasonCode:                "RULE_PERMIT",
		Reason:                    "ok",
		PolicyVersion:             "v1",
		ArgsStructuralSig:         "sig-1",
		CreatedAt:                 time.Unix(1, 0).UTC(),
	}
	rec.ComputeHash()
	if err := rec.SignWithEd25519(priv, pub); err != nil {
		t.Fatalf("SignWithEd25519: %v", err)
	}
	return rec
}

func TestVerifyEd25519RequiresValidRecordHash(t *testing.T) {
	rec := testSignedRecord(t)
	rec.RecordHash = "bad"
	ok, err := rec.VerifyEd25519()
	if err == nil {
		t.Fatalf("expected hash mismatch error")
	}
	if ok {
		t.Fatalf("expected signature verification to fail when hash is invalid")
	}
}

func TestVerifyEd25519ValidRecord(t *testing.T) {
	rec := testSignedRecord(t)
	ok, err := rec.VerifyEd25519()
	if err != nil {
		t.Fatalf("VerifyEd25519 error: %v", err)
	}
	if !ok {
		t.Fatalf("expected signature verification to succeed")
	}
}
