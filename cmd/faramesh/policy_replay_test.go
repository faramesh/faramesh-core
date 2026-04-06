package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

const replayTestPolicyYAML = `
faramesh-version: "1.0"
agent-id: "replay-test"
default_effect: deny
rules:
  - id: permit-safe-http
    match:
      tool: "http/get"
      when: "args.endpoint == 'https://safe.example'"
    effect: permit
    reason_code: RULE_PERMIT
`

const replayCredentialPolicyFPL = `
agent replay-credential {
	default deny

	credential vault_probe {
		scope vault/probe vault/probe/*
		backend vault
		max_scope payments
	}

	rules {
		permit vault/probe
		permit vault/probe/*
	}
}
`

func TestRunPolicyReplayWALBasicSuccess(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, replayTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:         "r1",
			ToolID:           "http/get",
			Effect:           "PERMIT",
			ReasonCode:       "RULE_PERMIT",
			SelectorSnapshot: map[string]any{"endpoint": "https://safe.example"},
			CreatedAt:        time.Date(2026, time.March, 20, 8, 0, 0, 0, time.UTC),
		},
		{
			RecordID:         "r2",
			ToolID:           "shell/exec",
			Effect:           "DENY",
			ReasonCode:       "UNMATCHED_DENY",
			SelectorSnapshot: map[string]any{"cmd": "echo test"},
			CreatedAt:        time.Date(2026, time.March, 20, 8, 1, 0, 0, time.UTC),
		},
	})

	summary, err := runPolicyReplayWAL(policyPath, walPath, 0)
	if err != nil {
		t.Fatalf("run policy replay: %v", err)
	}
	if summary.TotalRecords != 2 {
		t.Fatalf("expected 2 records, got %d", summary.TotalRecords)
	}
	if summary.Divergences != 0 {
		t.Fatalf("expected no divergences, got %+v", summary)
	}
}

func TestRunPolicyReplayWALDetectsDivergence(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, replayTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:         "r1",
			ToolID:           "http/get",
			Effect:           "DENY",
			ReasonCode:       "RULE_DENY",
			SelectorSnapshot: map[string]any{"endpoint": "https://safe.example"},
			CreatedAt:        time.Date(2026, time.March, 20, 8, 0, 0, 0, time.UTC),
		},
	})

	summary, err := runPolicyReplayWAL(policyPath, walPath, 0)
	if err != nil {
		t.Fatalf("run policy replay: %v", err)
	}
	if summary.Divergences != 1 {
		t.Fatalf("expected 1 divergence, got %+v", summary)
	}
	if len(summary.Samples) != 1 {
		t.Fatalf("expected 1 sample divergence, got %+v", summary.Samples)
	}
	if summary.Samples[0].OldEffect != "DENY" || summary.Samples[0].NewEffect != "PERMIT" {
		t.Fatalf("unexpected divergence sample: %+v", summary.Samples[0])
	}
	if summary.EffectDivergences != 1 || summary.ReasonCodeDivergences != 1 {
		t.Fatalf("expected effect=1 reason=1 divergences, got %+v", summary)
	}
}

func TestRunPolicyReplayWALLegacyNonPolicyReasonPassthrough(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, replayTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:   "r1",
			ToolID:     "shell/exec",
			Effect:     "DENY",
			ReasonCode: reasons.SensitiveFilePath,
			// Legacy record: no selector snapshot available for scanner replay.
			SelectorSnapshot: nil,
			CreatedAt:        time.Date(2026, time.April, 5, 8, 0, 0, 0, time.UTC),
		},
	})

	summary, err := runPolicyReplayWAL(policyPath, walPath, 0)
	if err != nil {
		t.Fatalf("run policy replay: %v", err)
	}
	if summary.Divergences != 0 {
		t.Fatalf("expected no divergences with legacy non-policy passthrough, got %+v", summary)
	}
	if summary.LegacyNonPolicyReasonPassthroughs != 1 {
		t.Fatalf("expected one legacy non-policy passthrough, got %+v", summary)
	}
}

func TestRunPolicyReplayWALStrictReasonParityFlagsLegacyNonPolicyMismatch(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, replayTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:   "r1",
			ToolID:     "shell/exec",
			Effect:     "DENY",
			ReasonCode: reasons.SensitiveFilePath,
			SelectorSnapshot: nil,
			CreatedAt:        time.Date(2026, time.April, 5, 8, 1, 0, 0, time.UTC),
		},
	})

	summary, err := runPolicyReplayWALWithOptions(policyPath, walPath, 0, policyReplayWALOptions{StrictReasonParity: true})
	if err != nil {
		t.Fatalf("run policy replay strict reason parity: %v", err)
	}
	if summary.Divergences != 1 {
		t.Fatalf("expected one divergence with strict reason parity, got %+v", summary)
	}
	if summary.EffectDivergences != 0 || summary.ReasonCodeDivergences != 1 {
		t.Fatalf("expected effect=0 reason=1 divergences, got %+v", summary)
	}
	if summary.Samples[0].ReplayMode != "pipeline" {
		t.Fatalf("expected strict mode to keep pipeline replay mode, got %+v", summary.Samples[0])
	}
}

func TestRunPolicyReplayWALPipelineScannerReasonParity(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, replayTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:   "r1",
			ToolID:     "shell/exec",
			Effect:     "DENY",
			ReasonCode: reasons.SensitiveFilePath,
			SelectorSnapshot: map[string]any{
				"cmd": "cat /etc/passwd",
			},
			CreatedAt: time.Date(2026, time.April, 5, 8, 2, 0, 0, time.UTC),
		},
	})

	summary, err := runPolicyReplayWALWithOptions(policyPath, walPath, 0, policyReplayWALOptions{StrictReasonParity: true})
	if err != nil {
		t.Fatalf("run policy replay strict scanner parity: %v", err)
	}
	if summary.Divergences != 0 {
		t.Fatalf("expected scanner parity with selector snapshot context, got %+v", summary)
	}
	if summary.LegacyNonPolicyReasonPassthroughs != 0 {
		t.Fatalf("expected no legacy passthrough usage, got %+v", summary)
	}
}

func TestRunPolicyReplayWALPipelineCredentialBrokerParity(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.fpl")
	if err := os.WriteFile(policyPath, []byte(replayCredentialPolicyFPL), 0o644); err != nil {
		t.Fatalf("write fpl policy file: %v", err)
	}
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:           "r1",
			AgentID:            "replay-credential",
			ToolID:             "vault/probe/_execute_tool_sync",
			Effect:             "PERMIT",
			ReasonCode:         reasons.RulePermit,
			CredentialBrokered: true,
			CredentialSource:   "vault",
			CredentialScope:    "payments",
			CreatedAt:          time.Date(2026, time.April, 5, 8, 3, 0, 0, time.UTC),
		},
	})

	summary, err := runPolicyReplayWALWithOptions(policyPath, walPath, 0, policyReplayWALOptions{StrictReasonParity: true})
	if err != nil {
		t.Fatalf("run policy replay strict credential parity: %v", err)
	}
	if summary.Divergences != 0 {
		t.Fatalf("expected brokered credential replay parity, got %+v", summary)
	}
	if summary.EffectDivergences != 0 || summary.ReasonCodeDivergences != 0 {
		t.Fatalf("expected effect=0 reason=0 divergences, got %+v", summary)
	}
}

func TestPolicyReplayWALCommandFailsWhenThresholdExceeded(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeReplayTestPolicy(t, dir, replayTestPolicyYAML)
	walPath := writeReplayTestWAL(t, dir, []*dpr.Record{
		{
			RecordID:         "r1",
			ToolID:           "http/get",
			Effect:           "DENY",
			ReasonCode:       "RULE_DENY",
			SelectorSnapshot: map[string]any{"endpoint": "https://safe.example"},
			CreatedAt:        time.Date(2026, time.March, 20, 8, 0, 0, 0, time.UTC),
		},
	})

	policyReplayWALPolicyPath = policyPath
	policyReplayWALPath = walPath
	policyReplayWALLimit = 0
	policyReplayWALMaxDivergence = 0

	err := runPolicyReplayWALCommand(nil, nil)
	if err == nil {
		t.Fatalf("expected threshold failure")
	}
	if !strings.Contains(err.Error(), "exceed threshold") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeReplayTestPolicy(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func writeReplayTestWAL(t *testing.T, dir string, records []*dpr.Record) string {
	t.Helper()
	path := filepath.Join(dir, "records.wal")
	w, err := dpr.OpenWAL(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	for _, rec := range records {
		if err := w.Write(rec); err != nil {
			t.Fatalf("write record %q: %v", rec.RecordID, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}
	return path
}
