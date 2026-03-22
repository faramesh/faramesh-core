package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
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
