package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/observe"
)

func TestRunPolicyAnalyzeJSONSchemaFromSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "pie_snapshot.json")
	now := time.Date(2026, time.March, 21, 18, 0, 0, 0, time.UTC)
	snap := pieSnapshot{
		Rules: []observe.RuleStats{
			{
				RuleID:        "r-dead",
				Permits:       1,
				LastTriggered: now.Add(-8 * 24 * time.Hour),
				FirstSeen:     now.Add(-14 * 24 * time.Hour),
			},
			{
				RuleID:        "r-high-approval",
				Defers:        20,
				Approvals:     19,
				Rejections:    1,
				LastTriggered: now.Add(-1 * time.Hour),
				FirstSeen:     now.Add(-10 * 24 * time.Hour),
			},
		},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(snapshotPath, raw, 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}

	result, err := runPolicyAnalyze(policyAnalyzeOptions{
		SnapshotPath:      snapshotPath,
		DeadAfter:         7 * 24 * time.Hour,
		MinDefers:         10,
		ApprovalThreshold: 0.90,
		Now:               now,
	})
	if err != nil {
		t.Fatalf("run analyze: %v", err)
	}
	if !result.HasData {
		t.Fatalf("expected data")
	}
	if result.Source != "snapshot" {
		t.Fatalf("expected snapshot source, got %q", result.Source)
	}
	if result.RuleCount != 2 {
		t.Fatalf("expected 2 rules, got %d", result.RuleCount)
	}
	if len(result.Recommendations) < 2 {
		t.Fatalf("expected recommendations, got %+v", result.Recommendations)
	}

	out, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result json: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal output json: %v", err)
	}
	required := []string{"source", "has_data", "rule_count", "generated_at", "recommendations"}
	for _, key := range required {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing required output key %q", key)
		}
	}
}

func TestRunPolicyAnalyzeNoDataPath(t *testing.T) {
	result, err := runPolicyAnalyze(policyAnalyzeOptions{
		SnapshotPath: "",
		DataDir:      t.TempDir(),
		Now:          time.Date(2026, time.March, 21, 18, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("run analyze: %v", err)
	}
	if result.HasData {
		t.Fatalf("expected no-data result")
	}
	if result.Source != "none" {
		t.Fatalf("expected none source, got %q", result.Source)
	}
	if result.NoDataReason == "" {
		t.Fatalf("expected no-data reason")
	}
}

func TestPrintPolicyAnalyzeJSONDeterministic(t *testing.T) {
	result := policyAnalyzeResult{
		Source:      "snapshot",
		HasData:     true,
		RuleCount:   1,
		GeneratedAt: "2026-03-21T18:00:00Z",
		Recommendations: []policyAnalyzeRecommendation{
			{
				RuleID:       "r1",
				Type:         "promote_to_permit",
				Reason:       "high approval rate suggests DEFER friction",
				ApprovalRate: 0.9,
				TotalDefers:  10,
			},
		},
	}
	output, err := captureStdout(func() error {
		return printPolicyAnalyze(result, true)
	})
	if err != nil {
		t.Fatalf("print json output: %v", err)
	}
	trimmed := strings.TrimSpace(output)
	var decoded policyAnalyzeResult
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		t.Fatalf("json output decode failed: %v\noutput=%s", err, trimmed)
	}
	if decoded.GeneratedAt != result.GeneratedAt {
		t.Fatalf("expected generated_at %q, got %q", result.GeneratedAt, decoded.GeneratedAt)
	}
}

func captureStdout(fn func() error) (string, error) {
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdout = w
	callErr := fn()
	_ = w.Close()
	os.Stdout = origStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	return buf.String(), callErr
}
