package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunPolicyBacktestFixturesPassesDefaultFixtures(t *testing.T) {
	report, err := runPolicyBacktestFixtures([]byte(defaultPolicyBacktestYAML), defaultPolicyBacktestFixtures())
	if err != nil {
		t.Fatalf("run backtest fixtures: %v", err)
	}
	if report.Total == 0 {
		t.Fatalf("expected non-zero fixture count")
	}
	if report.Failed != 0 {
		t.Fatalf("expected no failures, got %+v", report)
	}
}

func TestRunPolicyBacktestFixturesDetectsRegression(t *testing.T) {
	fixtures := defaultPolicyBacktestFixtures()
	fixtures[0].ExpectedReasonCode = "RULE_DENY"

	report, err := runPolicyBacktestFixtures([]byte(defaultPolicyBacktestYAML), fixtures)
	if err != nil {
		t.Fatalf("run backtest fixtures: %v", err)
	}
	if report.Failed != 1 {
		t.Fatalf("expected 1 failure, got %+v", report)
	}
	if len(report.Failures) != 1 {
		t.Fatalf("expected exactly one failure entry, got %+v", report.Failures)
	}
}

func TestRunPolicyBacktestReadsFixtureFileAndFails(t *testing.T) {
	dir := t.TempDir()
	fixturePath := filepath.Join(dir, "fixtures.json")
	raw := `[
  {
    "name": "forced-fail",
    "tool_id": "http/get",
    "args": {"endpoint":"https://safe.example"},
    "expected_effect": "DENY",
    "expected_reason_code": "RULE_DENY"
  }
]`
	if err := os.WriteFile(fixturePath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write fixtures file: %v", err)
	}

	policyBacktestPolicyPath = ""
	policyBacktestFixturesPath = fixturePath
	err := runPolicyBacktest(nil, nil)
	if err == nil {
		t.Fatalf("expected backtest command to fail for regression fixture")
	}
}
