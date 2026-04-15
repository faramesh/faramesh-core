package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicySimulateJSONSuccess(t *testing.T) {
	root := findRepoRoot(t)
	policyPath := filepath.Join(t.TempDir(), "simulate-policy.yaml")

	err := os.WriteFile(policyPath, []byte(strings.Join([]string{
		`faramesh-version: "1.0"`,
		`agent-id: "simulate-json-ok"`,
		`default_effect: deny`,
		`rules:`,
		`  - id: allow-refund`,
		`    match:`,
		`      tool: "stripe/refund"`,
		`    effect: permit`,
		`    reason_code: RULE_PERMIT`,
	}, "\n")), 0o600)
	if err != nil {
		t.Fatalf("write simulate policy fixture: %v", err)
	}

	cmd := exec.Command(
		"go", "run", ".",
		"policy", "simulate", policyPath,
		"--tool", "stripe/refund",
		"--args", `{"amount":500}`,
		"--mode", "allow",
		"--risk-score", "0.2",
		"--json",
	)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("policy simulate --json success path failed: %v", err)
	}

	var report policySimulateReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode simulate json report: %v\noutput=%s", err, string(out))
	}

	if report.Decision != "allow" {
		t.Fatalf("expected decision allow, got %q", report.Decision)
	}
	if report.Effect != "PERMIT" {
		t.Fatalf("expected effect PERMIT, got %q", report.Effect)
	}
	if len(report.MatchedRuleIDs) != 1 || report.MatchedRuleIDs[0] != "allow-refund" {
		t.Fatalf("expected matched rule allow-refund, got %+v", report.MatchedRuleIDs)
	}
	if len(report.Trace) < 4 {
		t.Fatalf("expected trace with >=4 steps, got %+v", report.Trace)
	}
}

func TestPolicySimulateJSONCapturesRequestedMode(t *testing.T) {
	root := findRepoRoot(t)
	policyPath := filepath.Join(t.TempDir(), "simulate-mode-policy.yaml")

	err := os.WriteFile(policyPath, []byte(strings.Join([]string{
		`faramesh-version: "1.0"`,
		`agent-id: "simulate-mode"`,
		`default_effect: deny`,
		`rules:`,
		`  - id: allow-http`,
		`    match:`,
		`      tool: "http/get"`,
		`    effect: permit`,
		`    reason_code: RULE_PERMIT`,
	}, "\n")), 0o600)
	if err != nil {
		t.Fatalf("write simulate policy fixture: %v", err)
	}

	cmd := exec.Command(
		"go", "run", ".",
		"policy", "simulate", policyPath,
		"--tool", "http/get",
		"--mode", "deny",
		"--json",
	)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("policy simulate --json failed: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}

	var report policySimulateReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode simulate report: %v\nstdout=%s", err, stdout.String())
	}

	foundRequestedMode := false
	for _, step := range report.Trace {
		if step.Step == "decision" && strings.Contains(step.Outcome, "requested_mode=deny") {
			foundRequestedMode = true
			break
		}
	}
	if !foundRequestedMode {
		t.Fatalf("expected trace to capture requested mode deny, got %+v", report.Trace)
	}
}
