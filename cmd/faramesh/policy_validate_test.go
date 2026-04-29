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

func TestPolicyValidateJSONSuccess(t *testing.T) {
	root := findRepoRoot(t)
	policyPath := filepath.Join(t.TempDir(), "valid-policy.yaml")

	err := os.WriteFile(policyPath, []byte(strings.Join([]string{
		`faramesh-version: "1.0"`,
		`agent-id: "validate-json-ok"`,
		`default_effect: deny`,
		`rules:`,
		`  - id: allow-http`,
		`    match:`,
		`      tool: "http/get"`,
		`    effect: permit`,
		`    reason_code: RULE_PERMIT`,
	}, "\n")), 0o600)
	if err != nil {
		t.Fatalf("write valid policy fixture: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "policy", "validate", policyPath, "--json")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("policy validate --json success path failed: %v", err)
	}

	var report policyValidateReport
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("decode validate json report: %v\noutput=%s", err, string(out))
	}
	if !report.OK {
		t.Fatalf("expected validation success, got report: %+v", report)
	}
	if report.Format != "yaml" {
		t.Fatalf("expected yaml format, got %q", report.Format)
	}
	if report.RuleCount != 1 {
		t.Fatalf("expected 1 rule, got %d", report.RuleCount)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("expected no errors, got %+v", report.Errors)
	}
}

func TestPolicyValidateJSONFailureIncludesDiagnostics(t *testing.T) {
	root := findRepoRoot(t)
	policyPath := filepath.Join(t.TempDir(), "invalid-policy.yaml")

	err := os.WriteFile(policyPath, []byte(strings.Join([]string{
		`faramesh-version: "1.0"`,
		`agent-id: "validate-json-bad"`,
		`default_effect: deny`,
		`rules:`,
		`  - id: invalid-when`,
		`    match:`,
		`      tool: "http/get"`,
		`      when: "missing_symbol > 0"`,
		`    effect: permit`,
	}, "\n")), 0o600)
	if err != nil {
		t.Fatalf("write invalid policy fixture: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "policy", "validate", policyPath, "--json")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err == nil {
		t.Fatal("expected validate command to fail for invalid policy")
	}

	var report policyValidateReport
	if jerr := json.Unmarshal(stdout.Bytes(), &report); jerr != nil {
		t.Fatalf("decode validate json report on failure: %v\nstdout=%s\nstderr=%s", jerr, stdout.String(), stderr.String())
	}
	if report.OK {
		t.Fatalf("expected validation failure, got report: %+v", report)
	}
	if len(report.Errors) == 0 {
		t.Fatalf("expected errors in report, got %+v", report)
	}
	if !strings.Contains(strings.ToLower(strings.Join(report.Errors, " | ")), "invalid when expression") {
		t.Fatalf("expected invalid-when diagnostic, got %+v", report.Errors)
	}
}
