package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyFPLCLI(t *testing.T) {
	root := findRepoRoot(t)
	golden := filepath.Join(root, "internal", "core", "fpl", "testdata", "golden.fpl")
	cmd := exec.Command("go", "run", ".", "policy", "fpl", "--json", golden)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("policy fpl: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"rules"`) || !strings.Contains(s, `"effect": "permit"`) || !strings.Contains(s, `"tool": "safe/read"`) {
		t.Fatalf("unexpected json: %s", out)
	}
}

func TestPolicyFPLDecompileCLI(t *testing.T) {
	root := findRepoRoot(t)
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "policy.yaml")
	policyYAML := "faramesh-version: \"1.0\"\n" +
		"agent-id: decompile-test\n" +
		"default_effect: deny\n" +
		"rules:\n" +
		"  - id: refund-high\n" +
		"    effect: defer\n" +
		"    match:\n" +
		"      tool: stripe/refund\n" +
		"      when: \"args.amount > 100\"\n" +
		"    notify: finance\n" +
		"    reason: high refund\n"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("write policy yaml: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "policy", "fpl", "decompile", policyPath)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy fpl decompile: %v\n%s", err, string(out))
	}
	s := string(out)
	if !strings.Contains(s, "agent decompile-test") || !strings.Contains(s, "defer stripe/refund when args.amount > 100") || !strings.Contains(s, "notify: \"finance\"") {
		t.Fatalf("unexpected decompile output: %s", s)
	}
}

func TestPolicyFPLYAMLCLI(t *testing.T) {
	root := findRepoRoot(t)
	tmp := t.TempDir()
	fplPath := filepath.Join(tmp, "policy.fpl")
	fplSrc := `agent yaml-test {
  default deny

  rules {
    permit http/get when args.host != nil && args.host matches "localhost|127.0.0.1"
  }
}`
	if err := os.WriteFile(fplPath, []byte(fplSrc), 0o600); err != nil {
		t.Fatalf("write fpl: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "policy", "fpl", "yaml", fplPath)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("policy fpl yaml: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "agent-id: yaml-test") || !strings.Contains(s, "default_effect: deny") || !strings.Contains(s, "fpl_inline:") || !strings.Contains(s, "permit http/get when args.host != nil") {
		t.Fatalf("unexpected yaml output: %s", s)
	}
}

func TestPolicyFPLDecompileForFPLInputIsLossless(t *testing.T) {
	root := findRepoRoot(t)
	tmp := t.TempDir()
	fplPath := filepath.Join(tmp, "policy.fpl")
	fplSrc := `agent lossless {
  default deny

  rules {
    defer stripe/refund when args.amount > 500 notify: "finance" reason: "high"
  }

  credential stripe {
    scope refund
    max_scope "refund:amount<=1000"
  }
}`
	if err := os.WriteFile(fplPath, []byte(fplSrc), 0o600); err != nil {
		t.Fatalf("write fpl: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "policy", "fpl", "decompile", fplPath)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("policy fpl decompile fpl input: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "credential stripe") || !strings.Contains(s, "notify: \"finance\"") {
		t.Fatalf("unexpected decompile output: %s", s)
	}
}

func TestPolicyValidateFPLCatchesEngineCompileErrors(t *testing.T) {
	root := findRepoRoot(t)
	tmp := t.TempDir()
	fplPath := filepath.Join(tmp, "invalid.fpl")
	fplSrc := `agent invalid {
  default deny

  rules {
    defer stripe/refund when amount > 100
  }
}`
	if err := os.WriteFile(fplPath, []byte(fplSrc), 0o600); err != nil {
		t.Fatalf("write invalid fpl: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "policy", "validate", fplPath)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected validation failure, got success: %s", string(out))
	}
	if !strings.Contains(string(out), "invalid when expression") && !strings.Contains(string(out), "unknown name amount") {
		t.Fatalf("unexpected validation error: %s", string(out))
	}
}
