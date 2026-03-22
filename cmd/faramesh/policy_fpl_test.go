package main

import (
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
