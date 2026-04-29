package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicySuiteCLI(t *testing.T) {
	root := findRepoRoot(t)
	policy := filepath.Join(root, "tests", "policy_suite_policy.yaml")
	fixtures := filepath.Join(root, "tests", "policy_suite_fixtures.yaml")
	cmd := exec.Command("go", "run", ".", "policy", "suite", policy, "--fixtures", fixtures)
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy suite: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "all 2 cases passed") {
		t.Fatalf("unexpected output:\n%s", out)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
