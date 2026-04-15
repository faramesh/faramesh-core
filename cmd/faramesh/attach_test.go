package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAttachPolicyPathFallsBackToGeneratedBootstrap(t *testing.T) {
	cwd := t.TempDir()
	dataDir := t.TempDir()

	policyPath, err := resolveAttachPolicyPath(cwd, dataDir, "")
	if err != nil {
		t.Fatalf("resolveAttachPolicyPath() error = %v", err)
	}
	if !strings.HasSuffix(policyPath, "attach-shadow-bootstrap.yaml") {
		t.Fatalf("policy path = %q, want generated bootstrap path", policyPath)
	}
	body, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("read generated policy: %v", err)
	}
	if !strings.Contains(string(body), `default_effect: permit`) {
		t.Fatalf("generated policy = %q, want default_effect permit", string(body))
	}
}

func TestResolveAttachPolicyPathUsesExistingPolicy(t *testing.T) {
	cwd := t.TempDir()
	dataDir := t.TempDir()
	existing := filepath.Join(cwd, "policy.yaml")
	if err := os.WriteFile(existing, []byte("faramesh-version: \"1.0\"\ndefault_effect: permit\nrules: []\n"), 0o644); err != nil {
		t.Fatalf("write existing policy: %v", err)
	}

	policyPath, err := resolveAttachPolicyPath(cwd, dataDir, "")
	if err != nil {
		t.Fatalf("resolveAttachPolicyPath() error = %v", err)
	}
	if policyPath != existing {
		t.Fatalf("policy path = %q, want existing policy %q", policyPath, existing)
	}
}
