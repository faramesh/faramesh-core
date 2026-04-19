package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureBootstrapPolicyCreatesAndReuses(t *testing.T) {
	stateDir := t.TempDir()

	path, created, err := ensureBootstrapPolicy(stateDir)
	if err != nil {
		t.Fatalf("ensureBootstrapPolicy create: %v", err)
	}
	if !created {
		t.Fatal("expected created=true on first call")
	}

	wantPath := filepath.Join(stateDir, "policy.bootstrap.yaml")
	if path != wantPath {
		t.Fatalf("policy path = %q, want %q", path, wantPath)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read starter policy: %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, "faramesh-version: '1.0'") {
		t.Fatalf("starter policy missing faramesh version: %q", content)
	}
	if !strings.Contains(content, "default_effect: permit") {
		t.Fatalf("starter policy missing default effect: %q", content)
	}

	path2, created2, err := ensureBootstrapPolicy(stateDir)
	if err != nil {
		t.Fatalf("ensureBootstrapPolicy reuse: %v", err)
	}
	if created2 {
		t.Fatal("expected created=false on second call")
	}
	if path2 != path {
		t.Fatalf("reused policy path = %q, want %q", path2, path)
	}
}
