package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDefaultAuditVerifyPathPrefersWAL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dataDir := t.TempDir()
	walPath := filepath.Join(dataDir, "faramesh.wal")
	dbPath := filepath.Join(dataDir, "faramesh.db")
	if err := os.WriteFile(walPath, []byte("wal"), 0o600); err != nil {
		t.Fatalf("write wal: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("db"), 0o600); err != nil {
		t.Fatalf("write db: %v", err)
	}

	runtimeDir := filepath.Join(home, ".faramesh", "runtime")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := writeRuntimeStartState(filepath.Join(runtimeDir, "runtime.json"), runtimeStartState{DataDir: dataDir}); err != nil {
		t.Fatalf("write runtime state: %v", err)
	}

	got, err := resolveDefaultAuditVerifyPath()
	if err != nil {
		t.Fatalf("resolveDefaultAuditVerifyPath: %v", err)
	}
	if got != walPath {
		t.Fatalf("resolveDefaultAuditVerifyPath = %q, want %q", got, walPath)
	}
}

func TestResolveDefaultAuditVerifyPathErrorsWhenStateMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	_, err := resolveDefaultAuditVerifyPath()
	if err == nil {
		t.Fatal("expected error when runtime state is missing")
	}
}
