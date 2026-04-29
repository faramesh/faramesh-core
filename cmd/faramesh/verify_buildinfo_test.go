package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/reprobuild"
)

func TestVerifyBuildinfoEmitAndCompare(t *testing.T) {
	root := findRepoRoot(t)
	dir := t.TempDir()
	cmd := exec.Command("go", "run", ".", "verify", "buildinfo", "--emit")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var fp reprobuild.Fingerprint
	if err := json.Unmarshal(out, &fp); err != nil {
		t.Fatalf("parse emit: %v\n%s", err, out)
	}
	if fp.GoVersion == "" || fp.MainPath == "" {
		t.Fatalf("unexpected fingerprint: %+v", fp)
	}
	expPath := filepath.Join(dir, "exp.json")
	if err := os.WriteFile(expPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd2 := exec.Command("go", "run", ".", "verify", "buildinfo", expPath)
	cmd2.Dir = filepath.Join(root, "cmd", "faramesh")
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out2)
	}
	if !strings.Contains(string(out2), "✓") {
		t.Fatalf("expected match: %s", out2)
	}
}

func TestVerifyBuildinfoComparePartial(t *testing.T) {
	root := findRepoRoot(t)
	dir := t.TempDir()
	cmd := exec.Command("go", "run", ".", "verify", "buildinfo", "--emit")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var fp reprobuild.Fingerprint
	if err := json.Unmarshal(out, &fp); err != nil {
		t.Fatal(err)
	}
	partial := map[string]any{"main_path": fp.MainPath}
	raw, _ := json.Marshal(partial)
	expPath := filepath.Join(dir, "partial.json")
	if err := os.WriteFile(expPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd2 := exec.Command("go", "run", ".", "verify", "buildinfo", expPath)
	cmd2.Dir = filepath.Join(root, "cmd", "faramesh")
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out2)
	}
	if !strings.Contains(string(out2), "✓") {
		t.Fatalf("expected match: %s", out2)
	}
}

func TestVerifyBuildinfoCompareStdin(t *testing.T) {
	root := findRepoRoot(t)
	cmd := exec.Command("go", "run", ".", "verify", "buildinfo", "--emit")
	cmd.Dir = filepath.Join(root, "cmd", "faramesh")
	emitOut, err := cmd.Output()
	if err != nil {
		t.Fatalf("%v\n%s", err, emitOut)
	}
	cmd2 := exec.Command("go", "run", ".", "verify", "buildinfo", "-")
	cmd2.Dir = filepath.Join(root, "cmd", "faramesh")
	cmd2.Stdin = bytes.NewReader(emitOut)
	out2, err := cmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out2)
	}
	if !strings.Contains(string(out2), "✓") {
		t.Fatalf("expected match: %s", out2)
	}
}
