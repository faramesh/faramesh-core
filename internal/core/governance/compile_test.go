package governance

import (
	"os"
	"path/filepath"
	"testing"


)

func TestCompileAndPlan(t *testing.T) {
	dir := t.TempDir()
	src := `
runtime {
  mode = enforce
  wal_dir = "./faramesh-wal"
}
agent "stack-agent" {
  rules {
    defer example
  }
}
`
	path := filepath.Join(dir, FileFPL)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := ParseSource(path, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	compiled, diags, err := Compile(doc, dir, []byte(src), CompileOptions{CheckEnv: false})
	if err != nil || HasErrors(diags) {
		t.Fatalf("compile: %v diags=%v", err, diags)
	}
	changes, err := Plan(dir, compiled)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Action != "create" {
		t.Fatalf("plan: %+v", changes)
	}
	if err := compiled.Write(dir); err != nil {
		t.Fatal(err)
	}
	changes2, err := Plan(dir, compiled)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes2) != 1 || changes2[0].Action != "noop" {
		t.Fatalf("expected noop after write, got %+v", changes2)
	}
}
