package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBytes_FPLInline(t *testing.T) {
	yaml := `
faramesh-version: "1.0"
agent-id: "t"
default_effect: deny
rules:
  - id: base
    match: { tool: "x", when: "true" }
    effect: deny
fpl_inline: |
  permit fpl/tool when true
`
	doc, _, err := LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("rules %d", len(doc.Rules))
	}
	if doc.Rules[1].ID != "fpl-1" || doc.Rules[1].Match.Tool != "fpl/tool" {
		t.Fatalf("fpl rule: %+v", doc.Rules[1])
	}
	if doc.FPLInline != "" {
		t.Fatal("fpl_inline should be cleared")
	}
}

func TestLoadFile_FPLFiles(t *testing.T) {
	dir := filepath.Join("testdata")
	p := filepath.Join(dir, "policy_with_fpl_files.yaml")
	doc, _, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d %+v", len(doc.Rules), doc.Rules)
	}
	if doc.Rules[1].Match.Tool != "overlay/tool" {
		t.Fatalf("overlay rule: %+v", doc.Rules[1])
	}
}

func TestLoadBytes_FPLFilesRejected(t *testing.T) {
	yaml := `faramesh-version: "1.0"
agent-id: "t"
default_effect: deny
fpl_files: [x.fpl]
`
	_, _, err := LoadBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMergeFPL_pathTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(policy, []byte(`faramesh-version: "1.0"
agent-id: "t"
default_effect: deny
fpl_files: ["../evil.fpl"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := LoadFile(policy)
	if err == nil {
		t.Fatal("expected error")
	}
}
