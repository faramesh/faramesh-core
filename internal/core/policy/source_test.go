package policy

import (
	"path/filepath"
	"testing"
)

func TestPolicyLoader_FromString_FPLInline(t *testing.T) {
	pl := NewPolicyLoader()
	yaml := `
faramesh-version: "1.0"
agent-id: "pl-test"
default_effect: deny
rules:
  - id: base
    match: { tool: "x", when: "true" }
    effect: deny
fpl_inline: |
  permit fpl/tool when true
`
	src, err := pl.FromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Doc.Rules) != 2 {
		t.Fatalf("rules %d", len(src.Doc.Rules))
	}
	if src.Doc.Rules[1].Match.Tool != "fpl/tool" {
		t.Fatalf("fpl rule: %+v", src.Doc.Rules[1])
	}
}

func TestPolicyLoader_FromFile_FPLFiles(t *testing.T) {
	pl := NewPolicyLoader()
	p := filepath.Join("testdata", "policy_with_fpl_files.yaml")
	src, err := pl.FromFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(src.Doc.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(src.Doc.Rules))
	}
	if src.Doc.Rules[1].Match.Tool != "overlay/tool" {
		t.Fatalf("overlay: %+v", src.Doc.Rules[1])
	}
}

func TestPolicyLoader_FromURL_rejectsFPLFiles(t *testing.T) {
	pl := NewPolicyLoader()
	// httptest server would need to serve yaml with fpl_files — exercise loadFromData path with empty dir
	_, err := pl.loadFromData([]byte(`faramesh-version: "1.0"
agent-id: "t"
default_effect: deny
fpl_files: [x.fpl]
`), SourceURL, "http://example/p.yaml", "")
	if err == nil {
		t.Fatal("expected error for fpl_files without policy directory")
	}
}
