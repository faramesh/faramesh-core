package fpl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenFPLFile(t *testing.T) {
	path := filepath.Join("testdata", "golden.fpl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	out, err := ParseAndCompileRules(string(raw))
	if err != nil {
		t.Fatalf("parse+compile golden: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 compiled rules, got %d", len(out))
	}
	if out[0].Effect != EffectPermit || out[0].Tool != "safe/read" {
		t.Fatalf("rule0: %+v", out[0])
	}
	if out[1].Effect != EffectDeny || !out[1].StrictDeny || out[1].Tool != "shell/exec" {
		t.Fatalf("rule1: %+v", out[1])
	}
	if out[2].Effect != EffectDefer || out[2].Tool != "payment/charge" {
		t.Fatalf("rule2: %+v", out[2])
	}
	if out[2].Notify == nil || out[2].Notify.Target != "finance" {
		t.Fatalf("rule2 notify: %+v", out[2].Notify)
	}
}
