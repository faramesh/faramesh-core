package sbom

import (
	"encoding/json"
	"testing"
)

func TestGenerateJSON(t *testing.T) {
	b, err := GenerateJSON("", "")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("bomFormat: %v", doc["bomFormat"])
	}
	comps, _ := doc["components"].([]any)
	if len(comps) < 1 {
		t.Fatal("expected at least one component")
	}
}
