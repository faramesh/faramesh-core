package registry

import "testing"

func TestParseImportFramework(t *testing.T) {
	r, err := ParseImport(`registry.faramesh.dev/frameworks/langgraph@1.0.0`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindFramework || r.Name != "langgraph" || r.Version != "1.0.0" {
		t.Fatalf("got %+v", r)
	}
}

func TestParseImportPolicy(t *testing.T) {
	r, err := ParseImport(`registry.faramesh.dev/policies/faramesh/stripe@1.3.0`)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindPolicy || r.Name != "faramesh/stripe" {
		t.Fatalf("got %+v", r)
	}
}

func TestParseImportRejectsLatest(t *testing.T) {
	_, err := ParseImport(`registry.faramesh.dev/frameworks/langgraph@latest`)
	if err == nil {
		t.Fatal("expected error")
	}
}
