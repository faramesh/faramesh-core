package refsrv

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/hub"
)

func TestReferenceRegistrySearchAndGetPack(t *testing.T) {
	srv := httptest.NewServer(NewHandler(defaultCatalog()))
	t.Cleanup(srv.Close)

	cl, err := hub.NewClient(srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	sr, err := cl.Search(ctx, "demo", nil)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(sr.Packs) != 1 || sr.Packs[0].Name != "refsrv/demo" {
		t.Fatalf("search packs = %+v", sr.Packs)
	}
	pv, err := cl.GetPackVersion(ctx, "refsrv/demo", "0.1.0")
	if err != nil {
		t.Fatalf("GetPackVersion: %v", err)
	}
	if err := hub.ValidatePackPayload(pv); err != nil {
		t.Fatalf("ValidatePackPayload: %v", err)
	}
	if pv.Publisher == nil || !pv.Publisher.Verified {
		t.Fatalf("publisher = %+v", pv.Publisher)
	}
}

func TestLoadPacksRegistryCatalogExample(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	// .../internal/hub/refsrv/refsrv_test.go -> repo packs/registry-catalog.example.json
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	catPath := filepath.Join(repoRoot, "packs", "registry-catalog.example.json")
	cat, err := LoadCatalogFromFile(catPath)
	if err != nil {
		t.Fatalf("LoadCatalogFromFile(%q): %v", catPath, err)
	}
	if len(cat.Packs) != 1 || cat.Packs[0].Name != "faramesh/starter" {
		t.Fatalf("catalog packs = %+v", cat.Packs)
	}
	yamlBody, fplBody, err := policyBodiesForVersion(cat, "faramesh/starter", "1.0.0")
	if err != nil {
		t.Fatalf("policyBodiesForVersion: %v", err)
	}
	if len(yamlBody) < 50 || !strings.Contains(string(yamlBody), "default_effect") {
		t.Fatalf("unexpected policy content")
	}
	if len(fplBody) == 0 || !strings.Contains(string(fplBody), "agent") {
		t.Fatalf("expected optional policy.fpl beside policy.yaml, got len=%d", len(fplBody))
	}
}
