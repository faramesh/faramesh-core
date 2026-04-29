package packs

import (
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/fpl"
)

// Ensures embedded policy.fpl sidecars stay syntactically valid (registry / hub parity).
func TestBundledPolicyFPLParsesAndCompiles(t *testing.T) {
	t.Parallel()
	for _, s := range Search("") {
		s := s
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			pv, err := Lookup(s.Name, s.LatestVersion)
			if err != nil {
				t.Fatal(err)
			}
			if pv.PolicyFPL == "" {
				t.Fatal("empty PolicyFPL (catalog_bundled_test also requires sidecar)")
			}
			doc, err := fpl.ParseDocument(pv.PolicyFPL)
			if err != nil {
				t.Fatalf("ParseDocument: %v", err)
			}
			if _, err := fpl.CompileDocument(doc); err != nil {
				t.Fatalf("CompileDocument: %v", err)
			}
		})
	}
}
