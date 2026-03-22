package reasons

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type reasonCodeSpec struct {
	Version string   `json:"version"`
	Codes   []string `json:"codes"`
}

func TestReasonCodeSpecMatchesCanonicalRegistry(t *testing.T) {
	data, err := os.ReadFile("reason_codes.spec.json")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}

	var spec reasonCodeSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	if len(spec.Codes) == 0 {
		t.Fatal("spec has no reason codes")
	}

	canonicalCodes := CanonicalCodes()
	if len(spec.Codes) != len(canonicalCodes) {
		t.Fatalf("reason code count mismatch: spec=%d canonical=%d", len(spec.Codes), len(canonicalCodes))
	}

	specSet := make(map[string]struct{}, len(spec.Codes))
	for _, code := range spec.Codes {
		if _, exists := specSet[code]; exists {
			t.Fatalf("duplicate reason code in spec: %s", code)
		}
		specSet[code] = struct{}{}
	}

	missingFromSpec := make([]string, 0)
	for _, code := range canonicalCodes {
		if _, ok := specSet[code]; !ok {
			missingFromSpec = append(missingFromSpec, code)
		}
	}

	canonicalSet := make(map[string]struct{}, len(canonicalCodes))
	for _, code := range canonicalCodes {
		canonicalSet[code] = struct{}{}
	}
	extraInSpec := make([]string, 0)
	for _, code := range spec.Codes {
		if _, ok := canonicalSet[code]; !ok {
			extraInSpec = append(extraInSpec, code)
		}
	}

	if len(missingFromSpec) > 0 || len(extraInSpec) > 0 {
		slices.Sort(missingFromSpec)
		slices.Sort(extraInSpec)
		t.Fatalf("reason code spec drift detected; missing_from_spec=%v extra_in_spec=%v", missingFromSpec, extraInSpec)
	}
}
