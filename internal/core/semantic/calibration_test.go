package semantic

import (
	"context"
	"strings"
	"testing"
)

func TestRecommendThreshold(t *testing.T) {
	provider := ProviderFunc{
		ProviderID: "mock",
		EmbedFunc: func(_ context.Context, texts []string) ([][]float64, error) {
			vecs := make([][]float64, len(texts))
			for i, text := range texts {
				switch {
				case strings.Contains(text, "safe output"):
					vecs[i] = []float64{1, 0}
				case strings.Contains(text, "different output"):
					vecs[i] = []float64{0, 1}
				default:
					vecs[i] = []float64{0.5, 0.5}
				}
			}
			return vecs, nil
		},
	}

	res, err := RecommendThreshold(context.Background(), provider, []CalibrationExample{
		{Name: "benign", ReferenceText: "safe output", CandidateText: "safe output", ExpectedDrift: false},
		{Name: "drift", ReferenceText: "safe output", CandidateText: "different output", ExpectedDrift: true},
	})
	if err != nil {
		t.Fatalf("RecommendThreshold error: %v", err)
	}
	if res.ExamplesScored != 2 {
		t.Fatalf("ExamplesScored = %d, want 2", res.ExamplesScored)
	}
	if res.BenignMaxDistance != 0 {
		t.Fatalf("BenignMaxDistance = %v, want 0", res.BenignMaxDistance)
	}
	if res.DriftMinDistance <= 0 {
		t.Fatalf("DriftMinDistance = %v, want > 0", res.DriftMinDistance)
	}
	if res.Threshold <= 0 || res.Threshold >= 1 {
		t.Fatalf("Threshold = %v, want in (0,1)", res.Threshold)
	}
}
