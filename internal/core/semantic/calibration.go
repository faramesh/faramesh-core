package semantic

import (
	"context"
	"fmt"
	"sort"
)

// CalibrationExample represents one labeled semantic-distance example.
// ExpectedDrift=true means the candidate should be semantically far from the reference.
type CalibrationExample struct {
	Name           string `json:"name"`
	ReferenceText  string `json:"reference_text"`
	CandidateText  string `json:"candidate_text"`
	ExpectedDrift  bool   `json:"expected_drift"`
}

// CalibrationResult summarizes threshold calibration output.
type CalibrationResult struct {
	Threshold       float64            `json:"threshold"`
	BenignMaxDistance float64          `json:"benign_max_distance"`
	DriftMinDistance float64           `json:"drift_min_distance"`
	ExamplesScored   int               `json:"examples_scored"`
	Notes           []string           `json:"notes,omitempty"`
}

// RecommendThreshold embeds the calibration examples and returns a threshold
// that separates benign from drift examples when possible.
func RecommendThreshold(ctx context.Context, provider Provider, examples []CalibrationExample) (*CalibrationResult, error) {
	if provider == nil {
		return nil, fmt.Errorf("calibration requires a semantic provider")
	}
	if len(examples) == 0 {
		return nil, fmt.Errorf("calibration requires at least one example")
	}

	benignDistances := make([]float64, 0, len(examples))
	driftDistances := make([]float64, 0, len(examples))
	for _, ex := range examples {
		vecs, err := provider.Embed(ctx, []string{ex.ReferenceText, ex.CandidateText})
		if err != nil {
			return nil, fmt.Errorf("calibration embed %q: %w", ex.Name, err)
		}
		if len(vecs) != 2 {
			return nil, fmt.Errorf("calibration embed %q: provider returned %d vectors, want 2", ex.Name, len(vecs))
		}
		dist, err := CosineDistance(vecs[0], vecs[1])
		if err != nil {
			return nil, fmt.Errorf("calibration distance %q: %w", ex.Name, err)
		}
		if ex.ExpectedDrift {
			driftDistances = append(driftDistances, dist)
		} else {
			benignDistances = append(benignDistances, dist)
		}
	}

	res := &CalibrationResult{ExamplesScored: len(examples)}
	if len(benignDistances) == 0 || len(driftDistances) == 0 {
		res.Threshold = 0.5
		res.Notes = append(res.Notes, "insufficient class separation; defaulted to 0.5")
		return res, nil
	}

	sort.Float64s(benignDistances)
	sort.Float64s(driftDistances)
	res.BenignMaxDistance = benignDistances[len(benignDistances)-1]
	res.DriftMinDistance = driftDistances[0]
	if res.BenignMaxDistance >= res.DriftMinDistance {
		res.Threshold = (res.BenignMaxDistance + res.DriftMinDistance) / 2
		res.Notes = append(res.Notes, "classes overlap; selected midpoint between closest drift and farthest benign example")
		return res, nil
	}
	res.Threshold = (res.BenignMaxDistance + res.DriftMinDistance) / 2
	res.Notes = append(res.Notes, "selected midpoint between benign and drift distributions")
	return res, nil
}

// ExampleSet returns a small, deterministic calibration corpus suitable for
// local threshold tuning and CI smoke tests.
func ExampleSet() []CalibrationExample {
	return []CalibrationExample{
		{Name: "benign-identical", ReferenceText: "short safe output", CandidateText: "short safe output", ExpectedDrift: false},
		{Name: "benign-paraphrase", ReferenceText: "approve the safe output", CandidateText: "approve the safe result", ExpectedDrift: false},
		{Name: "drift-opposite", ReferenceText: "short safe output", CandidateText: "completely different output", ExpectedDrift: true},
		{Name: "drift-topic-shift", ReferenceText: "safe summary of findings", CandidateText: "unrelated incident response playbook", ExpectedDrift: true},
	}
}
