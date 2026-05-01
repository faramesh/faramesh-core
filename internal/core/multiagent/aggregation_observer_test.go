package multiagent

import (
	"context"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/semantic"
)

type captureSemanticObserver struct {
	events []observe.SemanticDriftObservation
}

func (c *captureSemanticObserver) ObserveSemanticDrift(obs observe.SemanticDriftObservation) error {
	c.events = append(c.events, obs)
	return nil
}

func TestAggregationGovernor_EmitsSemanticDriftObservation(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{MinSources: 1})
	capture := &captureSemanticObserver{}
	ag.SetSemanticDriftObserver(capture)
	ag.ConfigureSemanticDrift(semantic.ProviderFunc{
		ProviderID: "mock",
		EmbedFunc: func(_ context.Context, texts []string) ([][]float64, error) {
			if len(texts) == 0 {
				return nil, nil
			}
			out := make([][]float64, len(texts))
			for i := range texts {
				if i == len(texts)-1 {
					out[i] = []float64{0, 1}
				} else {
					out[i] = []float64{1, 0}
				}
			}
			return out, nil
		},
	}, SemanticDriftConfig{Enabled: true, Threshold: 0.1, MinSourceCount: 1, DenyOnThreshold: true})

	_, _, err := ag.GovernOutput(AggregateResult{
		SessionID:   "sess-obs",
		Synthesized: "governed output",
		Sources:     []AggregationSource{{AgentID: "a1", Output: "source output"}},
	})
	if err == nil {
		t.Fatal("expected semantic drift denial")
	}
	if len(capture.events) != 1 {
		t.Fatalf("events = %d, want 1", len(capture.events))
	}
	if !capture.events[0].Triggered || !capture.events[0].Denied {
		t.Fatalf("unexpected observation: %#v", capture.events[0])
	}
}
