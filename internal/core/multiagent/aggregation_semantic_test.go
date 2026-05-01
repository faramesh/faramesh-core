package multiagent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/semantic"
)

func TestAggregationGovernor_SemanticDriftAllowsSimilarOutput(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{MinSources: 1})
	ag.ConfigureSemanticDrift(semantic.ProviderFunc{
		ProviderID: "len-mock",
		EmbedFunc: func(_ context.Context, texts []string) ([][]float64, error) {
			vecs := make([][]float64, len(texts))
			for i, text := range texts {
				if strings.Contains(text, "safe output") {
					vecs[i] = []float64{1, 0}
				} else {
					vecs[i] = []float64{0, 1}
				}
			}
			return vecs, nil
		},
	}, SemanticDriftConfig{Enabled: true, Threshold: 0.5, MinSourceCount: 1, CacheTTL: time.Minute, CacheEntries: 4, MaxEvents: 1})

	out, _, err := ag.GovernOutput(AggregateResult{
		SessionID:   "sess-1",
		Synthesized: "safe output",
		Sources: []AggregationSource{{AgentID: "a1", Output: "safe output"}},
	})
	if err != nil {
		t.Fatalf("GovernOutput error: %v", err)
	}
	if out != "safe output" {
		t.Fatalf("output = %q, want unchanged", out)
	}
	events := ag.SemanticDriftEvents()
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if events[0].Triggered {
		t.Fatal("expected non-triggered event for similar output")
	}
}

func TestAggregationGovernor_SemanticDriftDeniesDivergentOutput(t *testing.T) {
	ag := NewAggregationGovernor(AggregatePolicy{MinSources: 1})
	ag.ConfigureSemanticDrift(semantic.ProviderFunc{
		ProviderID: "len-mock",
		EmbedFunc: func(_ context.Context, texts []string) ([][]float64, error) {
			vecs := make([][]float64, len(texts))
			for i, text := range texts {
				if strings.Contains(text, "safe output") {
					vecs[i] = []float64{1, 0}
				} else {
					vecs[i] = []float64{0, 1}
				}
			}
			return vecs, nil
		},
	}, SemanticDriftConfig{Enabled: true, Threshold: 0.01, MinSourceCount: 1, DenyOnThreshold: true, CacheTTL: time.Minute, CacheEntries: 4, MaxEvents: 1})

	_, _, err := ag.GovernOutput(AggregateResult{
		SessionID:   "sess-1",
		Synthesized: "different output",
		Sources: []AggregationSource{{AgentID: "a1", Output: "safe output"}},
	})
	if err == nil || !strings.Contains(err.Error(), "SEMANTIC_DRIFT_EXCEEDED") {
		t.Fatalf("expected semantic drift denial, got %v", err)
	}
	if len(ag.SemanticDriftEvents()) != 1 {
		t.Fatalf("expected one drift event")
	}
}
