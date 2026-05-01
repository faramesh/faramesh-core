package semantic

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestCosineSimilarityAndDistance(t *testing.T) {
	sim, err := CosineSimilarity([]float64{1, 0}, []float64{1, 0})
	if err != nil {
		t.Fatalf("CosineSimilarity error: %v", err)
	}
	if sim != 1 {
		t.Fatalf("similarity = %v, want 1", sim)
	}
	dist, err := CosineDistance([]float64{1, 0}, []float64{1, 0})
	if err != nil {
		t.Fatalf("CosineDistance error: %v", err)
	}
	if dist != 0 {
		t.Fatalf("distance = %v, want 0", dist)
	}
}

func TestCentroid(t *testing.T) {
	got, err := Centroid([][]float64{{1, 1}, {3, 5}})
	if err != nil {
		t.Fatalf("Centroid error: %v", err)
	}
	want := []float64{2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("centroid = %#v, want %#v", got, want)
	}
}

func TestProviderFunc(t *testing.T) {
	p := ProviderFunc{
		ProviderID: "mock",
		EmbedFunc: func(_ context.Context, texts []string) ([][]float64, error) {
			out := make([][]float64, len(texts))
			for i := range texts {
				out[i] = []float64{float64(len(texts[i]))}
			}
			return out, nil
		},
	}
	vecs, err := p.Embed(context.Background(), []string{"aa", "bbbb"})
	if err != nil {
		t.Fatalf("Embed error: %v", err)
	}
	if p.ID() != "mock" {
		t.Fatalf("ID = %q, want mock", p.ID())
	}
	if len(vecs) != 2 || vecs[0][0] != 2 || vecs[1][0] != 4 {
		t.Fatalf("unexpected vectors: %#v", vecs)
	}
}

func TestCachingProviderCachesResults(t *testing.T) {
	calls := 0
	base := ProviderFunc{
		ProviderID: "cache-base",
		EmbedFunc: func(_ context.Context, texts []string) ([][]float64, error) {
			calls++
			out := make([][]float64, len(texts))
			for i, text := range texts {
				out[i] = []float64{float64(len(text))}
			}
			return out, nil
		},
	}
	cache := NewCachingProvider(base, 10*time.Minute, 8)
	first, err := cache.Embed(context.Background(), []string{"one", "two"})
	if err != nil {
		t.Fatalf("Embed error: %v", err)
	}
	second, err := cache.Embed(context.Background(), []string{"one", "two"})
	if err != nil {
		t.Fatalf("Embed error: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if len(first) != 2 || len(second) != 2 || first[0][0] != second[0][0] {
		t.Fatalf("cached vectors mismatch: first=%#v second=%#v", first, second)
	}
}
