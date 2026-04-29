package core

import "testing"

func TestUsageTokensFromArgs(t *testing.T) {
	if n := UsageTokensFromArgs(nil); n != 0 {
		t.Fatalf("nil args: %d", n)
	}
	if n := UsageTokensFromArgs(map[string]any{"_faramesh.tokens": 42}); n != 42 {
		t.Fatalf("underscore key: %d", n)
	}
	if n := UsageTokensFromArgs(map[string]any{"usage_tokens": float64(100)}); n != 100 {
		t.Fatalf("usage_tokens float: %d", n)
	}
	if n := UsageTokensFromArgs(map[string]any{"_faramesh": map[string]any{"tokens": int64(7)}}); n != 7 {
		t.Fatalf("nested: %d", n)
	}
	if n := UsageTokensFromArgs(map[string]any{"_faramesh.tokens": -1}); n != 0 {
		t.Fatalf("negative ignored: %d", n)
	}
}
