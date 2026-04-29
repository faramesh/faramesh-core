package deferwork

import "testing"

func TestDeferContextSessionStateHashIsDeterministic(t *testing.T) {
	left := NewDeferContext("tok", "sess", "policy", nil)
	left.SetSessionStateHash(map[string]any{
		"b": 2,
		"a": 1,
	})

	right := NewDeferContext("tok", "sess", "policy", nil)
	right.SetSessionStateHash(map[string]any{
		"a": 1,
		"b": 2,
	})

	if left.SessionStateHash != right.SessionStateHash {
		t.Fatalf("hash mismatch: left=%q right=%q", left.SessionStateHash, right.SessionStateHash)
	}
}
