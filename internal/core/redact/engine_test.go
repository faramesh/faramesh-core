package redact

import (
	"strings"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/agentgov"
)

func TestEngine_ApplyHMACRedactsPath(t *testing.T) {
	eng := NewEngine([]byte("test-key"), []agentgov.Redaction{{
		Tool: "stripe/charge", Paths: []string{"card.number"},
	}})
	out, err := eng.Apply("stripe/charge", map[string]any{
		"card": map[string]any{"number": "4242424242424242"},
	})
	if err != nil {
		t.Fatal(err)
	}
	card := out["card"].(map[string]any)
	v := card["number"].(string)
	if !strings.HasPrefix(v, "hmac:") {
		t.Fatalf("expected hmac redaction, got %q", v)
	}
}

func TestEngine_MissingPathFailsClosed(t *testing.T) {
	eng := NewEngine([]byte("k"), []agentgov.Redaction{{Tool: "*", Paths: []string{"missing"}}})
	_, err := eng.Apply("tool", map[string]any{"ok": true})
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}
