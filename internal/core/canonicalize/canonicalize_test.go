package canonicalize

import (
	"math"
	"reflect"
	"testing"
)

func TestArgs_StringHardening_StripsNullAndInvisible(t *testing.T) {
	in := map[string]any{
		"command": "rm -rf /\x00safe-suffix",
		"note":    "he\u200Bllo",
		"soft":    "a\u00ADb",
	}

	out := Args(in)

	if got := out["command"]; got != "rm -rf /" {
		t.Fatalf("command mismatch: got %v want %q", got, "rm -rf /")
	}
	if got := out["note"]; got != "hello" {
		t.Fatalf("note mismatch: got %v want %q", got, "hello")
	}
	if got := out["soft"]; got != "ab" {
		t.Fatalf("soft mismatch: got %v want %q", got, "ab")
	}
}

func TestToolID_Hardening_StripsNullAndInvisible(t *testing.T) {
	id := " shell\u200B/exec\x00evil "
	got := ToolID(id)
	if got != "shell/exec" {
		t.Fatalf("ToolID() = %q, want %q", got, "shell/exec")
	}
}

func TestValue_TypedSliceCanonicalization(t *testing.T) {
	in := []string{" hеllo ", "ok\u200B", "safe\x00suffix"}

	out, ok := Value(in).([]any)
	if !ok {
		t.Fatalf("Value([]string) type = %T, want []any", Value(in))
	}

	want := []any{"hello", "ok", "safe"}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("typed string slice canonicalization mismatch:\n got:  %v\n want: %v", out, want)
	}

	floatIn := []float64{0.1 + 0.2, math.Inf(1), math.NaN()}
	floatOut, ok := Value(floatIn).([]any)
	if !ok {
		t.Fatalf("Value([]float64) type = %T, want []any", Value(floatIn))
	}
	if len(floatOut) != 3 {
		t.Fatalf("Value([]float64) len = %d, want 3", len(floatOut))
	}
	if got, ok := floatOut[0].(float64); !ok || got < 0.29999999 || got > 0.30000001 {
		t.Fatalf("float artifact not normalized: got %v", floatOut[0])
	}
	if got, ok := floatOut[1].(float64); !ok || got != 0 {
		t.Fatalf("+Inf not normalized to 0: got %v", floatOut[1])
	}
	if got, ok := floatOut[2].(float64); !ok || got != 0 {
		t.Fatalf("NaN not normalized to 0: got %v", floatOut[2])
	}
}

func TestValue_TypedMapCanonicalizationAndCollisionPreference(t *testing.T) {
	in := map[string]string{
		"amount ":    "2000",
		"amount":     "1000",
		"paylоad":    "spoof", // Cyrillic о
		"payload":    "real",
		"tool\u200b": "shell/exec",
	}

	out, ok := Value(in).(map[string]any)
	if !ok {
		t.Fatalf("Value(map[string]string) type = %T, want map[string]any", Value(in))
	}

	if got := out["amount"]; got != "1000" {
		t.Fatalf("canonical key collision should keep canonical key value: got %v want %q", got, "1000")
	}
	if got := out["payload"]; got != "real" {
		t.Fatalf("confusable key collision should keep canonical key value: got %v want %q", got, "real")
	}
	if got := out["tool"]; got != "shell/exec" {
		t.Fatalf("invisible key normalization failed: got %v want %q", got, "shell/exec")
	}
}

func TestArgs_IdempotentWithTypedCollections(t *testing.T) {
	in := map[string]any{
		"nested": map[string]any{
			"a\u200b": "hеllo",
			"b":       "rm -rf /\x00tail",
		},
		"typed": []string{" one ", "two\u200b"},
	}

	first := Args(in)
	second := Args(first)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Args is not idempotent:\n first:  %v\n second: %v", first, second)
	}
}
