package canonicalize

import (
	"testing"
)

func TestJCSBasicObjectKeyOrdering(t *testing.T) {
	in := map[string]interface{}{
		"b": 1,
		"a": 2,
	}
	out, err := JCSMarshal(in)
	if err != nil {
		t.Fatalf("JCSMarshal error: %v", err)
	}
	got := string(out)
	want := "{\"a\":2,\"b\":1}"
	if got != want {
		t.Fatalf("unexpected canonical output.\n got: %s\nwant: %s", got, want)
	}
}

func TestJCSNumberFormatting(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{1.0, "1"},
		{1.200, "1.2"},
		{1e9, "1e+09"},
	}
	for _, c := range cases {
		out, err := JCSMarshal(c.in)
		if err != nil {
			t.Fatalf("JCSMarshal error: %v", err)
		}
		got := string(out)
		if got != c.want {
			t.Fatalf("number formatting mismatch: in=%v got=%s want=%s", c.in, got, c.want)
		}
	}
}

func TestJCSStringEscaping(t *testing.T) {
	in := map[string]interface{}{"s": "a\nb\"c"}
	out, err := JCSMarshal(in)
	if err != nil {
		t.Fatalf("JCSMarshal error: %v", err)
	}
	got := string(out)
	want := "{\"s\":\"a\\nb\\\"c\"}"
	if got != want {
		t.Fatalf("string escaping mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestJCSNestedOrderingAndArrays(t *testing.T) {
	in := map[string]interface{}{
		"z": []interface{}{3, 2, 1},
		"a": map[string]interface{}{"b": 2, "a": 1},
	}
	out, err := JCSMarshal(in)
	if err != nil {
		t.Fatalf("JCSMarshal error: %v", err)
	}
	got := string(out)
	want := "{\"a\":{\"a\":1,\"b\":2},\"z\":[3,2,1]}"
	if got != want {
		t.Fatalf("nested ordering mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestJCSUnicodeKeyOrdering(t *testing.T) {
	in := map[string]interface{}{
		"β": 2,
		"α": 1,
	}
	out, err := JCSMarshal(in)
	if err != nil {
		t.Fatalf("JCSMarshal error: %v", err)
	}
	got := string(out)
	// Ordering is by Unicode code point; alpha (α) comes before beta (β).
	want := "{\"α\":1,\"β\":2}"
	if got != want {
		t.Fatalf("unicode key ordering mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestJCSNumberRFCVectors(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{123456789012345.0, "1.23456789012345e+14"},
		{0.0000001234, "1.234e-07"},
		{-0.0000001234, "-1.234e-07"},
		{1.234e-10, "1.234e-10"},
	}
	for _, c := range cases {
		out, err := JCSMarshal(c.in)
		if err != nil {
			t.Fatalf("JCSMarshal error: %v", err)
		}
		got := string(out)
		if got != c.want {
			t.Fatalf("RFC-like number formatting mismatch: in=%v got=%s want=%s", c.in, got, c.want)
		}
	}
}
