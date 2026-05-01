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
