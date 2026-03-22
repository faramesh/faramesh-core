package hub

import "testing"

func TestParsePackRef(t *testing.T) {
	n, v, err := ParsePackRef("org/pack@1.2.3")
	if err != nil || n != "org/pack" || v != "1.2.3" {
		t.Fatalf("got %q %q %v", n, v, err)
	}
	n, v, err = ParsePackRef("solo")
	if err != nil || n != "solo" || v != "" {
		t.Fatalf("got %q %q %v", n, v, err)
	}
}
