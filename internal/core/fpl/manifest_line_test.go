package fpl

import "testing"

func TestParseManifestLine_grantErrors(t *testing.T) {
	for _, s := range []string{
		"manifest grant x to y max",
		"manifest grant x to y max n",
		"manifest grant x agent y max 1",
	} {
		if _, err := parseManifestLine(s); err == nil {
			t.Fatalf("expected error for %q", s)
		}
	}
}
