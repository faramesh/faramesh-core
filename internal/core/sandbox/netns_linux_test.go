//go:build linux

package sandbox

import "testing"

func TestBuildNetNSRedirectRulesPlacesAllowedCIDRsBeforeRedirects(t *testing.T) {
	rules := buildNetNSRedirectRules("ns-a", []string{"10.0.0.0/8", "127.0.0.1/32"}, []int{443}, "18443")
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	if got := rules[0][len(rules[0])-1]; got != "ACCEPT" {
		t.Fatalf("first rule should be ACCEPT for allowed CIDR, got %#v", rules[0])
	}
	if got := rules[1][len(rules[1])-1]; got != "ACCEPT" {
		t.Fatalf("second rule should be ACCEPT for allowed CIDR, got %#v", rules[1])
	}
	if got := rules[2][len(rules[2])-3]; got != "REDIRECT" {
		t.Fatalf("third rule should be REDIRECT, got %#v", rules[2])
	}
}
