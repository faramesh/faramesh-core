package main

import (
	"os"
	"testing"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

func TestOnboardPolicyRequiresCredentialSequestration(t *testing.T) {
	doc := &policy.Doc{
		Tools: map[string]policy.Tool{
			"stripe/refund": {Tags: []string{"credential:broker"}},
		},
	}
	if !onboardPolicyRequiresCredentialSequestration(doc) {
		t.Fatalf("expected credential sequestration requirement from tool tags")
	}
}

func TestOnboardPolicyRequiresIDPProvider(t *testing.T) {
	doc := &policy.Doc{
		Rules: []policy.Rule{
			{ID: "principal-check", Match: policy.Match{Tool: "*", When: `principal.verified && principal.role == "admin"`}, Effect: "permit"},
		},
	}
	if !onboardPolicyRequiresIDPProvider(doc) {
		t.Fatalf("expected IdP requirement when policy references principal.*")
	}
}

func TestOnboardMissingDeferBackends(t *testing.T) {
	doc := &policy.Doc{
		Rules: []policy.Rule{{ID: "defer-sensitive", Match: policy.Match{Tool: "*", When: "true"}, Effect: "defer"}},
		DeferPriority: &policy.DeferPriorityConfig{
			Critical: &policy.DeferTier{Channel: "slack"},
			High:     &policy.DeferTier{Channel: "pagerduty"},
		},
	}
	missing := onboardMissingDeferBackends(doc, "", "")
	if len(missing) != 2 {
		t.Fatalf("expected 2 missing defer backends, got %d (%v)", len(missing), missing)
	}
}

func TestOnboardHasCredentialSequestrationBackend(t *testing.T) {
	cfg := onboardCredentialConfig{VaultAddr: "https://vault.internal"}
	if !onboardHasCredentialSequestrationBackend(cfg) {
		t.Fatalf("expected credential backend detection for vault")
	}
}

func TestEvaluateIDPReadinessUsesDefaultProvider(t *testing.T) {
	t.Setenv("FARAMESH_IDP_PROVIDER", "")
	check := evaluateIDPReadiness(&policy.Doc{
		Rules: []policy.Rule{{ID: "principal-check", Match: policy.Match{Tool: "*", When: "principal.verified"}, Effect: "permit"}},
	}, true, "")
	if check.Status != onboardStatusPass {
		t.Fatalf("expected pass with default local idp provider, got %s (%s)", check.Status, check.Details)
	}
}

func TestOnboardHasCredentialSequestrationBackendEnvFallback(t *testing.T) {
	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "true")
	if !onboardHasCredentialSequestrationBackend(onboardCredentialConfig{}) {
		t.Fatalf("expected env fallback to satisfy credential backend readiness")
	}

	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "false")
	if onboardHasCredentialSequestrationBackend(onboardCredentialConfig{}) {
		t.Fatalf("expected backend readiness to fail when env fallback is disabled")
	}

	_ = os.Unsetenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK")
}
