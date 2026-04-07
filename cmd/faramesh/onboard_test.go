package main

import (
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
	if !onboardHasCredentialSequestrationBackend(cfg, false) {
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

func TestEvaluateIDPReadinessNotRequiredIsPass(t *testing.T) {
	check := evaluateIDPReadiness(&policy.Doc{
		Rules: []policy.Rule{{ID: "safe-rule", Match: policy.Match{Tool: "*", When: "true"}, Effect: "permit"}},
	}, true, "")
	if check.Status != onboardStatusPass {
		t.Fatalf("expected pass when policy does not require principal/delegation claims, got %s (%s)", check.Status, check.Details)
	}
}

func TestEvaluateHITLReadinessNoDeferIsPass(t *testing.T) {
	check := evaluateHITLReadiness(&policy.Doc{
		Rules: []policy.Rule{{ID: "allow", Match: policy.Match{Tool: "*", When: "true"}, Effect: "permit"}},
	}, "", "")
	if check.Status != onboardStatusPass {
		t.Fatalf("expected pass when policy has no defer effects, got %s (%s)", check.Status, check.Details)
	}
}

func TestEvaluateIdentityReadinessWithSPIFFEIDOverride(t *testing.T) {
	t.Setenv("FARAMESH_SPIFFE_ID", "spiffe://example.org/agent/test")
	check := evaluateIdentityReadiness(true, "", "spiffe://example.org/agent/test")
	if check.Status != onboardStatusPass {
		t.Fatalf("expected pass when SPIFFE ID override is configured, got %s (%s)", check.Status, check.Details)
	}
}

func TestOnboardAllowEnvCredentialFallbackByProfile(t *testing.T) {
	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "")
	if onboardAllowEnvCredentialFallback("production") {
		t.Fatalf("expected production profile to default env fallback to disabled")
	}
	if !onboardAllowEnvCredentialFallback("development") {
		t.Fatalf("expected development profile to default env fallback to enabled")
	}

	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "true")
	if !onboardAllowEnvCredentialFallback("production") {
		t.Fatalf("expected explicit env override=true to enable fallback")
	}

	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "false")
	if onboardAllowEnvCredentialFallback("development") {
		t.Fatalf("expected explicit env override=false to disable fallback")
	}
}

func TestEvaluateCredentialSequestrationReadinessRejectsEnvInProductionProfile(t *testing.T) {
	prevProfile := onboardCredentialProfile
	prevBackend := onboardCredentialBackend
	prevInteractive := onboardInteractive
	t.Cleanup(func() {
		onboardCredentialProfile = prevProfile
		onboardCredentialBackend = prevBackend
		onboardInteractive = prevInteractive
	})

	onboardCredentialProfile = "production"
	onboardCredentialBackend = "env"
	onboardInteractive = false

	doc := &policy.Doc{
		Tools: map[string]policy.Tool{
			"stripe/refund": {Tags: []string{"credential:broker"}},
		},
	}

	check := evaluateCredentialSequestrationReadiness(doc, true, &onboardCredentialConfig{})
	if check.Status != onboardStatusFail {
		t.Fatalf("expected fail when production profile selects env backend, got %s (%s)", check.Status, check.Details)
	}
}

func TestEvaluateCredentialSequestrationReadinessAllowsEnvInDevelopmentProfile(t *testing.T) {
	prevProfile := onboardCredentialProfile
	prevBackend := onboardCredentialBackend
	prevInteractive := onboardInteractive
	t.Cleanup(func() {
		onboardCredentialProfile = prevProfile
		onboardCredentialBackend = prevBackend
		onboardInteractive = prevInteractive
	})

	onboardCredentialProfile = "development"
	onboardCredentialBackend = "env"
	onboardInteractive = false

	doc := &policy.Doc{
		Tools: map[string]policy.Tool{
			"stripe/refund": {Tags: []string{"credential:broker"}},
		},
	}

	check := evaluateCredentialSequestrationReadiness(doc, true, &onboardCredentialConfig{})
	if check.Status != onboardStatusWarn {
		t.Fatalf("expected warning when development profile selects env fallback, got %s (%s)", check.Status, check.Details)
	}
}

func TestEvaluateCredentialSequestrationReadinessLocalVaultSelection(t *testing.T) {
	prevProfile := onboardCredentialProfile
	prevBackend := onboardCredentialBackend
	prevInteractive := onboardInteractive
	t.Cleanup(func() {
		onboardCredentialProfile = prevProfile
		onboardCredentialBackend = prevBackend
		onboardInteractive = prevInteractive
	})

	onboardCredentialProfile = "production"
	onboardCredentialBackend = "local-vault"
	onboardInteractive = false

	doc := &policy.Doc{
		Tools: map[string]policy.Tool{
			"stripe/refund": {Tags: []string{"credential:required"}},
		},
	}
	cfg := onboardCredentialConfig{}
	check := evaluateCredentialSequestrationReadiness(doc, true, &cfg)
	if check.Status != onboardStatusPass {
		t.Fatalf("expected pass when local-vault is selected, got %s (%s)", check.Status, check.Details)
	}
	if cfg.VaultAddr != defaultLocalVaultAddr {
		t.Fatalf("expected local vault addr %q, got %q", defaultLocalVaultAddr, cfg.VaultAddr)
	}
}

func TestEvaluateCredentialSequestrationReadinessNotRequiredIsPass(t *testing.T) {
	check := evaluateCredentialSequestrationReadiness(&policy.Doc{
		Tools: map[string]policy.Tool{
			"safe/tool": {Tags: []string{"audit"}},
		},
	}, true, &onboardCredentialConfig{})
	if check.Status != onboardStatusPass {
		t.Fatalf("expected pass when policy does not require credential sequestration, got %s (%s)", check.Status, check.Details)
	}
}
