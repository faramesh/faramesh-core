package core

import (
	"context"
	"errors"
	"testing"
	"time"

	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

const principalPolicy = `
faramesh-version: "1.0"
agent-id: "principal-test-agent"

rules:
  - id: permit-enterprise
    match:
      tool: "billing/export"
      when: "principal.verified && principal.tier == 'enterprise'"
    effect: permit
    reason: "enterprise principal allowed"

default_effect: deny
`

func buildPrincipalPipeline(
	t *testing.T,
	rm *principal.RevocationManager,
	ee *principal.ElevationEngine,
	wd WorkloadIdentityDetector,
) *Pipeline {
	t.Helper()
	doc, ver, err := policy.LoadBytes([]byte(principalPolicy))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	eng, err := policy.NewEngine(doc, ver)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return NewPipeline(Config{
		Engine:           policy.NewAtomicEngine(eng),
		Sessions:         session.NewManager(),
		Defers:           deferwork.NewWorkflow(""),
		Revocations:      rm,
		Elevations:       ee,
		WorkloadIdentity: wd,
	})
}

func principalReq(callID string, principalID *principal.Identity) CanonicalActionRequest {
	return CanonicalActionRequest{
		CallID:    callID,
		AgentID:   "principal-agent",
		SessionID: "principal-session",
		ToolID:    "billing/export",
		Args:      map[string]any{},
		Principal: principalID,
		Timestamp: time.Now(),
	}
}

type fakeWorkloadDetector struct {
	id *principal.Identity
}

func (f *fakeWorkloadDetector) Identity(_ context.Context) (*principal.Identity, error) {
	return f.id, nil
}

type failingWorkloadDetector struct{}

func (f *failingWorkloadDetector) Identity(_ context.Context) (*principal.Identity, error) {
	return nil, errors.New("spiffe unavailable")
}

func TestPrincipalRevocationPreEvalDeny(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	rm.Revoke(principal.RevocationEvent{
		PrincipalID:  "user-revoked",
		Reason:       "admin",
		Source:       "admin_api",
		RevertToTier: "free",
	})
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-revoked", &principal.Identity{
		ID:       "user-revoked",
		Tier:     "enterprise",
		Verified: true,
		Method:   "spiffe",
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("expected DENY for revoked principal, got %s", d.Effect)
	}
	if d.ReasonCode != reasons.PrincipalRevoked {
		t.Fatalf("expected reason %s, got %s", reasons.PrincipalRevoked, d.ReasonCode)
	}
}

func TestPrincipalElevationGrantAugmentsTierBeforeEval(t *testing.T) {
	ee := principal.NewElevationEngine(&principal.ElevationPolicy{
		Transitions: map[string]principal.ElevationConstraints{
			"free→enterprise": {RequireMFA: true, MaxTTL: 10 * time.Minute},
		},
	})
	rm := principal.NewRevocationManager(ee)
	grant, err := ee.RequestElevation(principal.ElevationRequest{
		PrincipalID: "user-elevated",
		CurrentTier: "free",
		TargetTier:  "enterprise",
		MFAMethod:   "totp",
		Reason:      "break-glass",
	})
	if err != nil || grant == nil {
		t.Fatalf("request elevation: %v", err)
	}
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-elevated", &principal.Identity{
		ID:       "user-elevated",
		Tier:     "free",
		Verified: true,
		Method:   "spiffe",
	}))
	if d.Effect != EffectPermit {
		t.Fatalf("expected PERMIT with active elevation grant, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestWorkloadIdentityFallbackInjectsPrincipalWhenMissing(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	wd := &fakeWorkloadDetector{
		id: &principal.Identity{
			ID:       "workload:svc-prod",
			Tier:     "enterprise",
			Verified: true,
			Method:   "aws_irsa",
			Org:      "acme",
		},
	}
	p := buildPrincipalPipeline(t, rm, ee, wd)

	d := p.Evaluate(principalReq("principal-missing", nil))
	if d.Effect != EffectPermit {
		t.Fatalf("expected PERMIT when workload identity is injected, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestConfiguredSPIFFEProviderSuccessPath(t *testing.T) {
	t.Setenv("FARAMESH_SPIFFE_ID", "spiffe://acme.local/ns/prod/sa/governor")
	t.Setenv("FARAMESH_SPIFFE_TIER", "enterprise")
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, principal.NewSPIFFEProvider("unix:///tmp/spire-agent.sock"))

	d := p.Evaluate(principalReq("principal-spiffe-success", nil))
	if d.Effect != EffectPermit {
		t.Fatalf("expected PERMIT when configured SPIFFE provider resolves identity, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestWorkloadIdentityFallbackReplacesUnverifiedPrincipal(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	wd := &fakeWorkloadDetector{
		id: &principal.Identity{
			ID:       "workload:svc-prod",
			Tier:     "enterprise",
			Verified: true,
			Method:   "github_oidc",
			Org:      "acme",
		},
	}
	p := buildPrincipalPipeline(t, rm, ee, wd)

	d := p.Evaluate(principalReq("principal-unverified", &principal.Identity{
		ID:       "self-asserted",
		Tier:     "free",
		Verified: false,
	}))
	if d.Effect != EffectPermit {
		t.Fatalf("expected PERMIT when unverified principal is replaced by workload identity, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestConfiguredSPIFFEProviderFailureFallsBackSafely(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, &failingWorkloadDetector{})

	d := p.Evaluate(principalReq("principal-spiffe-fail", nil))
	if d.Effect != EffectDeny {
		t.Fatalf("expected fallback DENY when SPIFFE provider fails and no principal is present, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestNoSPIFFEConfiguredUnverifiedPrincipalUnchanged(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-no-spiffe", &principal.Identity{
		ID:       "self-asserted",
		Tier:     "enterprise",
		Verified: false,
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("expected DENY without SPIFFE provider for unverified principal, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestPrincipalNormalPathNonRegression(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-normal", &principal.Identity{
		ID:       "user-normal",
		Tier:     "enterprise",
		Verified: true,
		Method:   "spiffe",
	}))
	if d.Effect != EffectPermit {
		t.Fatalf("expected normal verified principal to stay PERMIT, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestPrincipalVerifiedSpoofedMethodDenied(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-spoofed-method", &principal.Identity{
		ID:       "user-spoofed",
		Tier:     "enterprise",
		Verified: true,
		Method:   "x-forwarded-user",
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("expected DENY for spoofed verified method, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.PrincipalVerificationUntrusted {
		t.Fatalf("expected reason %s, got %s", reasons.PrincipalVerificationUntrusted, d.ReasonCode)
	}
}

func TestPrincipalVerifiedTrustedMethodPasses(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-trusted-method", &principal.Identity{
		ID:       "user-trusted",
		Tier:     "enterprise",
		Verified: true,
		Method:   "spiffe",
	}))
	if d.Effect != EffectPermit {
		t.Fatalf("expected PERMIT for trusted verified method, got %s (%s)", d.Effect, d.Reason)
	}
}

func TestPrincipalVerifiedMissingMethodDenied(t *testing.T) {
	ee := principal.NewElevationEngine(nil)
	rm := principal.NewRevocationManager(ee)
	p := buildPrincipalPipeline(t, rm, ee, nil)

	d := p.Evaluate(principalReq("principal-missing-method", &principal.Identity{
		ID:       "user-missing-method",
		Tier:     "enterprise",
		Verified: true,
	}))
	if d.Effect != EffectDeny {
		t.Fatalf("expected DENY when verified principal method is missing, got %s (%s)", d.Effect, d.Reason)
	}
	if d.ReasonCode != reasons.PrincipalVerificationUntrusted {
		t.Fatalf("expected reason %s, got %s", reasons.PrincipalVerificationUntrusted, d.ReasonCode)
	}
}
