package idp

import (
	"context"
	"fmt"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// OIDCConfig holds configuration for an OIDC-based identity provider.
type OIDCConfig struct {
	Issuer      string
	Audience    string
	ClientID    string
	GroupsClaim string
	RolesClaim  string
	OrgClaim    string
}

// OIDCVerifier verifies OIDC ID tokens using the provider's JWKS endpoint.
type OIDCVerifier struct {
	provider string
	cfg      OIDCConfig
	verifier *gooidc.IDTokenVerifier
}

// NewOIDCVerifier creates a new OIDC verifier. The provider discovery happens
// lazily on first token verification to avoid blocking startup.
func NewOIDCVerifier(provider string, cfg OIDCConfig) *OIDCVerifier {
	return &OIDCVerifier{
		provider: provider,
		cfg:      cfg,
	}
}

// VerifyToken validates an OIDC ID token and returns a VerifiedIdentity.
func (v *OIDCVerifier) VerifyToken(ctx context.Context, rawToken string) (*VerifiedIdentity, error) {
	if v.cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: issuer not configured for provider %q", v.provider)
	}

	// Lazy initialise the verifier on first call.
	if v.verifier == nil {
		p, err := gooidc.NewProvider(ctx, v.cfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc: discover %s: %w", v.cfg.Issuer, err)
		}
		oidcCfg := &gooidc.Config{ClientID: v.cfg.ClientID}
		if v.cfg.Audience != "" {
			oidcCfg.ClientID = v.cfg.Audience
		}
		v.verifier = p.Verifier(oidcCfg)
	}

	idToken, err := v.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify token: %w", err)
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: extract claims: %w", err)
	}

	identity := &VerifiedIdentity{
		Provider:   v.provider,
		VerifiedAt: time.Now(),
		ExpiresAt:  idToken.Expiry,
		RawClaims:  claims,
	}

	if sub, ok := claims["sub"].(string); ok {
		identity.Subject = sub
	}
	if email, ok := claims["email"].(string); ok {
		identity.Email = email
	}
	if name, ok := claims["name"].(string); ok {
		identity.Name = name
	}
	if org, ok := claims["org"].(string); ok {
		identity.Org = org
	}

	// Extract groups from configured claim.
	groupsClaim := v.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	if raw, ok := claims[groupsClaim]; ok {
		identity.Groups = toStringSlice(raw)
	}

	// Extract roles from configured claim.
	rolesClaim := v.cfg.RolesClaim
	if rolesClaim == "" {
		rolesClaim = "roles"
	}
	if raw, ok := claims[rolesClaim]; ok {
		identity.Roles = toStringSlice(raw)
	}

	return identity, nil
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}
