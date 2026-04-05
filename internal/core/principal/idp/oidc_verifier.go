package idp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
)

// OIDCConfig configures OIDC token verification behavior.
type OIDCConfig struct {
	Issuer      string
	Audience    string
	ClientID    string
	GroupsClaim string
	RolesClaim  string
	OrgClaim    string
}

// OIDCVerifier verifies bearer tokens using OIDC discovery and JWKS keys.
type OIDCVerifier struct {
	providerName string
	config       OIDCConfig

	mu       sync.RWMutex
	verifier *oidc.IDTokenVerifier
}

// NewOIDCVerifier creates an OIDC-backed token verifier.
func NewOIDCVerifier(providerName string, cfg OIDCConfig) *OIDCVerifier {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "roles"
	}
	if cfg.OrgClaim == "" {
		cfg.OrgClaim = "org"
	}
	return &OIDCVerifier{providerName: strings.ToLower(strings.TrimSpace(providerName)), config: cfg}
}

// VerifyToken validates a bearer token and extracts normalized identity claims.
func (v *OIDCVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	tok := normalizeBearerToken(token)
	if tok == "" {
		return nil, fmt.Errorf("oidc: token is empty")
	}

	verifier, err := v.getVerifier(ctx)
	if err != nil {
		return nil, err
	}

	idToken, err := verifier.Verify(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify token: %w", err)
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: decode claims: %w", err)
	}

	subject := claimString(claims, "sub")
	email := claimString(claims, "email")
	name := claimString(claims, "name")
	if strings.TrimSpace(subject) == "" && strings.TrimSpace(email) == "" && strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("oidc: missing subject/email/name claim")
	}

	org := claimString(claims, v.config.OrgClaim, "org", "hd", "tenant", "tenant_id", "tid")
	groups := claimStringSlice(claims, v.config.GroupsClaim, "groups")
	roles := claimStringSlice(claims, v.config.RolesClaim, "roles")

	return &VerifiedIdentity{
		Subject:    subject,
		Email:      email,
		Name:       name,
		Groups:     groups,
		Roles:      roles,
		Org:        org,
		Provider:   v.providerName,
		VerifiedAt: time.Now().UTC(),
		ExpiresAt:  idToken.Expiry,
		RawClaims:  claims,
	}, nil
}

func (v *OIDCVerifier) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.RLock()
	if v.verifier != nil {
		defer v.mu.RUnlock()
		return v.verifier, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}

	issuer := strings.TrimSpace(v.config.Issuer)
	if issuer == "" {
		return nil, fmt.Errorf("oidc: issuer is required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer %q: %w", issuer, err)
	}

	oidcCfg := &oidc.Config{}
	expectedAudience := strings.TrimSpace(v.config.Audience)
	if expectedAudience == "" {
		expectedAudience = strings.TrimSpace(v.config.ClientID)
	}
	if expectedAudience == "" {
		oidcCfg.SkipClientIDCheck = true
	} else {
		oidcCfg.ClientID = expectedAudience
	}

	v.verifier = provider.Verifier(oidcCfg)
	return v.verifier, nil
}

func normalizeBearerToken(token string) string {
	tok := strings.TrimSpace(token)
	if len(tok) >= len("bearer ") && strings.EqualFold(tok[:len("bearer ")], "bearer ") {
		return strings.TrimSpace(tok[len("bearer "):])
	}
	return tok
}

func claimString(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		v, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := v.(type) {
		case string:
			if s := strings.TrimSpace(typed); s != "" {
				return s
			}
		case []any:
			for _, entry := range typed {
				if s, ok := entry.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

func claimStringSlice(claims map[string]any, keys ...string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, key := range keys {
		v, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := v.(type) {
		case string:
			s := strings.TrimSpace(typed)
			if s != "" {
				if _, exists := seen[s]; !exists {
					out = append(out, s)
					seen[s] = struct{}{}
				}
			}
		case []any:
			for _, entry := range typed {
				s, ok := entry.(string)
				if !ok {
					continue
				}
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				if _, exists := seen[s]; exists {
					continue
				}
				out = append(out, s)
				seen[s] = struct{}{}
			}
		case []string:
			for _, s := range typed {
				s = strings.TrimSpace(s)
				if s == "" {
					continue
				}
				if _, exists := seen[s]; exists {
					continue
				}
				out = append(out, s)
				seen[s] = struct{}{}
			}
		}
	}
	return out
}
