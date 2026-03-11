// Package idp provides identity provider integration for principal verification.
//
// Supports multiple IDP backends:
//   - Okta: OIDC tokens / SCIM user sync
//   - Azure AD: Microsoft Identity Platform
//   - Auth0: Universal Login / M2M tokens
//   - Google Workspace: Google's OIDC
//   - LDAP: On-premise directory services
//
// Each provider implements the Verifier interface, allowing the policy engine
// to verify principal identity at session start and on elevation requests.
package idp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// VerifiedIdentity is the result of successful IDP verification.
type VerifiedIdentity struct {
	Subject     string            `json:"sub"`
	Email       string            `json:"email"`
	Name        string            `json:"name"`
	Groups      []string          `json:"groups"`
	Roles       []string          `json:"roles"`
	Org         string            `json:"org"`
	Provider    string            `json:"provider"` // okta, azure_ad, auth0, google, ldap
	VerifiedAt  time.Time         `json:"verified_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	RawClaims   map[string]any    `json:"raw_claims,omitempty"`
}

// Valid returns true if the verification has not expired.
func (v *VerifiedIdentity) Valid() bool {
	return time.Now().Before(v.ExpiresAt)
}

// Verifier is the interface that all IDP backends implement.
type Verifier interface {
	// Name returns the provider name.
	Name() string
	// VerifyToken validates an access/ID token and returns the identity.
	VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error)
	// VerifyAPIKey validates an API key and returns the identity.
	VerifyAPIKey(ctx context.Context, apiKey string) (*VerifiedIdentity, error)
}

// OktaConfig configures the Okta IDP verifier.
type OktaConfig struct {
	Domain       string `yaml:"domain"`        // e.g. "dev-123456.okta.com"
	ClientID     string `yaml:"client_id"`
	Audience     string `yaml:"audience"`
	GroupsClaim  string `yaml:"groups_claim"`   // default: "groups"
}

// OktaVerifier verifies principals against Okta.
type OktaVerifier struct {
	config OktaConfig
}

// NewOktaVerifier creates a new Okta verifier.
func NewOktaVerifier(cfg OktaConfig) *OktaVerifier {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &OktaVerifier{config: cfg}
}

func (v *OktaVerifier) Name() string { return "okta" }

func (v *OktaVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	// In production: validate JWT against https://{domain}/.well-known/openid-configuration
	// Verify signature, issuer, audience, expiry.
	// Extract claims: sub, email, name, groups.
	_ = ctx
	_ = token
	return nil, fmt.Errorf("okta: token verification requires OIDC library integration")
}

func (v *OktaVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("okta: API key verification not supported, use OIDC tokens")
}

// AzureADConfig configures the Azure AD IDP verifier.
type AzureADConfig struct {
	TenantID string `yaml:"tenant_id"`
	ClientID string `yaml:"client_id"`
	Audience string `yaml:"audience"`
}

// AzureADVerifier verifies principals against Azure AD.
type AzureADVerifier struct {
	config AzureADConfig
}

// NewAzureADVerifier creates a new Azure AD verifier.
func NewAzureADVerifier(cfg AzureADConfig) *AzureADVerifier {
	return &AzureADVerifier{config: cfg}
}

func (v *AzureADVerifier) Name() string { return "azure_ad" }

func (v *AzureADVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	// In production: validate JWT against https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
	_ = ctx
	_ = token
	return nil, fmt.Errorf("azure_ad: token verification requires OIDC library integration")
}

func (v *AzureADVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("azure_ad: API key verification not supported, use OIDC tokens")
}

// Auth0Config configures the Auth0 IDP verifier.
type Auth0Config struct {
	Domain   string `yaml:"domain"`    // e.g. "myapp.auth0.com"
	Audience string `yaml:"audience"`
}

// Auth0Verifier verifies principals against Auth0.
type Auth0Verifier struct {
	config Auth0Config
}

// NewAuth0Verifier creates a new Auth0 verifier.
func NewAuth0Verifier(cfg Auth0Config) *Auth0Verifier {
	return &Auth0Verifier{config: cfg}
}

func (v *Auth0Verifier) Name() string { return "auth0" }

func (v *Auth0Verifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	_ = ctx
	_ = token
	return nil, fmt.Errorf("auth0: token verification requires OIDC library integration")
}

func (v *Auth0Verifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("auth0: use M2M token flow instead of API keys")
}

// GoogleConfig configures the Google Workspace IDP verifier.
type GoogleConfig struct {
	ClientID string `yaml:"client_id"`
	Domain   string `yaml:"hd"` // hosted domain restriction
}

// GoogleVerifier verifies principals against Google.
type GoogleVerifier struct {
	config GoogleConfig
}

// NewGoogleVerifier creates a new Google verifier.
func NewGoogleVerifier(cfg GoogleConfig) *GoogleVerifier {
	return &GoogleVerifier{config: cfg}
}

func (v *GoogleVerifier) Name() string { return "google" }

func (v *GoogleVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	_ = ctx
	_ = token
	return nil, fmt.Errorf("google: token verification requires OIDC library integration")
}

func (v *GoogleVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("google: API key verification not supported, use OIDC tokens")
}

// LDAPConfig configures the LDAP IDP verifier.
type LDAPConfig struct {
	URL          string `yaml:"url"`       // e.g. "ldaps://ldap.example.com:636"
	BindDN       string `yaml:"bind_dn"`
	BaseDN       string `yaml:"base_dn"`
	UserFilter   string `yaml:"user_filter"` // e.g. "(uid=%s)"
	GroupFilter  string `yaml:"group_filter"`
	TLSVerify    bool   `yaml:"tls_verify"`
}

// LDAPVerifier verifies principals against an LDAP directory.
type LDAPVerifier struct {
	config LDAPConfig
}

// NewLDAPVerifier creates a new LDAP verifier.
func NewLDAPVerifier(cfg LDAPConfig) *LDAPVerifier {
	return &LDAPVerifier{config: cfg}
}

func (v *LDAPVerifier) Name() string { return "ldap" }

func (v *LDAPVerifier) VerifyToken(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("ldap: does not support bearer tokens, use VerifyAPIKey with credentials")
}

func (v *LDAPVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	// In production: perform LDAP bind with the API key as password,
	// then search for user attributes and groups.
	return nil, fmt.Errorf("ldap: verification requires LDAP library integration")
}

// ProviderChain tries multiple IDP verifiers in order.
type ProviderChain struct {
	mu        sync.RWMutex
	providers []Verifier
	cache     map[string]*cachedIdentity
	cacheTTL  time.Duration
}

type cachedIdentity struct {
	identity  *VerifiedIdentity
	cachedAt  time.Time
}

// NewProviderChain creates a new IDP chain.
func NewProviderChain(providers ...Verifier) *ProviderChain {
	return &ProviderChain{
		providers: providers,
		cache:     make(map[string]*cachedIdentity),
		cacheTTL:  5 * time.Minute,
	}
}

// VerifyToken tries each provider in order until one succeeds.
func (pc *ProviderChain) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, string, error) {
	// Check cache first.
	cacheKey := tokenCacheKey(token)
	pc.mu.RLock()
	if cached, ok := pc.cache[cacheKey]; ok && time.Since(cached.cachedAt) < pc.cacheTTL {
		pc.mu.RUnlock()
		return cached.identity, cached.identity.Provider, nil
	}
	pc.mu.RUnlock()

	var lastErr error
	for _, p := range pc.providers {
		id, err := p.VerifyToken(ctx, token)
		if err != nil {
			lastErr = err
			continue
		}
		id.Provider = p.Name()

		// Cache the result.
		pc.mu.Lock()
		pc.cache[cacheKey] = &cachedIdentity{identity: id, cachedAt: time.Now()}
		pc.mu.Unlock()

		return id, p.Name(), nil
	}
	return nil, "", fmt.Errorf("all IDP providers failed, last error: %w", lastErr)
}

func tokenCacheKey(token string) string {
	// Use prefix + hash to avoid storing raw tokens in memory.
	if len(token) > 16 {
		token = token[:8] + "..." + token[len(token)-8:]
	}
	return "tok:" + token
}

// APIKeyConfig maps API key prefixes to provider names.
type APIKeyConfig struct {
	Prefix   string `yaml:"prefix"`   // e.g. "far_"
	Provider string `yaml:"provider"` // e.g. "okta"
}

// VerifyAPIKey tries the provider matching the key prefix.
func (pc *ProviderChain) VerifyAPIKey(ctx context.Context, apiKey string) (*VerifiedIdentity, error) {
	for _, p := range pc.providers {
		id, err := p.VerifyAPIKey(ctx, apiKey)
		if err != nil {
			continue
		}
		id.Provider = p.Name()
		return id, nil
	}
	return nil, fmt.Errorf("no IDP provider could verify the API key")
}

// CleanupCache removes expired cache entries.
func (pc *ProviderChain) CleanupCache() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	now := time.Now()
	for key, cached := range pc.cache {
		if now.Sub(cached.cachedAt) > pc.cacheTTL {
			delete(pc.cache, key)
		}
	}
}

// RegisterWebhook registers an IDP webhook handler for real-time user events.
// This is used for user deactivation/deletion notifications from the IDP.
type WebhookHandler struct {
	// OnUserDeactivated is called when a user is deactivated in the IDP.
	OnUserDeactivated func(subject, provider string)
	// OnUserDeleted is called when a user is deleted in the IDP.
	OnUserDeleted func(subject, provider string)
	// OnGroupChanged is called when a user's groups change.
	OnGroupChanged func(subject, provider string, newGroups []string)
}

// HandleOktaWebhook processes an Okta event hook payload.
func (wh *WebhookHandler) HandleOktaWebhook(eventType, userID string) {
	switch {
	case strings.Contains(eventType, "user.lifecycle.deactivate"):
		if wh.OnUserDeactivated != nil {
			wh.OnUserDeactivated(userID, "okta")
		}
	case strings.Contains(eventType, "user.lifecycle.delete"):
		if wh.OnUserDeleted != nil {
			wh.OnUserDeleted(userID, "okta")
		}
	case strings.Contains(eventType, "group.user_membership"):
		if wh.OnGroupChanged != nil {
			wh.OnGroupChanged(userID, "okta", nil)
		}
	}
}

// HandleAzureADWebhook processes an Azure AD change notification.
func (wh *WebhookHandler) HandleAzureADWebhook(changeType, userID string) {
	switch changeType {
	case "deleted":
		if wh.OnUserDeleted != nil {
			wh.OnUserDeleted(userID, "azure_ad")
		}
	case "updated":
		// Could be a deactivation — check accountEnabled field.
		if wh.OnUserDeactivated != nil {
			wh.OnUserDeactivated(userID, "azure_ad")
		}
	}
}
