// Package idp provides identity provider integration for principal verification.
//
// Supports multiple IDP backends:
//   - Default: built-in ephemeral Ed25519 keypair verifier for local bootstrap
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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// VerifiedIdentity is the result of successful IDP verification.
type VerifiedIdentity struct {
	Subject    string         `json:"sub"`
	Email      string         `json:"email"`
	Name       string         `json:"name"`
	Groups     []string       `json:"groups"`
	Roles      []string       `json:"roles"`
	Org        string         `json:"org"`
	Provider   string         `json:"provider"` // okta, azure_ad, auth0, google, ldap
	VerifiedAt time.Time      `json:"verified_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	RawClaims  map[string]any `json:"raw_claims,omitempty"`
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
	Domain      string `yaml:"domain"` // e.g. "dev-123456.okta.com"
	Issuer      string `yaml:"issuer"`
	ClientID    string `yaml:"client_id"`
	Audience    string `yaml:"audience"`
	GroupsClaim string `yaml:"groups_claim"` // default: "groups"
	RolesClaim  string `yaml:"roles_claim"`
	OrgClaim    string `yaml:"org_claim"`
}

// OktaVerifier verifies principals against Okta.
type OktaVerifier struct {
	config OktaConfig
	oidc   *OIDCVerifier
}

// NewOktaVerifier creates a new Okta verifier.
func NewOktaVerifier(cfg OktaConfig) *OktaVerifier {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = oktaIssuerFromDomain(cfg.Domain)
	}
	return &OktaVerifier{
		config: cfg,
		oidc: NewOIDCVerifier("okta", OIDCConfig{
			Issuer:      issuer,
			Audience:    cfg.Audience,
			ClientID:    cfg.ClientID,
			GroupsClaim: cfg.GroupsClaim,
			RolesClaim:  cfg.RolesClaim,
			OrgClaim:    cfg.OrgClaim,
		}),
	}
}

func (v *OktaVerifier) Name() string { return "okta" }

func (v *OktaVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	if v.oidc == nil {
		return nil, fmt.Errorf("okta: verifier not initialized")
	}
	return v.oidc.VerifyToken(ctx, token)
}

func (v *OktaVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("okta: API key verification not supported, use OIDC tokens")
}

// AzureADConfig configures the Azure AD IDP verifier.
type AzureADConfig struct {
	TenantID    string `yaml:"tenant_id"`
	Issuer      string `yaml:"issuer"`
	ClientID    string `yaml:"client_id"`
	Audience    string `yaml:"audience"`
	GroupsClaim string `yaml:"groups_claim"`
	RolesClaim  string `yaml:"roles_claim"`
	OrgClaim    string `yaml:"org_claim"`
}

// AzureADVerifier verifies principals against Azure AD.
type AzureADVerifier struct {
	config AzureADConfig
	oidc   *OIDCVerifier
}

// NewAzureADVerifier creates a new Azure AD verifier.
func NewAzureADVerifier(cfg AzureADConfig) *AzureADVerifier {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = azureIssuerFromTenant(cfg.TenantID)
	}
	return &AzureADVerifier{
		config: cfg,
		oidc: NewOIDCVerifier("azure_ad", OIDCConfig{
			Issuer:      issuer,
			Audience:    cfg.Audience,
			ClientID:    cfg.ClientID,
			GroupsClaim: cfg.GroupsClaim,
			RolesClaim:  cfg.RolesClaim,
			OrgClaim:    cfg.OrgClaim,
		}),
	}
}

func (v *AzureADVerifier) Name() string { return "azure_ad" }

func (v *AzureADVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	if v.oidc == nil {
		return nil, fmt.Errorf("azure_ad: verifier not initialized")
	}
	return v.oidc.VerifyToken(ctx, token)
}

func (v *AzureADVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("azure_ad: API key verification not supported, use OIDC tokens")
}

// Auth0Config configures the Auth0 IDP verifier.
type Auth0Config struct {
	Domain      string `yaml:"domain"` // e.g. "myapp.auth0.com"
	Issuer      string `yaml:"issuer"`
	ClientID    string `yaml:"client_id"`
	Audience    string `yaml:"audience"`
	GroupsClaim string `yaml:"groups_claim"`
	RolesClaim  string `yaml:"roles_claim"`
	OrgClaim    string `yaml:"org_claim"`
}

// Auth0Verifier verifies principals against Auth0.
type Auth0Verifier struct {
	config Auth0Config
	oidc   *OIDCVerifier
}

// NewAuth0Verifier creates a new Auth0 verifier.
func NewAuth0Verifier(cfg Auth0Config) *Auth0Verifier {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = auth0IssuerFromDomain(cfg.Domain)
	}
	return &Auth0Verifier{
		config: cfg,
		oidc: NewOIDCVerifier("auth0", OIDCConfig{
			Issuer:      issuer,
			Audience:    cfg.Audience,
			ClientID:    cfg.ClientID,
			GroupsClaim: cfg.GroupsClaim,
			RolesClaim:  cfg.RolesClaim,
			OrgClaim:    cfg.OrgClaim,
		}),
	}
}

func (v *Auth0Verifier) Name() string { return "auth0" }

func (v *Auth0Verifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	if v.oidc == nil {
		return nil, fmt.Errorf("auth0: verifier not initialized")
	}
	return v.oidc.VerifyToken(ctx, token)
}

func (v *Auth0Verifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("auth0: use M2M token flow instead of API keys")
}

// GoogleConfig configures the Google Workspace IDP verifier.
type GoogleConfig struct {
	ClientID    string `yaml:"client_id"`
	Domain      string `yaml:"hd"` // hosted domain restriction
	Issuer      string `yaml:"issuer"`
	Audience    string `yaml:"audience"`
	GroupsClaim string `yaml:"groups_claim"`
	RolesClaim  string `yaml:"roles_claim"`
	OrgClaim    string `yaml:"org_claim"`
}

// GoogleVerifier verifies principals against Google.
type GoogleVerifier struct {
	config GoogleConfig
	oidc   *OIDCVerifier
}

// NewGoogleVerifier creates a new Google verifier.
func NewGoogleVerifier(cfg GoogleConfig) *GoogleVerifier {
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = "https://accounts.google.com"
	}
	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = cfg.ClientID
	}
	return &GoogleVerifier{
		config: cfg,
		oidc: NewOIDCVerifier("google", OIDCConfig{
			Issuer:      issuer,
			Audience:    audience,
			ClientID:    cfg.ClientID,
			GroupsClaim: cfg.GroupsClaim,
			RolesClaim:  cfg.RolesClaim,
			OrgClaim:    cfg.OrgClaim,
		}),
	}
}

func (v *GoogleVerifier) Name() string { return "google" }

func (v *GoogleVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	if v.oidc == nil {
		return nil, fmt.Errorf("google: verifier not initialized")
	}
	id, err := v.oidc.VerifyToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if domain := strings.TrimSpace(v.config.Domain); domain != "" {
		hd := ""
		if id.RawClaims != nil {
			hd = claimString(id.RawClaims, "hd")
		}
		if !strings.EqualFold(strings.TrimSpace(hd), domain) {
			return nil, fmt.Errorf("google: hosted domain mismatch (want %q)", domain)
		}
	}
	return id, nil
}

func (v *GoogleVerifier) VerifyAPIKey(_ context.Context, _ string) (*VerifiedIdentity, error) {
	return nil, fmt.Errorf("google: API key verification not supported, use OIDC tokens")
}

// LDAPConfig configures the LDAP IDP verifier.
type LDAPConfig struct {
	URL          string `yaml:"url"` // e.g. "ldaps://ldap.example.com:636"
	BindDN       string `yaml:"bind_dn"`
	BindPassword string `yaml:"bind_password"`
	BaseDN       string `yaml:"base_dn"`
	UserFilter   string `yaml:"user_filter"` // e.g. "(uid=%s)"
	GroupFilter  string `yaml:"group_filter"`
	UserAttr     string `yaml:"user_attr"`
	EmailAttr    string `yaml:"email_attr"`
	NameAttr     string `yaml:"name_attr"`
	GroupAttr    string `yaml:"group_attr"`
	TLSVerify    bool   `yaml:"tls_verify"`
}

// LDAPVerifier verifies principals against an LDAP directory.
type LDAPVerifier struct {
	config LDAPConfig
}

// NewLDAPVerifier creates a new LDAP verifier.
func NewLDAPVerifier(cfg LDAPConfig) *LDAPVerifier {
	if strings.TrimSpace(cfg.UserFilter) == "" {
		cfg.UserFilter = "(uid=%s)"
	}
	if strings.TrimSpace(cfg.GroupFilter) == "" {
		cfg.GroupFilter = "(member=%s)"
	}
	if strings.TrimSpace(cfg.UserAttr) == "" {
		cfg.UserAttr = "uid"
	}
	if strings.TrimSpace(cfg.EmailAttr) == "" {
		cfg.EmailAttr = "mail"
	}
	if strings.TrimSpace(cfg.NameAttr) == "" {
		cfg.NameAttr = "cn"
	}
	if strings.TrimSpace(cfg.GroupAttr) == "" {
		cfg.GroupAttr = "memberOf"
	}
	return &LDAPVerifier{config: cfg}
}

func (v *LDAPVerifier) Name() string { return "ldap" }

func (v *LDAPVerifier) VerifyToken(ctx context.Context, token string) (*VerifiedIdentity, error) {
	username, password, err := parseLDAPCredentialsToken(token)
	if err != nil {
		return nil, err
	}
	return v.verifyCredentials(ctx, username, password)
}

func (v *LDAPVerifier) VerifyAPIKey(ctx context.Context, apiKey string) (*VerifiedIdentity, error) {
	username, password, err := parseLDAPCredentialsToken(apiKey)
	if err != nil {
		return nil, err
	}
	return v.verifyCredentials(ctx, username, password)
}

func (v *LDAPVerifier) verifyCredentials(ctx context.Context, username, password string) (*VerifiedIdentity, error) {
	url := strings.TrimSpace(v.config.URL)
	if url == "" {
		return nil, fmt.Errorf("ldap: url is required")
	}
	baseDN := strings.TrimSpace(v.config.BaseDN)
	if baseDN == "" {
		return nil, fmt.Errorf("ldap: base dn is required")
	}
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, fmt.Errorf("ldap: username and password are required")
	}

	tlsCfg := &tls.Config{ //nolint:gosec // configurable for local dev LDAP
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: !v.config.TLSVerify,
	}
	dialOpts := []ldap.DialOpt{ldap.DialWithTLSConfig(tlsCfg)}
	conn, err := ldap.DialURL(url, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %q: %w", url, err)
	}
	defer conn.Close()

	if strings.HasPrefix(strings.ToLower(url), "ldap://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}

	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		timeout = remaining
	}
	conn.SetTimeout(timeout)

	serviceBindDN := strings.TrimSpace(v.config.BindDN)
	if serviceBindDN != "" {
		if err := conn.Bind(serviceBindDN, v.config.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap: service bind failed: %w", err)
		}
	}

	userFilter := fmt.Sprintf(v.config.UserFilter, ldap.EscapeFilter(strings.TrimSpace(username)))
	attrs := []string{v.config.UserAttr, v.config.EmailAttr, v.config.NameAttr, v.config.GroupAttr}
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		2,
		int(timeout.Seconds()),
		false,
		userFilter,
		attrs,
		nil,
	)
	searchRes, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap: user search failed: %w", err)
	}
	if len(searchRes.Entries) == 0 {
		return nil, fmt.Errorf("ldap: user %q not found", username)
	}
	if len(searchRes.Entries) > 1 {
		return nil, fmt.Errorf("ldap: user %q matched multiple entries", username)
	}

	entry := searchRes.Entries[0]
	userDN := strings.TrimSpace(entry.DN)
	if userDN == "" {
		return nil, fmt.Errorf("ldap: user entry missing dn")
	}

	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("ldap: invalid credentials")
	}

	subject := strings.TrimSpace(entry.GetAttributeValue(v.config.UserAttr))
	if subject == "" {
		subject = userDN
	}
	email := strings.TrimSpace(entry.GetAttributeValue(v.config.EmailAttr))
	name := strings.TrimSpace(entry.GetAttributeValue(v.config.NameAttr))
	groups := sanitizeStrings(entry.GetAttributeValues(v.config.GroupAttr))

	if len(groups) == 0 && strings.TrimSpace(v.config.GroupFilter) != "" {
		if serviceBindDN != "" {
			_ = conn.Bind(serviceBindDN, v.config.BindPassword)
		}
		groupFilter := fmt.Sprintf(v.config.GroupFilter, ldap.EscapeFilter(userDN))
		groupReq := ldap.NewSearchRequest(
			baseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			int(timeout.Seconds()),
			false,
			groupFilter,
			[]string{"cn"},
			nil,
		)
		if groupRes, groupErr := conn.Search(groupReq); groupErr == nil {
			for _, g := range groupRes.Entries {
				if cn := strings.TrimSpace(g.GetAttributeValue("cn")); cn != "" {
					groups = append(groups, cn)
					continue
				}
				if dn := strings.TrimSpace(g.DN); dn != "" {
					groups = append(groups, dn)
				}
			}
			groups = sanitizeStrings(groups)
		}
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"dn":       userDN,
		"username": username,
	}

	return &VerifiedIdentity{
		Subject:    subject,
		Email:      email,
		Name:       name,
		Groups:     groups,
		Roles:      groups,
		Provider:   "ldap",
		VerifiedAt: now,
		ExpiresAt:  now.Add(5 * time.Minute),
		RawClaims:  claims,
	}, nil
}

func parseLDAPCredentialsToken(raw string) (string, string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", "", fmt.Errorf("ldap: credential token is empty")
	}

	lower := strings.ToLower(token)
	if strings.HasPrefix(lower, "bearer ") {
		token = strings.TrimSpace(token[len("bearer "):])
		lower = strings.ToLower(token)
	}
	if strings.HasPrefix(lower, "basic ") {
		rawEncoded := strings.TrimSpace(token[len("basic "):])
		decoded, err := base64.StdEncoding.DecodeString(rawEncoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(rawEncoded)
			if err != nil {
				return "", "", fmt.Errorf("ldap: invalid basic credential encoding")
			}
		}
		token = string(decoded)
		lower = strings.ToLower(token)
	}
	if strings.HasPrefix(lower, "ldap:") {
		token = strings.TrimSpace(token[len("ldap:"):])
	}

	username, password, ok := strings.Cut(token, ":")
	if !ok {
		return "", "", fmt.Errorf("ldap: expected credentials in username:password format")
	}
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return "", "", fmt.Errorf("ldap: expected non-empty username and password")
	}
	return username, password, nil
}

func sanitizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// LocalConfig configures the lightweight built-in verifier used by default.
// It avoids any external IdP dependency for local/dev deployments.
type LocalConfig struct {
	SharedToken string
	Subject     string
	Email       string
	Name        string
	Tier        string
	Role        string
	Org         string
	Groups      []string
	Roles       []string
	TTL         time.Duration
}

// LocalVerifier verifies principals against a locally configured shared token.
type LocalVerifier struct {
	config LocalConfig
}

// NewLocalVerifier creates a local verifier with safe defaults for local/dev use.
func NewLocalVerifier(cfg LocalConfig) *LocalVerifier {
	if strings.TrimSpace(cfg.SharedToken) == "" {
		cfg.SharedToken = "faramesh-local-dev-token"
	}
	if strings.TrimSpace(cfg.Subject) == "" {
		cfg.Subject = "local-user"
	}
	if strings.TrimSpace(cfg.Email) == "" {
		cfg.Email = cfg.Subject + "@local"
	}
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = "Faramesh Local User"
	}
	if strings.TrimSpace(cfg.Tier) == "" {
		cfg.Tier = "default"
	}
	if strings.TrimSpace(cfg.Role) == "" {
		cfg.Role = "developer"
	}
	if strings.TrimSpace(cfg.Org) == "" {
		cfg.Org = "local"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 8 * time.Hour
	}
	return &LocalVerifier{config: cfg}
}

func (v *LocalVerifier) Name() string { return "local" }

func (v *LocalVerifier) VerifyToken(_ context.Context, token string) (*VerifiedIdentity, error) {
	return v.verifySharedToken(token)
}

func (v *LocalVerifier) VerifyAPIKey(_ context.Context, apiKey string) (*VerifiedIdentity, error) {
	return v.verifySharedToken(apiKey)
}

func (v *LocalVerifier) verifySharedToken(raw string) (*VerifiedIdentity, error) {
	presented := normalizeBearerToken(raw)
	if strings.TrimSpace(presented) == "" {
		return nil, fmt.Errorf("local idp: token is empty")
	}
	expected := v.config.SharedToken
	if subtle.ConstantTimeCompare([]byte(presented), []byte(expected)) != 1 {
		return nil, fmt.Errorf("local idp: token verification failed")
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"tier":   v.config.Tier,
		"role":   v.config.Role,
		"org":    v.config.Org,
		"groups": append([]string(nil), v.config.Groups...),
		"roles":  append([]string(nil), v.config.Roles...),
	}

	roles := append([]string(nil), v.config.Roles...)
	if len(roles) == 0 && strings.TrimSpace(v.config.Role) != "" {
		roles = []string{v.config.Role}
	}

	return &VerifiedIdentity{
		Subject:    v.config.Subject,
		Email:      v.config.Email,
		Name:       v.config.Name,
		Groups:     append([]string(nil), v.config.Groups...),
		Roles:      roles,
		Org:        v.config.Org,
		Provider:   "local",
		VerifiedAt: now,
		ExpiresAt:  now.Add(v.config.TTL),
		RawClaims:  claims,
	}, nil
}

const ephemeralTokenPrefix = "epk"

// EphemeralConfig configures the built-in default verifier.
// The default provider generates an in-memory Ed25519 keypair at startup and
// verifies signed short-lived tokens without external IdP dependencies.
type EphemeralConfig struct {
	Subject           string
	Email             string
	Name              string
	Tier              string
	Role              string
	Org               string
	Groups            []string
	Roles             []string
	TTL               time.Duration
	LegacySharedToken string
}

// EphemeralVerifier validates signed tokens against an in-memory Ed25519 keypair.
// It is intentionally process-local and resets on daemon restart.
type EphemeralVerifier struct {
	config     EphemeralConfig
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	keyID      string
}

type ephemeralSignedClaims struct {
	Subject string   `json:"sub,omitempty"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Tier    string   `json:"tier,omitempty"`
	Role    string   `json:"role,omitempty"`
	Org     string   `json:"org,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Roles   []string `json:"roles,omitempty"`
	ExpUnix int64    `json:"exp,omitempty"`
	KeyID   string   `json:"kid,omitempty"`
}

// NewEphemeralVerifier creates a default verifier backed by an ephemeral keypair.
func NewEphemeralVerifier(cfg EphemeralConfig) (*EphemeralVerifier, error) {
	if strings.TrimSpace(cfg.Subject) == "" {
		cfg.Subject = "local-ephemeral-user"
	}
	if strings.TrimSpace(cfg.Email) == "" {
		cfg.Email = cfg.Subject + "@local"
	}
	if strings.TrimSpace(cfg.Name) == "" {
		cfg.Name = "Faramesh Ephemeral User"
	}
	if strings.TrimSpace(cfg.Tier) == "" {
		cfg.Tier = "default"
	}
	if strings.TrimSpace(cfg.Role) == "" {
		cfg.Role = "developer"
	}
	if strings.TrimSpace(cfg.Org) == "" {
		cfg.Org = "local"
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Minute
	}
	if strings.TrimSpace(cfg.LegacySharedToken) == "" {
		cfg.LegacySharedToken = envFirst("FARAMESH_IDP_LOCAL_TOKEN", "FARAMESH_IDP_TOKEN")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("default idp: generate ephemeral keypair: %w", err)
	}
	kid := fmt.Sprintf("%x", sha256.Sum256(pub))[:16]

	return &EphemeralVerifier{
		config:     cfg,
		publicKey:  pub,
		privateKey: priv,
		keyID:      kid,
	}, nil
}

func (v *EphemeralVerifier) Name() string { return "default" }

func (v *EphemeralVerifier) VerifyToken(_ context.Context, token string) (*VerifiedIdentity, error) {
	return v.verify(token)
}

func (v *EphemeralVerifier) VerifyAPIKey(_ context.Context, apiKey string) (*VerifiedIdentity, error) {
	return v.verify(apiKey)
}

func (v *EphemeralVerifier) verify(raw string) (*VerifiedIdentity, error) {
	presented := normalizeBearerToken(raw)
	if strings.TrimSpace(presented) == "" {
		return nil, fmt.Errorf("default idp: token is empty")
	}
	if strings.HasPrefix(presented, ephemeralTokenPrefix+".") {
		return v.verifySignedToken(presented)
	}
	legacy := strings.TrimSpace(v.config.LegacySharedToken)
	if legacy != "" && subtle.ConstantTimeCompare([]byte(presented), []byte(legacy)) == 1 {
		return v.fallbackIdentity(time.Now().UTC()), nil
	}
	return nil, fmt.Errorf("default idp: token verification failed")
}

func (v *EphemeralVerifier) verifySignedToken(token string) (*VerifiedIdentity, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != ephemeralTokenPrefix {
		return nil, fmt.Errorf("default idp: invalid token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("default idp: invalid token payload encoding")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("default idp: invalid token signature encoding")
	}
	if !ed25519.Verify(v.publicKey, payload, sig) {
		return nil, fmt.Errorf("default idp: signature verification failed")
	}

	var claims ephemeralSignedClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("default idp: invalid token claims")
	}
	if strings.TrimSpace(claims.KeyID) != "" && strings.TrimSpace(claims.KeyID) != v.keyID {
		return nil, fmt.Errorf("default idp: token key id mismatch")
	}
	now := time.Now().UTC()
	if claims.ExpUnix <= 0 || now.Unix() >= claims.ExpUnix {
		return nil, fmt.Errorf("default idp: token expired")
	}

	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		subject = v.config.Subject
	}
	email := strings.TrimSpace(claims.Email)
	if email == "" {
		email = v.config.Email
	}
	name := strings.TrimSpace(claims.Name)
	if name == "" {
		name = v.config.Name
	}
	if subject == "" && email == "" && name == "" {
		return nil, fmt.Errorf("default idp: missing subject/email/name")
	}

	roles := append([]string(nil), claims.Roles...)
	if len(roles) == 0 && strings.TrimSpace(claims.Role) != "" {
		roles = []string{strings.TrimSpace(claims.Role)}
	}
	if len(roles) == 0 {
		roles = append([]string(nil), v.config.Roles...)
		if len(roles) == 0 && strings.TrimSpace(v.config.Role) != "" {
			roles = []string{strings.TrimSpace(v.config.Role)}
		}
	}

	groups := append([]string(nil), claims.Groups...)
	if len(groups) == 0 {
		groups = append([]string(nil), v.config.Groups...)
	}

	org := strings.TrimSpace(claims.Org)
	if org == "" {
		org = strings.TrimSpace(v.config.Org)
	}
	tier := strings.TrimSpace(claims.Tier)
	if tier == "" {
		tier = strings.TrimSpace(v.config.Tier)
	}
	role := strings.TrimSpace(claims.Role)
	if role == "" && len(roles) > 0 {
		role = strings.TrimSpace(roles[0])
	}

	claimsMap := map[string]any{
		"kid":    v.keyID,
		"tier":   tier,
		"role":   role,
		"org":    org,
		"groups": groups,
		"roles":  roles,
	}

	return &VerifiedIdentity{
		Subject:    subject,
		Email:      email,
		Name:       name,
		Groups:     groups,
		Roles:      roles,
		Org:        org,
		Provider:   "default",
		VerifiedAt: now,
		ExpiresAt:  time.Unix(claims.ExpUnix, 0).UTC(),
		RawClaims:  claimsMap,
	}, nil
}

func (v *EphemeralVerifier) fallbackIdentity(now time.Time) *VerifiedIdentity {
	roles := append([]string(nil), v.config.Roles...)
	if len(roles) == 0 && strings.TrimSpace(v.config.Role) != "" {
		roles = []string{strings.TrimSpace(v.config.Role)}
	}
	claims := map[string]any{
		"kid":    v.keyID,
		"tier":   v.config.Tier,
		"role":   v.config.Role,
		"org":    v.config.Org,
		"groups": append([]string(nil), v.config.Groups...),
		"roles":  append([]string(nil), roles...),
	}
	return &VerifiedIdentity{
		Subject:    v.config.Subject,
		Email:      v.config.Email,
		Name:       v.config.Name,
		Groups:     append([]string(nil), v.config.Groups...),
		Roles:      roles,
		Org:        v.config.Org,
		Provider:   "default",
		VerifiedAt: now,
		ExpiresAt:  now.Add(v.config.TTL),
		RawClaims:  claims,
	}
}

// mintToken is intentionally package-private and used by unit tests to verify
// default verifier behavior.
func (v *EphemeralVerifier) mintToken(claims ephemeralSignedClaims, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = v.config.TTL
	}
	now := time.Now().UTC()
	if claims.ExpUnix <= 0 {
		claims.ExpUnix = now.Add(ttl).Unix()
	}
	if strings.TrimSpace(claims.Subject) == "" {
		claims.Subject = v.config.Subject
	}
	if strings.TrimSpace(claims.Email) == "" {
		claims.Email = v.config.Email
	}
	if strings.TrimSpace(claims.Name) == "" {
		claims.Name = v.config.Name
	}
	if strings.TrimSpace(claims.Tier) == "" {
		claims.Tier = v.config.Tier
	}
	if strings.TrimSpace(claims.Role) == "" {
		claims.Role = v.config.Role
	}
	if strings.TrimSpace(claims.Org) == "" {
		claims.Org = v.config.Org
	}
	if len(claims.Groups) == 0 {
		claims.Groups = append([]string(nil), v.config.Groups...)
	}
	if len(claims.Roles) == 0 {
		claims.Roles = append([]string(nil), v.config.Roles...)
	}
	claims.KeyID = v.keyID

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(v.privateKey, payload)
	return fmt.Sprintf("%s.%s.%s",
		ephemeralTokenPrefix,
		base64.RawURLEncoding.EncodeToString(payload),
		base64.RawURLEncoding.EncodeToString(sig),
	), nil
}

// ValidateProviderConfigFromEnv validates required runtime configuration for a provider.
func ValidateProviderConfigFromEnv(provider string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return fmt.Errorf("idp provider is required")
	}

	requireAny := func(label string, values ...string) error {
		for _, value := range values {
			if strings.TrimSpace(value) != "" {
				return nil
			}
		}
		return fmt.Errorf("%s is required", label)
	}

	issuer := envFirst("FARAMESH_IDP_ISSUER")
	audience := envFirst("FARAMESH_IDP_AUDIENCE")
	clientID := envFirst("FARAMESH_IDP_CLIENT_ID")

	switch provider {
	case "default", "local":
		return nil
	case "okta":
		if err := requireAny("FARAMESH_IDP_ISSUER or FARAMESH_IDP_OKTA_DOMAIN", issuer, envFirst("FARAMESH_IDP_OKTA_DOMAIN", "FARAMESH_IDP_DOMAIN")); err != nil {
			return fmt.Errorf("okta: %w", err)
		}
		if err := requireAny("FARAMESH_IDP_CLIENT_ID or FARAMESH_IDP_AUDIENCE", clientID, audience); err != nil {
			return fmt.Errorf("okta: %w", err)
		}
		return nil
	case "azure_ad":
		if err := requireAny("FARAMESH_IDP_ISSUER or FARAMESH_IDP_AZURE_TENANT_ID", issuer, envFirst("FARAMESH_IDP_AZURE_TENANT_ID", "FARAMESH_IDP_TENANT_ID")); err != nil {
			return fmt.Errorf("azure_ad: %w", err)
		}
		if err := requireAny("FARAMESH_IDP_CLIENT_ID or FARAMESH_IDP_AUDIENCE", clientID, audience); err != nil {
			return fmt.Errorf("azure_ad: %w", err)
		}
		return nil
	case "auth0":
		if err := requireAny("FARAMESH_IDP_ISSUER or FARAMESH_IDP_AUTH0_DOMAIN", issuer, envFirst("FARAMESH_IDP_AUTH0_DOMAIN", "FARAMESH_IDP_DOMAIN")); err != nil {
			return fmt.Errorf("auth0: %w", err)
		}
		if err := requireAny("FARAMESH_IDP_CLIENT_ID or FARAMESH_IDP_AUDIENCE", clientID, audience); err != nil {
			return fmt.Errorf("auth0: %w", err)
		}
		return nil
	case "google":
		if err := requireAny("FARAMESH_IDP_CLIENT_ID or FARAMESH_IDP_AUDIENCE", clientID, audience); err != nil {
			return fmt.Errorf("google: %w", err)
		}
		return nil
	case "ldap":
		if err := requireAny("FARAMESH_IDP_LDAP_URL", envFirst("FARAMESH_IDP_LDAP_URL")); err != nil {
			return fmt.Errorf("ldap: %w", err)
		}
		if err := requireAny("FARAMESH_IDP_LDAP_BASE_DN", envFirst("FARAMESH_IDP_LDAP_BASE_DN")); err != nil {
			return fmt.Errorf("ldap: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported idp provider %q", provider)
	}
}

// ProviderChain tries multiple IDP verifiers in order.
type ProviderChain struct {
	mu        sync.RWMutex
	providers []Verifier
	cache     map[string]*cachedIdentity
	cacheTTL  time.Duration
}

type cachedIdentity struct {
	identity *VerifiedIdentity
	cachedAt time.Time
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

// NewVerifierFromEnv builds an IDP verifier from provider + environment variables.
func NewVerifierFromEnv(provider string) (Verifier, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil, fmt.Errorf("idp provider is required")
	}
	if err := ValidateProviderConfigFromEnv(provider); err != nil {
		return nil, err
	}

	issuer := envFirst("FARAMESH_IDP_ISSUER")
	audience := envFirst("FARAMESH_IDP_AUDIENCE")
	clientID := envFirst("FARAMESH_IDP_CLIENT_ID")
	groupsClaim := envFirst("FARAMESH_IDP_GROUPS_CLAIM")
	rolesClaim := envFirst("FARAMESH_IDP_ROLES_CLAIM")
	orgClaim := envFirst("FARAMESH_IDP_ORG_CLAIM")

	switch provider {
	case "default":
		return NewEphemeralVerifier(EphemeralConfig{
			Subject:           envFirst("FARAMESH_IDP_DEFAULT_SUBJECT", "FARAMESH_IDP_LOCAL_SUBJECT"),
			Email:             envFirst("FARAMESH_IDP_DEFAULT_EMAIL", "FARAMESH_IDP_LOCAL_EMAIL"),
			Name:              envFirst("FARAMESH_IDP_DEFAULT_NAME", "FARAMESH_IDP_LOCAL_NAME"),
			Tier:              envFirst("FARAMESH_IDP_DEFAULT_TIER", "FARAMESH_IDP_LOCAL_TIER"),
			Role:              envFirst("FARAMESH_IDP_DEFAULT_ROLE", "FARAMESH_IDP_LOCAL_ROLE"),
			Org:               envFirst("FARAMESH_IDP_DEFAULT_ORG", "FARAMESH_IDP_LOCAL_ORG"),
			Groups:            envCSVFirst("FARAMESH_IDP_DEFAULT_GROUPS", "FARAMESH_IDP_LOCAL_GROUPS"),
			Roles:             envCSVFirst("FARAMESH_IDP_DEFAULT_ROLES", "FARAMESH_IDP_LOCAL_ROLES"),
			TTL:               parseDurationDefault(envFirst("FARAMESH_IDP_DEFAULT_TTL", "FARAMESH_IDP_LOCAL_TTL"), 30*time.Minute),
			LegacySharedToken: envFirst("FARAMESH_IDP_LOCAL_TOKEN", "FARAMESH_IDP_TOKEN"),
		})
	case "local":
		return NewLocalVerifier(LocalConfig{
			SharedToken: envFirst("FARAMESH_IDP_LOCAL_TOKEN", "FARAMESH_IDP_TOKEN"),
			Subject:     envFirst("FARAMESH_IDP_LOCAL_SUBJECT"),
			Email:       envFirst("FARAMESH_IDP_LOCAL_EMAIL"),
			Name:        envFirst("FARAMESH_IDP_LOCAL_NAME"),
			Tier:        envFirst("FARAMESH_IDP_LOCAL_TIER"),
			Role:        envFirst("FARAMESH_IDP_LOCAL_ROLE"),
			Org:         envFirst("FARAMESH_IDP_LOCAL_ORG"),
			Groups:      envCSVFirst("FARAMESH_IDP_LOCAL_GROUPS"),
			Roles:       envCSVFirst("FARAMESH_IDP_LOCAL_ROLES"),
			TTL:         parseDurationDefault(envFirst("FARAMESH_IDP_LOCAL_TTL"), 8*time.Hour),
		}), nil
	case "okta":
		return NewOktaVerifier(OktaConfig{
			Domain:      envFirst("FARAMESH_IDP_OKTA_DOMAIN", "FARAMESH_IDP_DOMAIN"),
			Issuer:      issuer,
			ClientID:    clientID,
			Audience:    audience,
			GroupsClaim: groupsClaim,
			RolesClaim:  rolesClaim,
			OrgClaim:    orgClaim,
		}), nil
	case "azure_ad":
		return NewAzureADVerifier(AzureADConfig{
			TenantID:    envFirst("FARAMESH_IDP_AZURE_TENANT_ID", "FARAMESH_IDP_TENANT_ID"),
			Issuer:      issuer,
			ClientID:    clientID,
			Audience:    audience,
			GroupsClaim: groupsClaim,
			RolesClaim:  rolesClaim,
			OrgClaim:    orgClaim,
		}), nil
	case "auth0":
		return NewAuth0Verifier(Auth0Config{
			Domain:      envFirst("FARAMESH_IDP_AUTH0_DOMAIN", "FARAMESH_IDP_DOMAIN"),
			Issuer:      issuer,
			ClientID:    clientID,
			Audience:    audience,
			GroupsClaim: groupsClaim,
			RolesClaim:  rolesClaim,
			OrgClaim:    orgClaim,
		}), nil
	case "google":
		return NewGoogleVerifier(GoogleConfig{
			ClientID:    clientID,
			Domain:      envFirst("FARAMESH_IDP_GOOGLE_DOMAIN", "FARAMESH_IDP_DOMAIN"),
			Issuer:      issuer,
			Audience:    audience,
			GroupsClaim: groupsClaim,
			RolesClaim:  rolesClaim,
			OrgClaim:    orgClaim,
		}), nil
	case "ldap":
		return NewLDAPVerifier(LDAPConfig{
			URL:          envFirst("FARAMESH_IDP_LDAP_URL"),
			BindDN:       envFirst("FARAMESH_IDP_LDAP_BIND_DN"),
			BindPassword: envFirst("FARAMESH_IDP_LDAP_BIND_PASSWORD"),
			BaseDN:       envFirst("FARAMESH_IDP_LDAP_BASE_DN"),
			UserFilter:   envFirst("FARAMESH_IDP_LDAP_USER_FILTER"),
			GroupFilter:  envFirst("FARAMESH_IDP_LDAP_GROUP_FILTER"),
			UserAttr:     envFirst("FARAMESH_IDP_LDAP_USER_ATTR"),
			EmailAttr:    envFirst("FARAMESH_IDP_LDAP_EMAIL_ATTR"),
			NameAttr:     envFirst("FARAMESH_IDP_LDAP_NAME_ATTR"),
			GroupAttr:    envFirst("FARAMESH_IDP_LDAP_GROUP_ATTR"),
			TLSVerify:    envBoolDefault(envFirst("FARAMESH_IDP_LDAP_TLS_VERIFY"), true),
		}), nil
	default:
		return nil, fmt.Errorf("unsupported idp provider %q", provider)
	}
}

func envFirst(keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return ""
}

func envCSVFirst(keys ...string) []string {
	raw := envFirst(keys...)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseDurationDefault(raw string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(raw)
	if v == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	if parsed <= 0 {
		return fallback
	}
	return parsed
}

func envBoolDefault(raw string, fallback bool) bool {
	v := strings.TrimSpace(raw)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func ensureHTTPSURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return s
	}
	return "https://" + s
}

func oktaIssuerFromDomain(domain string) string {
	base := strings.TrimRight(ensureHTTPSURL(domain), "/")
	if base == "" {
		return ""
	}
	if strings.Contains(base, "/oauth2/") {
		return base
	}
	return base + "/oauth2/default"
}

func azureIssuerFromTenant(tenant string) string {
	ten := strings.TrimSpace(tenant)
	if ten == "" {
		return ""
	}
	return "https://login.microsoftonline.com/" + ten + "/v2.0"
}

func auth0IssuerFromDomain(domain string) string {
	base := strings.TrimRight(ensureHTTPSURL(domain), "/")
	if base == "" {
		return ""
	}
	return base + "/"
}
