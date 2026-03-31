package idp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewVerifierFromEnvDefaultProvider(t *testing.T) {
	t.Setenv("FARAMESH_IDP_LOCAL_TOKEN", "dev-token")

	verifier, err := NewVerifierFromEnv("default")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if verifier.Name() != "local" {
		t.Fatalf("provider name=%q, want local", verifier.Name())
	}
}

func TestLocalVerifierVerifyToken(t *testing.T) {
	verifier := NewLocalVerifier(LocalConfig{
		SharedToken: "local-secret",
		Subject:     "user-123",
		Email:       "user@example.com",
		Name:        "User",
		Tier:        "pro",
		Role:        "operator",
		Org:         "acme",
		Groups:      []string{"engineering"},
		Roles:       []string{"operator"},
	})

	identity, err := verifier.VerifyToken(context.Background(), "Bearer local-secret")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if identity.Subject != "user-123" {
		t.Fatalf("subject=%q, want user-123", identity.Subject)
	}
	if identity.Provider != "local" {
		t.Fatalf("provider=%q, want local", identity.Provider)
	}
	if identity.Org != "acme" {
		t.Fatalf("org=%q, want acme", identity.Org)
	}
	if !identity.Valid() {
		t.Fatalf("expected local identity to be valid")
	}
}

func TestParseLDAPCredentialsTokenBasic(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	user, pass, err := parseLDAPCredentialsToken("Basic " + encoded)
	if err != nil {
		t.Fatalf("parse basic token: %v", err)
	}
	if user != "alice" || pass != "secret" {
		t.Fatalf("credentials=%q:%q, want alice:secret", user, pass)
	}
}

func TestValidateProviderConfigFromEnvLDAPRequiresFields(t *testing.T) {
	err := ValidateProviderConfigFromEnv("ldap")
	if err == nil {
		t.Fatalf("expected ldap validation error")
	}
	if !strings.Contains(err.Error(), "FARAMESH_IDP_LDAP_URL") {
		t.Fatalf("unexpected ldap validation error: %v", err)
	}
}

func TestNewVerifierFromEnvLDAPDefaultsTLSVerify(t *testing.T) {
	t.Setenv("FARAMESH_IDP_LDAP_URL", "ldaps://ldap.example.com:636")
	t.Setenv("FARAMESH_IDP_LDAP_BASE_DN", "dc=example,dc=com")

	verifier, err := NewVerifierFromEnv("ldap")
	if err != nil {
		t.Fatalf("new ldap verifier: %v", err)
	}
	ldapVerifier, ok := verifier.(*LDAPVerifier)
	if !ok {
		t.Fatalf("expected LDAPVerifier, got %T", verifier)
	}
	if !ldapVerifier.config.TLSVerify {
		t.Fatalf("expected ldap tls_verify default to true")
	}
}
