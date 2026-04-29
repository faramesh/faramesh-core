package idp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestNewVerifierFromEnvDefaultProvider(t *testing.T) {
	verifier, err := NewVerifierFromEnv("default")
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if verifier.Name() != "default" {
		t.Fatalf("provider name=%q, want default", verifier.Name())
	}
	if _, ok := verifier.(*EphemeralVerifier); !ok {
		t.Fatalf("expected EphemeralVerifier for default provider, got %T", verifier)
	}
}

func TestEphemeralVerifierVerifySignedToken(t *testing.T) {
	verifier, err := NewEphemeralVerifier(EphemeralConfig{
		Subject: "user-ephemeral",
		Email:   "user-ephemeral@example.com",
		Name:    "Ephemeral User",
		Org:     "acme",
		Role:    "operator",
		Tier:    "pro",
	})
	if err != nil {
		t.Fatalf("new ephemeral verifier: %v", err)
	}

	token, err := verifier.mintToken(ephemeralSignedClaims{}, 2*time.Minute)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	identity, err := verifier.VerifyToken(context.Background(), "Bearer "+token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if identity.Subject != "user-ephemeral" {
		t.Fatalf("subject=%q, want user-ephemeral", identity.Subject)
	}
	if identity.Provider != "default" {
		t.Fatalf("provider=%q, want default", identity.Provider)
	}
	if identity.Org != "acme" {
		t.Fatalf("org=%q, want acme", identity.Org)
	}
	if !identity.Valid() {
		t.Fatalf("expected ephemeral identity to be valid")
	}
}

func TestEphemeralVerifierRejectsTamperedToken(t *testing.T) {
	verifier, err := NewEphemeralVerifier(EphemeralConfig{})
	if err != nil {
		t.Fatalf("new ephemeral verifier: %v", err)
	}

	token, err := verifier.mintToken(ephemeralSignedClaims{}, time.Minute)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token format")
	}
	if len(parts[1]) < 2 {
		t.Fatalf("unexpected payload length")
	}
	parts[1] = parts[1][:len(parts[1])-1] + "A"
	tampered := strings.Join(parts, ".")

	if _, err := verifier.VerifyToken(context.Background(), tampered); err == nil {
		t.Fatalf("expected tampered token verification error")
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
