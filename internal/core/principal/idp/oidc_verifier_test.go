package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOIDCVerifierVerifyTokenSuccess(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	defer issuer.server.Close()

	token := issuer.sign(t, map[string]any{
		"iss":    issuer.server.URL,
		"aud":    "faramesh-client",
		"sub":    "user-123",
		"email":  "alice@example.com",
		"name":   "Alice",
		"groups": []string{"engineering", "ops"},
		"roles":  []string{"admin"},
		"org":    "acme",
		"exp":    time.Now().Add(10 * time.Minute).Unix(),
		"iat":    time.Now().Add(-1 * time.Minute).Unix(),
	})

	verifier := NewOIDCVerifier("okta", OIDCConfig{
		Issuer:   issuer.server.URL,
		ClientID: "faramesh-client",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	identity, err := verifier.VerifyToken(ctx, "Bearer "+token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if identity.Subject != "user-123" {
		t.Fatalf("subject=%q, want user-123", identity.Subject)
	}
	if identity.Email != "alice@example.com" {
		t.Fatalf("email=%q, want alice@example.com", identity.Email)
	}
	if identity.Provider != "okta" {
		t.Fatalf("provider=%q, want okta", identity.Provider)
	}
	if identity.Org != "acme" {
		t.Fatalf("org=%q, want acme", identity.Org)
	}
	if len(identity.Groups) != 2 {
		t.Fatalf("groups=%v, want 2 entries", identity.Groups)
	}
	if len(identity.Roles) != 1 || identity.Roles[0] != "admin" {
		t.Fatalf("roles=%v, want [admin]", identity.Roles)
	}
	if !identity.Valid() {
		t.Fatalf("expected verified identity to be valid")
	}
}

func TestOIDCVerifierVerifyTokenAudienceMismatch(t *testing.T) {
	issuer := newOIDCTestIssuer(t)
	defer issuer.server.Close()

	token := issuer.sign(t, map[string]any{
		"iss":   issuer.server.URL,
		"aud":   "faramesh-client",
		"sub":   "user-123",
		"email": "alice@example.com",
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
		"iat":   time.Now().Add(-1 * time.Minute).Unix(),
	})

	verifier := NewOIDCVerifier("okta", OIDCConfig{
		Issuer:   issuer.server.URL,
		ClientID: "different-client",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := verifier.VerifyToken(ctx, token)
	if err == nil {
		t.Fatalf("expected audience mismatch verification error")
	}
}

type oidcTestIssuer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	kid        string
}

func newOIDCTestIssuer(t *testing.T) *oidcTestIssuer {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	i := &oidcTestIssuer{
		privateKey: privateKey,
		kid:        "test-key-1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   i.server.URL,
			"jwks_uri": i.server.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []any{rsaJWK(&privateKey.PublicKey, i.kid)},
		})
	})

	i.server = httptest.NewServer(mux)
	return i
}

func (i *oidcTestIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	tok.Header["kid"] = i.kid
	signed, err := tok.SignedString(i.privateKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func rsaJWK(pub *rsa.PublicKey, kid string) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
