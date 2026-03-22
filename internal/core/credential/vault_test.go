package credential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultBrokerFetch_KVv2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, "forbidden", 403)
			return
		}
		resp := vaultSecretResponse{
			Data: map[string]any{
				"data": map[string]any{
					"api_key": "sk_live_abc123",
				},
			},
			LeaseDuration: 3600,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	b := NewVaultBroker(VaultConfig{
		Addr:      srv.URL,
		Token:     "test-token",
		MountPath: "secret",
	})

	cred, err := b.Fetch(context.Background(), FetchRequest{
		ToolID: "stripe/refund",
		Scope:  "stripe:charges:write",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "sk_live_abc123" {
		t.Fatalf("got value %q, want sk_live_abc123", cred.Value)
	}
	if cred.Source != "vault" {
		t.Fatalf("got source %q", cred.Source)
	}
	if cred.ExpiresAt.IsZero() {
		t.Fatal("expected non-zero ExpiresAt")
	}
}

func TestVaultBrokerFetch_DynamicAWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/aws/creds/my-role" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		resp := vaultSecretResponse{
			Data: map[string]any{
				"access_key": "AKID123",
				"secret_key": "secret456",
			},
			LeaseID:       "aws/creds/my-role/abcd1234",
			LeaseDuration: 900,
			Renewable:     true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	b := NewVaultBroker(VaultConfig{
		Addr:      srv.URL,
		Token:     "root",
		MountPath: "aws",
	})

	cred, err := b.Fetch(context.Background(), FetchRequest{
		ToolID: "aws/s3-upload",
		Scope:  "my-role",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "AKID123" {
		t.Fatalf("got %q, want AKID123", cred.Value)
	}
	if !cred.Revocable {
		t.Fatal("expected revocable credential (lease)")
	}
}

func TestVaultBrokerFetch_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"errors":["permission denied"]}`, 403)
	}))
	defer srv.Close()

	b := NewVaultBroker(VaultConfig{
		Addr:  srv.URL,
		Token: "bad-token",
	})
	_, err := b.Fetch(context.Background(), FetchRequest{ToolID: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVaultBrokerRevoke(t *testing.T) {
	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/leases/revoke" {
			revoked = true
			w.WriteHeader(204)
			return
		}
		http.Error(w, "not found", 404)
	}))
	defer srv.Close()

	b := NewVaultBroker(VaultConfig{Addr: srv.URL, Token: "root"})
	err := b.Revoke(context.Background(), &Credential{
		Revocable: true,
		handle:    "aws/creds/my-role/abcd1234",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("expected revoke call")
	}
}
