package credential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAzureKeyVaultBroker_Fetch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secrets/faramesh-stripe-refund" {
			json.NewEncoder(w).Encode(azureSecretResponse{
				Value: "sk_live_azure_secret_42",
				ID:    "https://myvault.vault.azure.net/secrets/faramesh-stripe-refund/v1",
			})
			return
		}
		w.WriteHeader(404)
	}))
	defer ts.Close()

	broker := NewAzureKeyVaultBroker(AzureKeyVaultConfig{
		VaultURL: ts.URL,
		Endpoint: ts.URL,
		Timeout:  5 * time.Second,
	})
	// Skip OAuth token for test — inject directly
	broker.token = "test-token"
	broker.tokenExp = time.Now().Add(time.Hour)

	cred, err := broker.Fetch(context.Background(), FetchRequest{
		ToolID:    "stripe-refund",
		Operation: "create",
		Scope:     "",
	})
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if cred.Value != "sk_live_azure_secret_42" {
		t.Errorf("expected sk_live_azure_secret_42, got %s", cred.Value)
	}
	if cred.Source != "azure_key_vault" {
		t.Errorf("expected source azure_key_vault, got %s", cred.Source)
	}
}

func TestAzureKeyVaultBroker_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("not found"))
	}))
	defer ts.Close()

	broker := NewAzureKeyVaultBroker(AzureKeyVaultConfig{
		VaultURL: ts.URL,
		Endpoint: ts.URL,
	})
	broker.token = "test-token"
	broker.tokenExp = time.Now().Add(time.Hour)

	_, err := broker.Fetch(context.Background(), FetchRequest{
		ToolID: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}
