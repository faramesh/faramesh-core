package credential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGCPSecretsBrokerFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/projects/my-project/secrets/faramesh-stripe/refund/versions/latest:access" {
			t.Logf("path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("authorization header: got %q", got)
		}
		resp := gcpSecretResponse{
			Name: "projects/my-project/secrets/faramesh-stripe/refund/versions/1",
		}
		resp.Payload.Data = "Z2NwX3NlY3JldF92YWx1ZV80NTY="
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	b := NewGCPSecretsBroker(GCPSecretsConfig{
		Project:     "my-project",
		Endpoint:    srv.URL,
		AccessToken: "test-token",
	})

	cred, err := b.Fetch(context.Background(), FetchRequest{
		ToolID: "stripe/refund",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "gcp_secret_value_456" {
		t.Fatalf("got %q", cred.Value)
	}
	if cred.Source != "gcp_secret_manager" {
		t.Fatalf("got source %q", cred.Source)
	}
}

func TestGCPSecretsBrokerFetch_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, 404)
	}))
	defer srv.Close()

	b := NewGCPSecretsBroker(GCPSecretsConfig{
		Project:     "bad",
		Endpoint:    srv.URL,
		AccessToken: "test-token",
	})
	_, err := b.Fetch(context.Background(), FetchRequest{ToolID: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}
