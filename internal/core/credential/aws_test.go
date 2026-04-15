package credential

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAWSSecretsBrokerFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); !strings.Contains(got, "AWS4-HMAC-SHA256") {
			t.Fatalf("missing SigV4 authorization header: %q", got)
		}
		if got := r.Header.Get("X-Amz-Date"); got == "" {
			t.Fatalf("missing X-Amz-Date header")
		}
		if got := r.Header.Get("X-Amz-Security-Token"); got != "test-session" {
			t.Fatalf("unexpected session token header: %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		var req awsGetSecretValueRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req.SecretID != "faramesh/stripe/refund" {
			t.Fatalf("secret id: got %q", req.SecretID)
		}
		resp := awsSecretResponse{
			Name:         "faramesh/stripe/refund",
			SecretString: "sk_live_stripe_key_123",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	b := NewAWSSecretsBroker(AWSSecretsConfig{
		Region:       "us-west-2",
		Endpoint:     srv.URL,
		AccessKey:    "AKIATESTKEY123",
		SecretKey:    "test-secret-key",
		SessionToken: "test-session",
	})

	cred, err := b.Fetch(context.Background(), FetchRequest{
		ToolID: "stripe/refund",
		Scope:  "faramesh/stripe/refund",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Value != "sk_live_stripe_key_123" {
		t.Fatalf("got %q", cred.Value)
	}
	if cred.Source != "aws_secrets_manager" {
		t.Fatalf("got source %q", cred.Source)
	}
}

func TestAWSSecretsBrokerFetch_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"not found"}`, 400)
	}))
	defer srv.Close()

	b := NewAWSSecretsBroker(AWSSecretsConfig{
		Region:    "us-west-2",
		Endpoint:  srv.URL,
		AccessKey: "AKIATESTKEY123",
		SecretKey: "test-secret-key",
	})
	_, err := b.Fetch(context.Background(), FetchRequest{ToolID: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}
