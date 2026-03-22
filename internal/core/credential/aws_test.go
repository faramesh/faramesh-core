package credential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAWSSecretsBrokerFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := awsSecretResponse{
			Name:         "faramesh/stripe/refund",
			SecretString: "sk_live_stripe_key_123",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	b := NewAWSSecretsBroker(AWSSecretsConfig{
		Region:   "us-west-2",
		Endpoint: srv.URL,
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

	b := NewAWSSecretsBroker(AWSSecretsConfig{Endpoint: srv.URL})
	_, err := b.Fetch(context.Background(), FetchRequest{ToolID: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
}
