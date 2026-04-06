package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestNormalizeVaultToolID(t *testing.T) {
	got, err := normalizeVaultToolID("/stripe/refund/")
	if err != nil {
		t.Fatalf("normalizeVaultToolID err: %v", err)
	}
	if got != "stripe/refund" {
		t.Fatalf("normalizeVaultToolID = %q", got)
	}

	if _, err := normalizeVaultToolID("../etc/passwd"); err == nil {
		t.Fatalf("expected traversal validation error")
	}
	if _, err := normalizeVaultToolID("stripe//refund"); err == nil {
		t.Fatalf("expected empty segment validation error")
	}
}

func TestVaultDataWritePath(t *testing.T) {
	got := vaultDataWritePath("secret", "stripe/refund")
	want := "secret/data/faramesh/stripe/refund"
	if got != want {
		t.Fatalf("vaultDataWritePath = %q want %q", got, want)
	}
}

func TestVaultListenAddress(t *testing.T) {
	got, err := vaultListenAddress("http://127.0.0.1:18200")
	if err != nil {
		t.Fatalf("vaultListenAddress err: %v", err)
	}
	if got != "127.0.0.1:18200" {
		t.Fatalf("vaultListenAddress = %q", got)
	}
	if _, err := vaultListenAddress("https://127.0.0.1:18200"); err == nil {
		t.Fatalf("expected https address to fail for local provision")
	}
}

func TestResolveVaultStatePaths(t *testing.T) {
	dir := t.TempDir()
	state, err := resolveVaultStatePaths(dir)
	if err != nil {
		t.Fatalf("resolveVaultStatePaths err: %v", err)
	}
	if state.Dir != dir {
		t.Fatalf("state dir = %q want %q", state.Dir, dir)
	}
	if state.PIDFile != filepath.Join(dir, "vault.pid") {
		t.Fatalf("unexpected pid path: %q", state.PIDFile)
	}
}

func TestPutVaultSecret(t *testing.T) {
	var gotPath string
	var gotMethod string
	var gotToken string
	var gotNamespace string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotToken = r.Header.Get("X-Vault-Token")
		gotNamespace = r.Header.Get("X-Vault-Namespace")
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	err := putVaultSecret(srv.URL, "vault-token", "tenant-a", "secret", "stripe/refund", "api_key", "sk_test_123")
	if err != nil {
		t.Fatalf("putVaultSecret err: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s", gotMethod)
	}
	if gotPath != "/v1/secret/data/faramesh/stripe/refund" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotToken != "vault-token" {
		t.Fatalf("token header = %s", gotToken)
	}
	if gotNamespace != "tenant-a" {
		t.Fatalf("namespace header = %s", gotNamespace)
	}
	data, _ := gotBody["data"].(map[string]any)
	if data["api_key"] != "sk_test_123" {
		t.Fatalf("api_key field not stored")
	}
	if data["value"] != "sk_test_123" {
		t.Fatalf("value field not mirrored")
	}
}
