package hub

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClientRequiresURL(t *testing.T) {
	if _, err := NewClient(""); err == nil {
		t.Fatal("expected error")
	}
	if _, err := NewClient("ftp://x"); err == nil {
		t.Fatal("expected error for non-http(s)")
	}
}

func TestSearchAndGetPackVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/search" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(SearchResponse{
				APIVersion: "1",
				Packs: []PackSummary{
					{Name: "demo/pack", LatestVersion: "1.0.0", Description: "test", Downloads: 3},
				},
			})
		case r.URL.Path == "/v1/packs/demo-pack/versions/1.0.0" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(PackVersionResponse{
				APIVersion: "1",
				Name:       "demo-pack",
				Version:    "1.0.0",
				PolicyYAML: "faramesh-version: \"1.0\"\nagent-id: \"x\"\n",
				SHA256Hex:  Sum256Hex([]byte("faramesh-version: \"1.0\"\nagent-id: \"x\"\n")),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()

	ctx := context.Background()
	sr, err := c.Search(ctx, "demo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sr.Packs) != 1 || sr.Packs[0].Name != "demo/pack" {
		t.Fatalf("search: %+v", sr)
	}

	pv, err := c.GetPackVersion(ctx, "demo-pack", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePackPayload(pv); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPolicySignatureRoundTrip(t *testing.T) {
	policy := []byte("faramesh-version: \"1.0\"\nagent-id: \"demo\"\n")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, policy)
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	pv := &PackVersionResponse{
		APIVersion: "1",
		Name:       "demo/pack",
		Version:    "1.0.0",
		PolicyYAML: string(policy),
		SHA256Hex:  Sum256Hex(policy),
		Signature: &PackSignature{
			Algorithm:    "ed25519",
			ValueB64:     base64.StdEncoding.EncodeToString(sig),
			PublicKeyPEM: string(pemBytes),
		},
	}
	if err := ValidatePackPayload(pv); err != nil {
		t.Fatal(err)
	}
}

func TestPublish(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/packs" && r.Method == http.MethodPost {
			var err error
			gotBody, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	ctx := context.Background()
	fpl := "agent z { default deny rules { deny! shell/run } }\n"
	if err := c.Publish(ctx, PublishRequest{Name: "x/y", Version: "1.0.0", PolicyYAML: "k: v\n", PolicyFPL: fpl}); err != nil {
		t.Fatal(err)
	}
	var dec map[string]any
	if err := json.Unmarshal(gotBody, &dec); err != nil {
		t.Fatal(err)
	}
	if got, ok := dec["policy_fpl"].(string); !ok || got != fpl {
		t.Fatalf("publish body policy_fpl: got %q want %q", got, fpl)
	}
}

func TestSearchVisibilityAndOrgHeader(t *testing.T) {
	var gotQuery, gotOrg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/search" && r.Method == http.MethodGet {
			gotQuery = r.URL.RawQuery
			gotOrg = r.Header.Get("X-Faramesh-Org-Id")
			_ = json.NewEncoder(w).Encode(SearchResponse{APIVersion: "1", Packs: nil})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.HTTP = srv.Client()
	c.OrgID = "org_acme"

	ctx := context.Background()
	_, err = c.Search(ctx, "demo", &SearchOptions{Visibility: "org"})
	if err != nil {
		t.Fatal(err)
	}
	if gotOrg != "org_acme" {
		t.Fatalf("org header = %q", gotOrg)
	}
	if !strings.Contains(gotQuery, "visibility=org") || !strings.Contains(gotQuery, "q=demo") {
		t.Fatalf("query = %q", gotQuery)
	}
}
