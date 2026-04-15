package credential

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
)

// GCPSecretsConfig configures the GCP Secret Manager broker.
type GCPSecretsConfig struct {
	Project     string
	Endpoint    string // override for testing
	AccessToken string // override for testing or explicit bearer injection
	Timeout     time.Duration
}

func (c *GCPSecretsConfig) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
}

// NewGCPSecretsBroker creates a GCP Secret Manager broker.
func NewGCPSecretsBroker(cfg GCPSecretsConfig) *GCPSecretsBroker {
	cfg.defaults()
	return &GCPSecretsBroker{
		Project: cfg.Project,
		cfg:     cfg,
		client:  &http.Client{Timeout: cfg.Timeout},
	}
}

func (b *GCPSecretsBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}

	secretID := resolveGCPSecretID(req)
	endpoint := b.resolveEndpoint()
	url := fmt.Sprintf("%s/v1/projects/%s/secrets/%s/versions/latest:access",
		endpoint, b.cfg.Project, secretID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("gcp secrets: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	token, err := resolveGCPAccessToken(ctx, b.cfg)
	if err != nil {
		return nil, fmt.Errorf("gcp secrets: resolve access token: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gcp secrets: request %s: %w", secretID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcp secrets: %s returned %d: %s", secretID, resp.StatusCode, truncate(string(body), 200))
	}

	var result gcpSecretResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("gcp secrets: parse response: %w", err)
	}

	value := result.Payload.Data
	if value == "" {
		return nil, fmt.Errorf("gcp secrets: empty payload at %s", secretID)
	}

	// Real GCP Secret Manager returns base64-encoded payloads.
	// Try to decode; if it fails, treat the value as plaintext
	// (for test endpoints that return unencoded values).
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		value = string(decoded)
	}

	return &Credential{
		Value:     value,
		Source:    "gcp_secret_manager",
		Scope:     req.Scope,
		Revocable: false,
	}, nil
}

func (b *GCPSecretsBroker) resolveEndpoint() string {
	if b.cfg.Endpoint != "" {
		return b.cfg.Endpoint
	}
	return "https://secretmanager.googleapis.com"
}

func resolveGCPSecretID(req FetchRequest) string {
	if req.Scope != "" {
		return req.Scope
	}
	return "faramesh-" + req.ToolID
}

type gcpSecretResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"`
	} `json:"payload"`
}

func resolveGCPAccessToken(ctx context.Context, cfg GCPSecretsConfig) (string, error) {
	if tok := strings.TrimSpace(cfg.AccessToken); tok != "" {
		return tok, nil
	}

	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return "", err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", err
	}
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return "", fmt.Errorf("received empty access token from default credentials")
	}
	return token.AccessToken, nil
}
