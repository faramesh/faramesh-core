package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// GCPSecretsConfig configures the GCP Secret Manager broker.
type GCPSecretsConfig struct {
	Project  string
	Endpoint string // override for testing
	Timeout  time.Duration
}

func (c *GCPSecretsConfig) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
}

// NewGCPSecretsBroker creates a production GCP Secret Manager broker.
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
