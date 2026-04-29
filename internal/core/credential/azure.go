package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AzureKeyVaultConfig configures the Azure Key Vault broker.
type AzureKeyVaultConfig struct {
	VaultURL string // e.g. https://myvault.vault.azure.net
	TenantID string
	ClientID string
	ClientSecret string
	Endpoint string // override for testing
	Timeout  time.Duration
}

func (c *AzureKeyVaultConfig) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
}

// AzureKeyVaultBroker fetches credentials from Azure Key Vault.
type AzureKeyVaultBroker struct {
	VaultURL string
	cfg      AzureKeyVaultConfig
	client   *http.Client
	token    string
	tokenExp time.Time
}

func (b *AzureKeyVaultBroker) Name() string { return "azure_key_vault" }

// NewAzureKeyVaultBroker creates a production Azure Key Vault broker.
func NewAzureKeyVaultBroker(cfg AzureKeyVaultConfig) *AzureKeyVaultBroker {
	cfg.defaults()
	return &AzureKeyVaultBroker{
		VaultURL: cfg.VaultURL,
		cfg:      cfg,
		client:   &http.Client{Timeout: cfg.Timeout},
	}
}

func (b *AzureKeyVaultBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}

	if err := b.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("azure key vault: auth: %w", err)
	}

	secretName := resolveAzureSecretName(req)
	endpoint := b.resolveEndpoint()
	url := fmt.Sprintf("%s/secrets/%s?api-version=7.4", endpoint, secretName)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("azure key vault: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+b.token)

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("azure key vault: request %s: %w", secretName, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure key vault: %s returned %d: %s", secretName, resp.StatusCode, truncate(string(body), 200))
	}

	var result azureSecretResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("azure key vault: parse response: %w", err)
	}

	if result.Value == "" {
		return nil, fmt.Errorf("azure key vault: empty secret at %s", secretName)
	}

	return &Credential{
		Value:     result.Value,
		Source:    "azure_key_vault",
		Scope:     req.Scope,
		Revocable: false,
	}, nil
}

func (b *AzureKeyVaultBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

func (b *AzureKeyVaultBroker) ensureToken(ctx context.Context) error {
	if b.token != "" && time.Now().Before(b.tokenExp) {
		return nil
	}

	if b.cfg.ClientID == "" || b.cfg.ClientSecret == "" || b.cfg.TenantID == "" {
		return fmt.Errorf("azure key vault: ClientID, ClientSecret, and TenantID are required")
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", b.cfg.TenantID)
	body := fmt.Sprintf("grant_type=client_credentials&client_id=%s&client_secret=%s&scope=https://vault.azure.net/.default",
		b.cfg.ClientID, b.cfg.ClientSecret)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Body = io.NopCloser(stringReader(body))

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("azure token: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("azure token: %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return fmt.Errorf("azure token: parse: %w", err)
	}

	b.token = tokenResp.AccessToken
	b.tokenExp = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)
	return nil
}

func (b *AzureKeyVaultBroker) resolveEndpoint() string {
	if b.cfg.Endpoint != "" {
		return b.cfg.Endpoint
	}
	return b.cfg.VaultURL
}

func resolveAzureSecretName(req FetchRequest) string {
	if req.Scope != "" {
		return req.Scope
	}
	return "faramesh-" + req.ToolID
}

type azureSecretResponse struct {
	Value string `json:"value"`
	ID    string `json:"id"`
}

type stringReaderType struct{ s string; i int }

func (r *stringReaderType) Read(p []byte) (int, error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n := copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

func stringReader(s string) io.Reader {
	return &stringReaderType{s: s}
}
