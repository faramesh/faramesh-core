package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VaultConfig configures the Vault credential broker.
type VaultConfig struct {
	Addr      string        `json:"addr"`
	Token     string        `json:"-"`
	MountPath string        `json:"mount_path"` // e.g. "secret", "aws", "database"
	Namespace string        `json:"namespace,omitempty"`
	Timeout   time.Duration `json:"timeout"`
}

func (c *VaultConfig) defaults() {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.MountPath == "" {
		c.MountPath = "secret"
	}
	c.Addr = strings.TrimRight(c.Addr, "/")
}

// NewVaultBroker creates a production Vault credential broker.
func NewVaultBroker(cfg VaultConfig) *VaultBroker {
	cfg.defaults()
	return &VaultBroker{
		Addr:   cfg.Addr,
		Token:  cfg.Token,
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (b *VaultBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}

	path := b.resolvePath(req)
	url := fmt.Sprintf("%s/v1/%s", b.cfg.Addr, path)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: build request: %w", err)
	}
	httpReq.Header.Set("X-Vault-Token", b.cfg.Token)
	if b.cfg.Namespace != "" {
		httpReq.Header.Set("X-Vault-Namespace", b.cfg.Namespace)
	}

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("vault: request %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault: %s returned %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}

	var vaultResp vaultSecretResponse
	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault: parse response: %w", err)
	}

	value, leaseID := extractCredentialValue(vaultResp)
	if value == "" {
		return nil, fmt.Errorf("vault: no credential value in response at %s", path)
	}

	expiresAt := time.Time{}
	if vaultResp.LeaseDuration > 0 {
		expiresAt = time.Now().Add(time.Duration(vaultResp.LeaseDuration) * time.Second)
	}

	return &Credential{
		Value:     value,
		Source:    "vault",
		Scope:     req.Scope,
		ExpiresAt: expiresAt,
		Revocable: leaseID != "",
		handle:    leaseID,
	}, nil
}

func (b *VaultBroker) Revoke(ctx context.Context, cred *Credential) error {
	leaseID, ok := cred.handle.(string)
	if !ok || leaseID == "" {
		return nil
	}
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}

	url := fmt.Sprintf("%s/v1/sys/leases/revoke", b.cfg.Addr)
	payload := fmt.Sprintf(`{"lease_id":"%s"}`, leaseID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("vault: build revoke request: %w", err)
	}
	httpReq.Header.Set("X-Vault-Token", b.cfg.Token)
	httpReq.Header.Set("Content-Type", "application/json")
	if b.cfg.Namespace != "" {
		httpReq.Header.Set("X-Vault-Namespace", b.cfg.Namespace)
	}

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("vault: revoke lease %s: %w", leaseID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault: revoke lease %s returned %d: %s", leaseID, resp.StatusCode, truncate(string(body), 200))
	}
	return nil
}

// resolvePath maps a FetchRequest to a Vault API path.
// Convention: tool "stripe/refund" with mount "secret" → secret/data/faramesh/stripe/refund
// Dynamic secrets (aws, database) use: <mount>/creds/<scope-or-role>
func (b *VaultBroker) resolvePath(req FetchRequest) string {
	mount := b.cfg.MountPath
	switch {
	case mount == "aws" || mount == "database" || mount == "pki":
		role := req.Scope
		if role == "" {
			role = strings.ReplaceAll(req.ToolID, "/", "-")
		}
		return fmt.Sprintf("%s/creds/%s", mount, role)
	default:
		return fmt.Sprintf("%s/data/faramesh/%s", mount, req.ToolID)
	}
}

type vaultSecretResponse struct {
	Data          map[string]any `json:"data"`
	LeaseID       string         `json:"lease_id"`
	LeaseDuration int            `json:"lease_duration"`
	Renewable     bool           `json:"renewable"`
}

func extractCredentialValue(resp vaultSecretResponse) (value string, leaseID string) {
	leaseID = resp.LeaseID
	if resp.Data == nil {
		return "", leaseID
	}
	// KV v2: data is nested under resp.Data["data"]
	if inner, ok := resp.Data["data"].(map[string]any); ok {
		if v, ok := inner["value"].(string); ok {
			return v, leaseID
		}
		if v, ok := inner["api_key"].(string); ok {
			return v, leaseID
		}
		if v, ok := inner["token"].(string); ok {
			return v, leaseID
		}
		if v, ok := inner["password"].(string); ok {
			return v, leaseID
		}
		// Return first string value as fallback.
		for _, v := range inner {
			if s, ok := v.(string); ok && s != "" {
				return s, leaseID
			}
		}
	}
	// KV v1 or dynamic secrets: data is flat.
	for _, key := range []string{"value", "api_key", "token", "password", "access_key", "secret_key"} {
		if v, ok := resp.Data[key].(string); ok && v != "" {
			return v, leaseID
		}
	}
	return "", leaseID
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
