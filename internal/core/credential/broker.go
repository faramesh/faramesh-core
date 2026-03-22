// Package credential implements the Credential Broker — the feature that
// ensures agents never hold long-lived credentials. For each permitted tool
// call, the broker fetches the minimal credential needed for that specific
// operation, injects it for the duration of the call, then discards it.
//
// This implements Layer 5 from the Faramesh architecture spec.
//
// The broker is an interface: production deploys implement it against
// Vault, AWS Secrets Manager, GCP Secret Manager, etc. The credential
// value is NEVER written to any log, DPR record, OTel span, or error message.
package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Broker is the interface that credential source backends must implement.
// Each implementation fetches minimal, scoped credentials for a single
// tool call and returns them. The caller injects the credential into the
// tool's execution environment and discards it immediately after.
type Broker interface {
	// Fetch retrieves a credential for the given request.
	// The credential must be scoped to the minimum permissions needed
	// for the specified tool and operation.
	//
	// The returned Credential.Value is NEVER logged or persisted.
	Fetch(ctx context.Context, req FetchRequest) (*Credential, error)

	// Revoke revokes a previously fetched credential, if the backend
	// supports credential revocation. This is called after the tool
	// call completes, whether it succeeded or failed.
	// Implementations should return nil if revocation is not supported.
	Revoke(ctx context.Context, cred *Credential) error

	// Name returns the backend name (e.g. "vault", "aws_secrets_manager").
	Name() string
}

// FetchRequest describes what credential is needed.
type FetchRequest struct {
	// ToolID is the governed tool (e.g. "stripe/refund").
	ToolID string

	// Operation is the specific operation (e.g. "create", "read").
	Operation string

	// Scope is the permission scope required (e.g. "stripe:charges:write").
	Scope string

	// AgentID is the requesting agent's identity.
	AgentID string

	// TTL is the maximum lifetime for the credential (0 = backend default).
	TTL time.Duration
}

// Credential is the result of a broker fetch.
// The Value field is NEVER written to logs, DPR records, or telemetry.
type Credential struct {
	// Value is the secret credential value. NEVER LOGGED.
	Value string `json:"-"` // json:"-" prevents accidental serialization

	// Source is the backend that provided this credential.
	Source string `json:"source"`

	// Scope is the actual scope granted (may differ from requested).
	Scope string `json:"scope"`

	// ExpiresAt is when the credential expires (zero = no expiry).
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Revocable indicates whether Revoke() can be called on this credential.
	Revocable bool `json:"revocable"`

	// handle is backend-specific revocation state.
	handle any
}

// DPRMeta returns the metadata safe to record in a DPR record.
// The credential value is NEVER included.
type DPRMeta struct {
	Brokered bool   `json:"credential_brokered"`
	Source   string `json:"credential_source"`
	Scope    string `json:"credential_scope"`
}

// Meta returns the DPR-safe metadata for this credential.
func (c *Credential) Meta() DPRMeta {
	if c == nil {
		return DPRMeta{Brokered: false}
	}
	return DPRMeta{
		Brokered: true,
		Source:   c.Source,
		Scope:    c.Scope,
	}
}

// EnvBroker is the fallback credential broker that reads from environment
// variables. It logs a warning because env vars are less secure than
// brokered credentials (the agent holds them for the deployment lifetime).
type EnvBroker struct{}

func (b *EnvBroker) Name() string { return "env" }

func (b *EnvBroker) Fetch(_ context.Context, req FetchRequest) (*Credential, error) {
	// Env broker is a passthrough — the credential is already in the environment.
	// Return a marker credential indicating env-based injection.
	return &Credential{
		Source:    "env",
		Scope:     req.Scope,
		Revocable: false,
	}, nil
}

func (b *EnvBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

// VaultBroker is a credential broker backed by HashiCorp Vault.
// Supports KV v1/v2 static secrets and dynamic secrets (AWS STS, database, PKI).
// Real implementation in vault.go; use NewVaultBroker(VaultConfig{...}) to construct.
type VaultBroker struct {
	Addr   string
	Token  string
	cfg    VaultConfig
	client *http.Client
}

func (b *VaultBroker) Name() string { return "vault" }

// AWSSecretsBroker fetches credentials from AWS Secrets Manager.
// Real implementation in aws.go; use NewAWSSecretsBroker(AWSSecretsConfig{...}) to construct.
type AWSSecretsBroker struct {
	Region string
	cfg    AWSSecretsConfig
	client *http.Client
}

func (b *AWSSecretsBroker) Name() string { return "aws_secrets_manager" }

func (b *AWSSecretsBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

// GCPSecretsBroker fetches credentials from GCP Secret Manager.
// Real implementation in gcp.go; use NewGCPSecretsBroker(GCPSecretsConfig{...}) to construct.
type GCPSecretsBroker struct {
	Project string
	cfg     GCPSecretsConfig
	client  *http.Client
}

func (b *GCPSecretsBroker) Name() string { return "gcp_secret_manager" }

func (b *GCPSecretsBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

// 1PasswordBroker fetches credentials from 1Password via Connect API.
type OnePasswordBroker struct {
	ConnectHost  string
	ConnectToken string
	VaultID      string
	client       *http.Client
}

func (b *OnePasswordBroker) Name() string { return "1password" }

func (b *OnePasswordBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}
	itemTitle := req.Scope
	if itemTitle == "" {
		itemTitle = "faramesh-" + req.ToolID
	}
	url := b.ConnectHost + "/v1/vaults/" + b.VaultID + "/items?filter=title eq \"" + itemTitle + "\""
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+b.ConnectToken)

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("1password: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("1password: status %d", resp.StatusCode)
	}
	var items []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil || len(items) == 0 {
		return nil, fmt.Errorf("1password: item not found: %s", itemTitle)
	}

	detailURL := b.ConnectHost + "/v1/vaults/" + b.VaultID + "/items/" + items[0].ID
	detailReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, detailURL, nil)
	detailReq.Header.Set("Authorization", "Bearer "+b.ConnectToken)
	detailResp, err := b.client.Do(detailReq)
	if err != nil {
		return nil, err
	}
	defer detailResp.Body.Close()
	var detail struct {
		Fields []struct {
			Label string `json:"label"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	if err := json.NewDecoder(detailResp.Body).Decode(&detail); err != nil {
		return nil, err
	}
	for _, f := range detail.Fields {
		if f.Label == "credential" || f.Label == "password" || f.Label == "api_key" {
			return &Credential{Value: f.Value, Source: "1password", Scope: req.Scope}, nil
		}
	}
	if len(detail.Fields) > 0 {
		return &Credential{Value: detail.Fields[0].Value, Source: "1password", Scope: req.Scope}, nil
	}
	return nil, fmt.Errorf("1password: no credential field found in %s", itemTitle)
}

func (b *OnePasswordBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

// InfisicalBroker fetches credentials from Infisical.
type InfisicalBroker struct {
	Host        string
	Token       string
	Environment string
	ProjectID   string
	client      *http.Client
}

func (b *InfisicalBroker) Name() string { return "infisical" }

func (b *InfisicalBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	if b.client == nil {
		b.client = &http.Client{Timeout: 10 * time.Second}
	}
	secretKey := req.Scope
	if secretKey == "" {
		secretKey = "FARAMESH_" + req.ToolID
	}
	env := b.Environment
	if env == "" {
		env = "prod"
	}
	url := fmt.Sprintf("%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s",
		b.Host, secretKey, b.ProjectID, env)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+b.Token)

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("infisical: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("infisical: status %d", resp.StatusCode)
	}
	var result struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Secret.SecretValue == "" {
		return nil, fmt.Errorf("infisical: empty secret %s", secretKey)
	}
	return &Credential{Value: result.Secret.SecretValue, Source: "infisical", Scope: req.Scope}, nil
}

func (b *InfisicalBroker) Revoke(_ context.Context, _ *Credential) error { return nil }
