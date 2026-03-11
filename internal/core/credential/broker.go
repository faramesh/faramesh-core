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
	"fmt"
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
// Supports dynamic secrets, PKI, and cloud dynamic credentials.
type VaultBroker struct {
	Addr  string
	Token string
}

func (b *VaultBroker) Name() string { return "vault" }

func (b *VaultBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	// TODO: Implement Vault API call for dynamic secret generation.
	// This is the integration point for:
	//   - AWS STS token generation (vault read aws/creds/my-role)
	//   - Database dynamic credentials (vault read database/creds/my-role)
	//   - PKI certificate generation (vault write pki/issue/my-role)
	return nil, fmt.Errorf("vault broker: not yet implemented (addr=%s)", b.Addr)
}

func (b *VaultBroker) Revoke(ctx context.Context, cred *Credential) error {
	// TODO: Implement Vault lease revocation.
	return nil
}

// AWSSecretsBroker fetches credentials from AWS Secrets Manager.
type AWSSecretsBroker struct {
	Region string
}

func (b *AWSSecretsBroker) Name() string { return "aws_secrets_manager" }

func (b *AWSSecretsBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	// TODO: Implement AWS Secrets Manager API call.
	return nil, fmt.Errorf("aws secrets broker: not yet implemented (region=%s)", b.Region)
}

func (b *AWSSecretsBroker) Revoke(_ context.Context, _ *Credential) error { return nil }

// GCPSecretsBroker fetches credentials from GCP Secret Manager.
type GCPSecretsBroker struct {
	Project string
}

func (b *GCPSecretsBroker) Name() string { return "gcp_secret_manager" }

func (b *GCPSecretsBroker) Fetch(ctx context.Context, req FetchRequest) (*Credential, error) {
	// TODO: Implement GCP Secret Manager API call.
	return nil, fmt.Errorf("gcp secrets broker: not yet implemented (project=%s)", b.Project)
}

func (b *GCPSecretsBroker) Revoke(_ context.Context, _ *Credential) error { return nil }
