package provider

import (
	"context"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
)

// SecretsBroker adapts ProviderService GetSecret to credential.Broker.
type SecretsBroker struct {
	BrokerName string
	Client     providerv1.ProviderServiceClient
}

func (b *SecretsBroker) Name() string {
	if b.BrokerName != "" {
		return b.BrokerName
	}
	return "provider"
}

func (b *SecretsBroker) Fetch(ctx context.Context, req credential.FetchRequest) (*credential.Credential, error) {
	path := strings.TrimSpace(req.Scope)
	if path == "" {
		path = strings.TrimSpace(req.ToolID)
	}
	secret, err := b.Client.GetSecret(ctx, &providerv1.SecretRequest{
		Path: path,
		Opts: map[string]string{
			"tool_id":   req.ToolID,
			"operation": req.Operation,
			"agent_id":  req.AgentID,
		},
	})
	if err != nil {
		return nil, err
	}
	cred := &credential.Credential{
		Value:  string(secret.GetValue()),
		Source: b.BrokerName,
		Scope:  req.Scope,
	}
	if secret.GetTtl() != nil {
		cred.ExpiresAt = time.Now().Add(secret.GetTtl().AsDuration())
	}
	return cred, nil
}

func (b *SecretsBroker) Revoke(context.Context, *credential.Credential) error {
	return nil
}
