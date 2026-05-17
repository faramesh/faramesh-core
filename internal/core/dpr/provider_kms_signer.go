package dpr

import (
	"context"
	"fmt"
	"time"

	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
)

// ProviderKMSSigner signs DPR payloads via ProviderService.Sign (production KMS path).
type ProviderKMSSigner struct {
	client providerv1.ProviderServiceClient
	keyRef string
}

// NewProviderKMSSigner returns a signer backed by a KMS-capable provider.
func NewProviderKMSSigner(client providerv1.ProviderServiceClient, keyRef string) (*ProviderKMSSigner, error) {
	if client == nil {
		return nil, fmt.Errorf("kms provider client is nil")
	}
	return &ProviderKMSSigner{client: client, keyRef: keyRef}, nil
}

func (p *ProviderKMSSigner) ID() string {
	if p == nil {
		return ""
	}
	if p.keyRef != "" {
		return "provider-kms:" + p.keyRef
	}
	return "provider-kms"
}

func (p *ProviderKMSSigner) PublicKey() ([]byte, error) {
	return nil, fmt.Errorf("provider kms signer does not expose local public key material")
}

func (p *ProviderKMSSigner) Sign(data []byte) ([]byte, error) {
	if p == nil || p.client == nil {
		return nil, fmt.Errorf("provider kms signer not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := p.client.Sign(ctx, &providerv1.SignRequest{
		Payload: data,
		KeyRef:  p.keyRef,
	})
	if err != nil {
		return nil, fmt.Errorf("provider kms sign: %w", err)
	}
	if resp == nil || len(resp.GetSignature()) == 0 {
		return nil, fmt.Errorf("provider kms sign: empty signature")
	}
	return resp.GetSignature(), nil
}
