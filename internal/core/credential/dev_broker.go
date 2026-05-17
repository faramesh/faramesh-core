package credential

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// DevBroker issues ephemeral placeholder secrets for faramesh dev (no Vault required).
type DevBroker struct{}

func (b *DevBroker) Name() string { return "dev-vault" }

func (b *DevBroker) Fetch(_ context.Context, req FetchRequest) (*Credential, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("dev-vault: %w", err)
	}
	scope := req.Scope
	if scope == "" {
		scope = req.ToolID
	}
	return &Credential{
		Value:     "STUB-" + hex.EncodeToString(buf),
		Source:    "dev-vault",
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
		Revocable: false,
	}, nil
}

func (b *DevBroker) Revoke(_ context.Context, _ *Credential) error { return nil }
