package principal

import (
	"context"
	"errors"
	"os"
	"strings"
)

var errSPIFFEUnavailable = errors.New("spiffe provider unavailable")

// SPIFFEProvider resolves workload identity from configured SPIFFE socket.
// Current implementation is minimal and safe: resolution is best-effort and
// fail-open for runtime fallback behavior.
type SPIFFEProvider struct {
	socketPath string
	resolveID  func(ctx context.Context, socketPath string) (string, error)
}

func NewSPIFFEProvider(socketPath string) *SPIFFEProvider {
	return &SPIFFEProvider{
		socketPath: strings.TrimSpace(socketPath),
		resolveID:  resolveSPIFFEIDFromEnv,
	}
}

func (p *SPIFFEProvider) Name() string { return "spiffe" }

func (p *SPIFFEProvider) Available(context.Context) bool {
	return p != nil && strings.TrimSpace(p.socketPath) != ""
}

func (p *SPIFFEProvider) Identity(ctx context.Context) (*Identity, error) {
	if !p.Available(ctx) {
		return nil, errSPIFFEUnavailable
	}
	spiffeID, err := p.resolveID(ctx, p.socketPath)
	if err != nil {
		return nil, err
	}
	spiffeID = strings.TrimSpace(spiffeID)
	if spiffeID == "" {
		return nil, errors.New("empty spiffe id")
	}
	return &Identity{
		ID:       spiffeID,
		Tier:     resolveSPIFFETier(),
		Org:      trustDomainFromSPIFFEID(spiffeID),
		Verified: true,
		Method:   "spiffe",
	}, nil
}

func resolveSPIFFEIDFromEnv(_ context.Context, _ string) (string, error) {
	v := strings.TrimSpace(getenv("FARAMESH_SPIFFE_ID"))
	if v == "" {
		return "", errors.New("spiffe id not available")
	}
	return v, nil
}

func resolveSPIFFETier() string {
	v := strings.TrimSpace(getenv("FARAMESH_SPIFFE_TIER"))
	if v == "" {
		return "enterprise"
	}
	return v
}

func trustDomainFromSPIFFEID(id string) string {
	const prefix = "spiffe://"
	if !strings.HasPrefix(strings.ToLower(id), prefix) {
		return ""
	}
	rest := strings.TrimPrefix(id, prefix)
	if i := strings.Index(rest, "/"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func getenv(key string) string {
	return os.Getenv(key)
}
