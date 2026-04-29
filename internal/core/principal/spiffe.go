package principal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

var errSPIFFEUnavailable = errors.New("spiffe provider unavailable")

// SPIFFEProvider resolves workload identity from configured SPIFFE socket.
// Resolution prefers an explicit FARAMESH_SPIFFE_ID override for bootstrap and
// test environments, then falls back to the SPIFFE Workload API socket.
type SPIFFEProvider struct {
	socketPath string
	resolveID  func(ctx context.Context, socketPath string) (string, error)
}

func NewSPIFFEProvider(socketPath string) *SPIFFEProvider {
	return &SPIFFEProvider{
		socketPath: strings.TrimSpace(socketPath),
		resolveID:  resolveSPIFFEID,
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

func resolveSPIFFEID(ctx context.Context, socketPath string) (string, error) {
	if id, ok := explicitSPIFFEID(); ok {
		return id, nil
	}
	if strings.TrimSpace(socketPath) == "" {
		return "", errors.New("spiffe socket path not configured")
	}
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(normalizeSPIFFESocketAddr(socketPath)))
	if err != nil {
		return "", fmt.Errorf("connect spiffe workload api: %w", err)
	}
	defer client.Close()
	svid, err := client.FetchX509SVID(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch x509 svid: %w", err)
	}
	if svid == nil {
		return "", errors.New("workload api returned nil x509-svid")
	}
	return svid.ID.String(), nil
}

func explicitSPIFFEID() (string, bool) {
	v := strings.TrimSpace(getenv("FARAMESH_SPIFFE_ID"))
	if v == "" {
		return "", false
	}
	return v, true
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

func normalizeSPIFFESocketAddr(socketPath string) string {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" {
		return socketPath
	}
	if strings.Contains(socketPath, "://") {
		return socketPath
	}
	if strings.HasPrefix(socketPath, "unix:") {
		return "unix://" + strings.TrimPrefix(socketPath, "unix:")
	}
	if strings.HasPrefix(socketPath, "/") {
		return "unix://" + filepath.Clean(socketPath)
	}
	return socketPath
}

func getenv(key string) string {
	return os.Getenv(key)
}
