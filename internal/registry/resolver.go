package registry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
)

// Resolver fetches registry artifacts over HTTP or from a local faramesh-registry checkout.
type Resolver struct {
	http   *Client
	local  *LocalCatalog
}

// NewResolver picks local catalog (FARAMESH_REGISTRY_ROOT or file:// URL) or HTTP hub client.
func NewResolver() (*Resolver, error) {
	if root := LocalCatalogRootFromEnv(); root != "" {
		loc, err := NewLocalCatalog(root)
		if err != nil {
			return nil, err
		}
		return &Resolver{local: loc}, nil
	}
	base := registryBaseURLFromEnv()
	client, err := hub.NewClient(base)
	if err != nil {
		return nil, err
	}
	return &Resolver{http: NewClient(client)}, nil
}

func registryBaseURLFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL")); v != "" {
		if strings.HasPrefix(v, "file://") {
			return ""
		}
		return v
	}
	return "https://" + DefaultHost
}

// FetchFPLPack loads a policy or framework pack.
func (r *Resolver) FetchFPLPack(ctx context.Context, ref Ref) (*hub.PackVersionResponse, error) {
	if r == nil {
		return nil, fmt.Errorf("registry resolver not configured")
	}
	if r.local != nil {
		return r.local.FetchFPLPack(ctx, ref)
	}
	return r.http.FetchFPLPack(ctx, ref)
}

// InstallProviderBinary downloads or copies a signed provider binary into the stack.
func (r *Resolver) InstallProviderBinary(ctx context.Context, ref Ref, stackDir string) (string, error) {
	if r == nil {
		return "", fmt.Errorf("registry resolver not configured")
	}
	if r.local != nil {
		return r.local.InstallProviderBinary(ctx, ref, stackDir)
	}
	return InstallProviderBinary(ctx, r.http, ref, stackDir)
}

// Local returns the filesystem catalog when configured.
func (r *Resolver) Local() *LocalCatalog {
	if r == nil {
		return nil
	}
	return r.local
}

// FetchProviderVersion loads a provider manifest (HTTP or local).
func (r *Resolver) FetchProviderVersion(ctx context.Context, ref Ref) (*ProviderVersionResponse, error) {
	if r.local != nil {
		return r.local.FetchProviderVersion(ctx, ref)
	}
	return r.http.FetchProviderVersion(ctx, ref)
}

// Search queries the registry catalog (HTTP only).
func (r *Resolver) Search(ctx context.Context, q, kind, tier string) ([]CatalogRow, error) {
	if r.local != nil {
		return r.local.Search(q, kind, tier)
	}
	if r.http == nil || r.http.Hub == nil {
		return nil, fmt.Errorf("registry search requires HTTP registry URL")
	}
	return r.http.Search(ctx, q, kind, tier)
}

// CatalogRow is one artifact in browse/search output.
type CatalogRow struct {
	Kind          string
	Name          string
	LatestVersion string
	Description   string
	TrustTier     string
	Category      string
}
