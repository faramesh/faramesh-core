package registry

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
)

// CatalogRow is one artifact in browse/search output.
type CatalogRow struct {
	Kind          string
	Name          string
	LatestVersion string
	Description   string
	TrustTier     string
	Category      string
}

// Resolver fetches registry artifacts from GitHub (default), HTTP, or a local checkout.
type Resolver struct {
	github *GitHubCatalog
	http   *Client
	local  *LocalCatalog
}

// NewResolver picks local catalog, explicit HTTP URL, or the public GitHub catalog.
func NewResolver() (*Resolver, error) {
	if root := LocalCatalogRootFromEnv(); root != "" {
		loc, err := NewLocalCatalog(root)
		if err != nil {
			return nil, err
		}
		return &Resolver{local: loc}, nil
	}
	if url := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL")); url != "" && !strings.HasPrefix(url, "file://") {
		client, err := hub.NewClient(url)
		if err != nil {
			return nil, err
		}
		return &Resolver{http: NewClient(client)}, nil
	}
	return &Resolver{github: DefaultGitHubCatalog()}, nil
}

// Local returns the filesystem catalog when configured.
func (r *Resolver) Local() *LocalCatalog {
	if r == nil {
		return nil
	}
	return r.local
}

// FetchFPLPack loads a policy or framework pack.
func (r *Resolver) FetchFPLPack(ctx context.Context, ref Ref) (*hub.PackVersionResponse, error) {
	if r == nil {
		return nil, fmt.Errorf("registry resolver not configured")
	}
	if r.local != nil {
		return r.local.FetchFPLPack(ctx, ref)
	}
	if r.github != nil {
		return r.github.FetchFPLPack(ctx, ref)
	}
	return r.http.FetchFPLPack(ctx, ref)
}

// FetchProviderVersion loads a provider manifest.
func (r *Resolver) FetchProviderVersion(ctx context.Context, ref Ref) (*ProviderVersionResponse, error) {
	if r == nil {
		return nil, fmt.Errorf("registry resolver not configured")
	}
	if r.local != nil {
		return r.local.FetchProviderVersion(ctx, ref)
	}
	if r.github != nil {
		return r.github.FetchProviderVersion(ctx, ref)
	}
	return r.http.FetchProviderVersion(ctx, ref)
}

// InstallProviderBinary downloads or copies a signed provider binary into the stack.
func (r *Resolver) InstallProviderBinary(ctx context.Context, ref Ref, stackDir string) (string, error) {
	if r == nil {
		return "", fmt.Errorf("registry resolver not configured")
	}
	if r.local != nil {
		return r.local.InstallProviderBinary(ctx, ref, stackDir)
	}
	if r.github != nil {
		return r.github.InstallProviderBinary(ctx, ref, stackDir)
	}
	return InstallProviderBinary(ctx, r.http, ref, stackDir)
}

// Search queries the catalog.
func (r *Resolver) Search(ctx context.Context, q, kind, tier string) ([]CatalogRow, error) {
	if r == nil {
		return nil, fmt.Errorf("registry resolver not configured")
	}
	if r.local != nil {
		return r.local.Search(q, kind, tier)
	}
	if r.github != nil {
		return r.github.Search(ctx, q, kind, tier)
	}
	return r.http.Search(ctx, q, kind, tier)
}

// RegistryURLDescription returns a human-readable description of the active registry source.
func RegistryURLDescription() string {
	if root := LocalCatalogRootFromEnv(); root != "" {
		return root
	}
	if v := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL")); v != "" {
		return v
	}
	g := DefaultGitHubCatalog()
	return fmt.Sprintf("https://github.com/%s/%s (ref %s)", g.Owner, g.Repo, g.Ref)
}
