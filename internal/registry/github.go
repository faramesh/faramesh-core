package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/hub"
)

const (
	DefaultHost        = "github.com/faramesh/faramesh-registry"
	defaultGitHubOwner = "faramesh"
	defaultGitHubRepo  = "faramesh-registry"
	defaultGitHubRef   = "main"
)

// GitHubCatalog resolves artifacts from the public faramesh-registry Git repository.
type GitHubCatalog struct {
	Owner string
	Repo  string
	Ref   string
	HTTP  *http.Client
}

// DefaultGitHubCatalog returns the official catalog on GitHub.
func DefaultGitHubCatalog() *GitHubCatalog {
	ref := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_GITHUB_REF"))
	if ref == "" {
		ref = defaultGitHubRef
	}
	owner := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_GITHUB_OWNER"))
	if owner == "" {
		owner = defaultGitHubOwner
	}
	repo := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_GITHUB_REPO"))
	if repo == "" {
		repo = defaultGitHubRepo
	}
	return &GitHubCatalog{
		Owner: owner,
		Repo:  repo,
		Ref:   ref,
		HTTP:  &http.Client{Timeout: 120 * time.Second},
	}
}

func (g *GitHubCatalog) rawURL(rel string) string {
	rel = strings.TrimPrefix(rel, "/")
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", g.Owner, g.Repo, g.Ref, rel)
}

func (g *GitHubCatalog) fetch(ctx context.Context, rel string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.rawURL(rel), nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github catalog fetch %s: HTTP %d", rel, resp.StatusCode)
	}
	return b, nil
}

func (g *GitHubCatalog) loadIndex(ctx context.Context) (*catalogIndex, error) {
	b, err := g.fetch(ctx, "catalog/catalog.json")
	if err != nil {
		return nil, err
	}
	var idx catalogIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, err
	}
	prefix := "catalog/"
	resolve := func(m map[string]string) {
		for ver, rel := range m {
			if rel != "" && !strings.HasPrefix(rel, "catalog/") {
				m[ver] = prefix + rel
			}
		}
	}
	for i := range idx.Packs {
		resolve(idx.Packs[i].Versions)
	}
	for i := range idx.Providers {
		resolve(idx.Providers[i].Versions)
	}
	for i := range idx.Policies {
		resolve(idx.Policies[i].Versions)
	}
	for i := range idx.Frameworks {
		resolve(idx.Frameworks[i].Versions)
	}
	return &idx, nil
}

func (g *GitHubCatalog) findEntry(ctx context.Context, ref Ref) (*catalogEntry, string, error) {
	idx, err := g.loadIndex(ctx)
	if err != nil {
		return nil, "", err
	}
	var list []catalogEntry
	switch ref.Kind {
	case KindProvider:
		list = idx.Providers
	case KindPolicy:
		list = idx.Policies
	case KindFramework:
		list = idx.Frameworks
	default:
		return nil, "", fmt.Errorf("unknown kind %q", ref.Kind)
	}
	for i := range list {
		if list[i].Name != ref.Name {
			continue
		}
		p, ok := list[i].Versions[ref.Version]
		if !ok {
			return nil, "", fmt.Errorf("%s/%s@%s not in catalog", ref.Kind, ref.Name, ref.Version)
		}
		return &list[i], p, nil
	}
	return nil, "", fmt.Errorf("%s/%s@%s not found", ref.Kind, ref.Name, ref.Version)
}

// FetchFPLPack downloads policy.fpl or profile.fpl from GitHub.
func (g *GitHubCatalog) FetchFPLPack(ctx context.Context, ref Ref) (*hub.PackVersionResponse, error) {
	_, artifactRel, err := g.findEntry(ctx, ref)
	if err != nil {
		return nil, err
	}
	dir := path.Dir(artifactRel)
	primary := "policy.fpl"
	if ref.Kind == KindFramework {
		primary = "profile.fpl"
	}
	body, err := g.fetch(ctx, path.Join(dir, primary))
	if err != nil {
		return nil, err
	}
	out := &hub.PackVersionResponse{Name: ref.Name, Version: ref.Version, PolicyFPL: string(body)}
	if sig, err := g.fetch(ctx, path.Join(dir, primary+".sig")); err == nil && len(sig) > 0 {
		var sigRef hub.PackSignature
		if json.Unmarshal(sig, &sigRef) == nil {
			out.Signature = &sigRef
		}
	}
	return out, nil
}

// FetchProviderVersion downloads manifest.json and rewrites file:// downloads to raw GitHub URLs.
func (g *GitHubCatalog) FetchProviderVersion(ctx context.Context, ref Ref) (*ProviderVersionResponse, error) {
	ent, manifestRel, err := g.findEntry(ctx, ref)
	if err != nil {
		return nil, err
	}
	b, err := g.fetch(ctx, manifestRel)
	if err != nil {
		return nil, err
	}
	var man ProviderVersionResponse
	if err := json.Unmarshal(b, &man); err != nil {
		return nil, err
	}
	man.Name = ref.Name
	man.Version = ref.Version
	man.Kind = "provider"
	man.TrustTier = ent.TrustTier
	if len(man.Capabilities) == 0 {
		man.Capabilities = ent.Capabilities
	}
	manifestDir := path.Dir(manifestRel)
	for k, dl := range man.Downloads {
		url := strings.TrimSpace(dl.URL)
		if strings.HasPrefix(url, "file://") {
			rel := strings.TrimPrefix(url, "file://")
			url = g.rawURL(path.Join(manifestDir, rel))
		}
		man.Downloads[k] = ProviderDownload{URL: url, SHA256Hex: dl.SHA256Hex, Size: dl.Size}
	}
	return &man, nil
}

// InstallProviderBinary downloads the provider binary from GitHub raw content.
func (g *GitHubCatalog) InstallProviderBinary(ctx context.Context, ref Ref, stackDir string) (string, error) {
	pv, err := g.FetchProviderVersion(ctx, ref)
	if err != nil {
		return "", err
	}
	key := PlatformKey()
	dl, ok := pv.Downloads[key]
	if !ok || strings.TrimSpace(dl.URL) == "" {
		return "", fmt.Errorf("provider %s@%s: no download for %s", ref.Name, ref.Version, key)
	}
	installDir := path.Join(stackDir, ".faramesh", "providers", strings.ReplaceAll(ref.Name, "/", "_")+"@"+ref.Version)
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", err
	}
	binPath := path.Join(installDir, "provider")
	if err := fetchProviderArtifact(ctx, dl, binPath); err != nil {
		return "", err
	}
	if want := strings.TrimSpace(dl.SHA256Hex); want != "" {
		sum, err := fileSHA256(binPath)
		if err != nil {
			return "", err
		}
		if sum != strings.ToLower(want) {
			_ = os.Remove(binPath)
			return "", fmt.Errorf("provider %s@%s: sha256 mismatch", ref.Name, ref.Version)
		}
	}
	if pv.Signature != nil {
		pubB64 := strings.TrimSpace(pv.Signature.PublicKeyB64)
		if pubB64 == "" {
			pubB64 = strings.TrimSpace(pv.Signature.PublicKeyPEM)
		}
		if pubB64 != "" {
			_ = ensureRegistryPublicKey(stackDir, pubB64)
		}
	}
	if err := verifyProviderBinary(binPath, stackDir); err != nil {
		return "", err
	}
	_ = os.Chmod(binPath, 0o755)
	return binPath, nil
}

// Search lists artifacts from catalog.json on GitHub.
func (g *GitHubCatalog) Search(ctx context.Context, q, kind, tier string) ([]CatalogRow, error) {
	idx, err := g.loadIndex(ctx)
	if err != nil {
		return nil, err
	}
	q = strings.ToLower(strings.TrimSpace(q))
	kind = strings.ToLower(strings.TrimSpace(kind))
	tier = strings.ToLower(strings.TrimSpace(tier))
	return filterCatalogRows(idx, q, kind, tier), nil
}

func filterCatalogRows(idx *catalogIndex, q, kind, tier string) []CatalogRow {
	var out []CatalogRow
	add := func(k string, e catalogEntry) {
		if kind != "" && kind != k {
			return
		}
		if tier != "" && strings.ToLower(e.TrustTier) != tier {
			return
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Name), q) && !strings.Contains(strings.ToLower(e.Description), q) {
			return
		}
		out = append(out, CatalogRow{
			Kind: k, Name: e.Name, LatestVersion: e.LatestVersion,
			Description: e.Description, TrustTier: e.TrustTier, Category: e.Category,
		})
	}
	for _, e := range idx.Providers {
		add("provider", e)
	}
	for _, e := range idx.Policies {
		add("policy", e)
	}
	for _, e := range idx.Frameworks {
		add("framework", e)
	}
	return out
}
