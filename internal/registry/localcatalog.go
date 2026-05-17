package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
	"github.com/faramesh/faramesh-core/internal/provider/launcher"
)

// LocalCatalog resolves artifacts from a faramesh-registry Git checkout (catalog/ tree).
type LocalCatalog struct {
	Root string // repo root containing catalog/
}

// LocalCatalogRootFromEnv returns a filesystem registry root if configured.
func LocalCatalogRootFromEnv() string {
	if v := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_ROOT")); v != "" {
		return v
	}
	url := strings.TrimSpace(os.Getenv("FARAMESH_REGISTRY_URL"))
	if strings.HasPrefix(url, "file://") {
		return strings.TrimPrefix(url, "file://")
	}
	return ""
}

// NewLocalCatalog loads catalog.json under root/catalog.
func NewLocalCatalog(root string) (*LocalCatalog, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("empty local registry root")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	cat := filepath.Join(abs, "catalog", "catalog.json")
	if _, err := os.Stat(cat); err != nil {
		return nil, fmt.Errorf("local registry: missing %s (expected a faramesh-registry checkout)", cat)
	}
	return &LocalCatalog{Root: abs}, nil
}

func (l *LocalCatalog) catalogDir() string {
	return filepath.Join(l.Root, "catalog")
}

type catalogIndex struct {
	Providers  []catalogEntry `json:"providers"`
	Policies   []catalogEntry `json:"policies"`
	Frameworks []catalogEntry `json:"frameworks"`
	Packs      []catalogEntry `json:"packs"`
}

type catalogEntry struct {
	Name          string            `json:"name"`
	LatestVersion string            `json:"latest_version"`
	Description   string            `json:"description"`
	TrustTier     string            `json:"trust_tier,omitempty"`
	Category      string            `json:"category,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Versions      map[string]string `json:"versions"`
}

func (l *LocalCatalog) loadIndex() (*catalogIndex, error) {
	b, err := os.ReadFile(filepath.Join(l.catalogDir(), "catalog.json"))
	if err != nil {
		return nil, err
	}
	var idx catalogIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, err
	}
	resolve := func(m map[string]string) {
		for ver, rel := range m {
			if rel != "" && !filepath.IsAbs(rel) {
				m[ver] = filepath.Join(l.catalogDir(), rel)
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

func (l *LocalCatalog) findEntry(idx *catalogIndex, ref Ref) (*catalogEntry, string, error) {
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
		path, ok := list[i].Versions[ref.Version]
		if !ok {
			return nil, "", fmt.Errorf("%s/%s@%s not in catalog", ref.Kind, ref.Name, ref.Version)
		}
		return &list[i], path, nil
	}
	return nil, "", fmt.Errorf("%s/%s@%s not found", ref.Kind, ref.Name, ref.Version)
}

// FetchFPLPack reads policy.fpl or profile.fpl from the catalog tree.
func (l *LocalCatalog) FetchFPLPack(_ context.Context, ref Ref) (*hub.PackVersionResponse, error) {
	idx, err := l.loadIndex()
	if err != nil {
		return nil, err
	}
	_, artifactPath, err := l.findEntry(idx, ref)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(artifactPath)
	primary := "policy.fpl"
	if ref.Kind == KindFramework {
		primary = "profile.fpl"
	}
	fplPath := filepath.Join(dir, primary)
	body, err := os.ReadFile(fplPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", fplPath, err)
	}
	out := &hub.PackVersionResponse{Name: ref.Name, Version: ref.Version, PolicyFPL: string(body)}
	if sig, err := os.ReadFile(fplPath + ".sig"); err == nil {
		var sigRef hub.PackSignature
		if json.Unmarshal(sig, &sigRef) == nil {
			out.Signature = &sigRef
		}
	}
	return out, nil
}

// FetchProviderVersion loads manifest.json for a provider version.
func (l *LocalCatalog) FetchProviderVersion(_ context.Context, ref Ref) (*ProviderVersionResponse, error) {
	idx, err := l.loadIndex()
	if err != nil {
		return nil, err
	}
	ent, manifestPath, err := l.findEntry(idx, ref)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(manifestPath)
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
	artDir := filepath.Join(l.catalogDir(), "artifacts")
	for k, dl := range man.Downloads {
		url := strings.TrimSpace(dl.URL)
		if strings.HasPrefix(url, "file://") {
			rel := strings.TrimPrefix(url, "file://")
			if !filepath.IsAbs(rel) {
				rel = filepath.Join(filepath.Dir(manifestPath), rel)
			}
			man.Downloads[k] = ProviderDownload{URL: "file://" + rel, SHA256Hex: dl.SHA256Hex, Size: dl.Size}
			_ = artDir
		}
	}
	return &man, nil
}

// InstallProviderBinary copies the platform binary from the local catalog tree.
func (l *LocalCatalog) InstallProviderBinary(ctx context.Context, ref Ref, stackDir string) (string, error) {
	pv, err := l.FetchProviderVersion(ctx, ref)
	if err != nil {
		return "", err
	}
	key := PlatformKey()
	dl, ok := pv.Downloads[key]
	if !ok || strings.TrimSpace(dl.URL) == "" {
		return "", fmt.Errorf("provider %s@%s: no download for %s", ref.Name, ref.Version, key)
	}
	installDir := filepath.Join(stackDir, ".faramesh", "providers", strings.ReplaceAll(ref.Name, "/", "_")+"@"+ref.Version)
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return "", err
	}
	binPath := filepath.Join(installDir, "provider")
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
		pubB64 := strings.TrimSpace(pv.Signature.PublicKeyPEM)
		if pubB64 == "" {
			pubB64 = strings.TrimSpace(pv.Signature.PublicKeyB64)
		}
		if pubB64 != "" {
			_ = ensureRegistryPublicKey(stackDir, pubB64)
		}
	}
	if err := launcher.VerifyBinary(binPath, stackDir); err != nil {
		return "", err
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return "", err
	}
	return binPath, nil
}
