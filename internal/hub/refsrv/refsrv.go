// Package refsrv is a minimal HTTP registry compatible with hub.Client (GET
// /v1/search and GET /v1/packs/{name}/versions/{version}).
package refsrv

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/faramesh/faramesh-core/internal/hub"
)

// Catalog describes packs served by the reference registry.
type Catalog struct {
	Packs []PackCatalogEntry `json:"packs"`
}

// PackCatalogEntry is one pack with versioned policy files on disk.
type PackCatalogEntry struct {
	Name           string            `json:"name"`
	LatestVersion  string            `json:"latest_version"`
	Description    string            `json:"description"`
	TrustTier      string            `json:"trust_tier,omitempty"`
	Versions          map[string]string `json:"versions"` // version -> relative path to policy YAML
	PublisherVerified bool              `json:"publisher_verified,omitempty"`
	PublisherID       string            `json:"publisher_id,omitempty"`
	PublisherName     string            `json:"publisher_display_name,omitempty"`
}

// LoadCatalogFromFile reads catalog JSON. Paths in versions are resolved
// relative to the catalog file's directory. If path is empty, a built-in demo
// catalog (in-memory) is returned.
func LoadCatalogFromFile(path string) (*Catalog, error) {
	if strings.TrimSpace(path) == "" {
		return defaultCatalog(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	for i := range c.Packs {
		for ver, rel := range c.Packs[i].Versions {
			if !filepath.IsAbs(rel) {
				c.Packs[i].Versions[ver] = filepath.Join(base, rel)
			}
		}
	}
	return &c, nil
}

func defaultCatalog() *Catalog {
	return &Catalog{
		Packs: []PackCatalogEntry{
			{
				Name:          "refsrv/demo",
				LatestVersion: "0.1.0",
				Description:   "built-in demo pack for local registry smoke tests",
				TrustTier:     "community",
				Versions: map[string]string{
					"0.1.0": "",
				},
				PublisherID:       "refsrv",
				PublisherName:     "Reference registry",
				PublisherVerified: true,
			},
		},
	}
}

const demoPolicyYAML = `agent_id: refsrv-demo
default_effect: deny
rules:
  - id: permit-echo
    match: { tool: "echo/*" }
    effect: permit
    reason: "demo allow"
`

// NewHandler serves the catalog over HTTP.
func NewHandler(c *Catalog) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/search", func(w http.ResponseWriter, r *http.Request) {
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		var rows []hub.PackSummary
		for _, p := range c.Packs {
			if q != "" && !strings.Contains(strings.ToLower(p.Name), q) && !strings.Contains(strings.ToLower(p.Description), q) {
				continue
			}
			rows = append(rows, hub.PackSummary{
				Name:          p.Name,
				LatestVersion: p.LatestVersion,
				Description:   p.Description,
				TrustTier:     p.TrustTier,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(hub.SearchResponse{APIVersion: hub.APIVersion, Packs: rows})
	})

	mux.HandleFunc("GET /v1/packs/{name}/versions/{version}", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSpace(r.PathValue("name"))
		version := strings.TrimSpace(r.PathValue("version"))
		if name == "" || version == "" {
			http.Error(w, "missing name or version", http.StatusBadRequest)
			return
		}
		body, fplBody, err := policyBodiesForVersion(c, name, version)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		sum := sha256.Sum256(body)
		resp := hub.PackVersionResponse{
			APIVersion: hub.APIVersion,
			Name:        name,
			Version:     version,
			Description: "reference registry pack",
			PolicyYAML:  string(body),
			SHA256Hex:   hex.EncodeToString(sum[:]),
		}
		if len(fplBody) > 0 {
			resp.PolicyFPL = string(fplBody)
		}
		for _, p := range c.Packs {
			if p.Name != name {
				continue
			}
			resp.Description = p.Description
			resp.TrustTier = p.TrustTier
			if p.PublisherID != "" {
				resp.Publisher = &hub.PackPublisher{
					ID:          p.PublisherID,
					DisplayName: p.PublisherName,
					Verified:    p.PublisherVerified,
				}
			}
			break
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	return mux
}

func policyBodiesForVersion(c *Catalog, name, version string) (yaml []byte, fpl []byte, err error) {
	for _, p := range c.Packs {
		if p.Name != name {
			continue
		}
		pathOrEmpty, ok := p.Versions[version]
		if !ok {
			return nil, nil, fmt.Errorf("unknown version %q for pack %q", version, name)
		}
		if pathOrEmpty == "" {
			return []byte(demoPolicyYAML), nil, nil
		}
		b, err := os.ReadFile(pathOrEmpty)
		if err != nil {
			return nil, nil, fmt.Errorf("read policy: %w", err)
		}
		fplPath := strings.TrimSuffix(pathOrEmpty, ".yaml") + ".fpl"
		if fb, err := os.ReadFile(fplPath); err == nil {
			fpl = fb
		}
		return b, fpl, nil
	}
	return nil, nil, fmt.Errorf("unknown pack %q", name)
}
