package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ManifestSidecar is written next to policy.yaml for offline inspection.
type ManifestSidecar struct {
	APIVersion string `json:"api_version"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	SHA256Hex  string `json:"sha256_hex"`
	TrustTier  string `json:"trust_tier,omitempty"`
}

// WritePackToDisk writes policy.yaml and manifest.json under the hub packs root.
func WritePackToDisk(root string, p *PackVersionResponse) (policyPath string, err error) {
	if p == nil {
		return "", fmt.Errorf("nil pack")
	}
	dir := PackInstallDir(root, p.Name, p.Version)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("mkdir pack dir: %w", err)
	}
	policyPath = filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(p.PolicyYAML), 0600); err != nil {
		return "", fmt.Errorf("write policy: %w", err)
	}
	man := ManifestSidecar{
		APIVersion: APIVersion,
		Name:       p.Name,
		Version:    p.Version,
		SHA256Hex:  Sum256Hex([]byte(p.PolicyYAML)),
		TrustTier:  p.TrustTier,
	}
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, mb, 0600); err != nil {
		return "", fmt.Errorf("write manifest: %w", err)
	}
	return policyPath, nil
}
