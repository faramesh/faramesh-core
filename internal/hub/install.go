package hub

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManifestSidecar is written next to policy.yaml for offline inspection.
type ManifestSidecar struct {
	APIVersion          string              `json:"api_version"`
	Name                string              `json:"name"`
	Version             string              `json:"version"`
	SHA256Hex           string              `json:"sha256_hex"`
	AppliedMode         string              `json:"applied_mode,omitempty"`
	TrustTier           string              `json:"trust_tier,omitempty"`
	Description         string              `json:"description,omitempty"`
	Publisher           *PackPublisher      `json:"publisher,omitempty"`
	RiskModel           *PackRiskModel      `json:"risk_model,omitempty"`
	SupportedFrameworks []string            `json:"supported_frameworks,omitempty"`
	ActionSurfaces      []string            `json:"supported_action_surfaces,omitempty"`
	Dependencies        []string            `json:"dependencies,omitempty"`
	FarameshVersion     string              `json:"faramesh_version,omitempty"`
	ObserveEnforce      *PackObserveEnforce `json:"observe_enforce_recommendation,omitempty"`
	// PolicyFPLSHA256Hex is set when policy.fpl was installed alongside policy.yaml.
	PolicyFPLSHA256Hex string `json:"policy_fpl_sha256,omitempty"`
	// PolicyCompiledSHA256Hex is the SHA-256 of policy.compiled.yaml (engine-normalized YAML).
	PolicyCompiledSHA256Hex string `json:"policy_compiled_sha256,omitempty"`
}

// WritePackToDisk writes policy.yaml and manifest.json under the hub packs root.
func WritePackToDisk(root string, p *PackVersionResponse) (policyPath string, err error) {
	return WritePackToDiskWithMode(root, p, "enforce")
}

// WritePackToDiskWithMode writes policy.yaml and manifest.json under the hub packs root.
func WritePackToDiskWithMode(root string, p *PackVersionResponse, mode string) (policyPath string, err error) {
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
	hasFPL := strings.TrimSpace(p.PolicyFPL) != ""
	if hasFPL {
		fplPath := filepath.Join(dir, "policy.fpl")
		if err := os.WriteFile(fplPath, []byte(p.PolicyFPL), 0600); err != nil {
			return "", fmt.Errorf("write policy.fpl: %w", err)
		}
	}
	compiledBytes, err := MaterializePolicyCompiledYAML(dir)
	if err != nil {
		return "", err
	}
	compiledPath := filepath.Join(dir, compiledPolicyFile)
	if err := os.WriteFile(compiledPath, compiledBytes, 0600); err != nil {
		return "", fmt.Errorf("write %s: %w", compiledPolicyFile, err)
	}
	man := ManifestSidecar{
		APIVersion:          APIVersion,
		Name:                p.Name,
		Version:             p.Version,
		SHA256Hex:           Sum256Hex([]byte(p.PolicyYAML)),
		AppliedMode:         normalizeInstallMode(mode),
		TrustTier:           p.TrustTier,
		Description:         p.Description,
		Publisher:           p.Publisher,
		RiskModel:           p.RiskModel,
		SupportedFrameworks: append([]string(nil), p.SupportedFrameworks...),
		ActionSurfaces:      append([]string(nil), p.ActionSurfaces...),
		Dependencies:        append([]string(nil), p.Dependencies...),
		FarameshVersion:     p.FarameshVersion,
		ObserveEnforce:      p.ObserveEnforce,
	}
	if hasFPL {
		man.PolicyFPLSHA256Hex = Sum256Hex([]byte(p.PolicyFPL))
	}
	man.PolicyCompiledSHA256Hex = Sum256Hex(compiledBytes)
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

func normalizeInstallMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shadow":
		return "shadow"
	default:
		return "enforce"
	}
}
