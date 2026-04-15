package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrPackNotInstalled = errors.New("pack is not installed")

type DisabledManifest struct {
	PackName    string                    `json:"pack_name"`
	PackVersion string                    `json:"pack_version"`
	Reason      string                    `json:"reason"`
	Findings    []InstallAdmissionFinding `json:"findings,omitempty"`
	CreatedAt   string                    `json:"created_at"`
}

type PackLifecycleStatus struct {
	PackName           string `json:"pack_name"`
	PackVersion        string `json:"pack_version"`
	Installed          bool   `json:"installed"`
	PolicyPath         string `json:"policy_path,omitempty"`
	PolicyFPLPath      string `json:"policy_fpl_path,omitempty"`
	PolicyCompiledPath string `json:"policy_compiled_path,omitempty"`
	AppliedMode        string `json:"applied_mode,omitempty"`
	TrustTier          string `json:"trust_tier,omitempty"`
	Disabled           bool   `json:"disabled"`
	DisabledPath       string `json:"disabled_path,omitempty"`
	DisabledReason     string `json:"disabled_reason,omitempty"`
	DisabledAt         string `json:"disabled_at,omitempty"`
	DisableFindings    int    `json:"disable_findings,omitempty"`
}

func DisableInstalledPack(root, name, version, reason string, findings []InstallAdmissionFinding) (string, error) {
	dir, policyPath, err := installedPackPaths(root, name, version)
	if err != nil {
		return "", err
	}
	if err := requireInstalledPolicy(policyPath); err != nil {
		return "", err
	}

	manifestPath := filepath.Join(dir, "disabled.json")
	manifest := DisabledManifest{
		PackName:    strings.TrimSpace(name),
		PackVersion: strings.TrimSpace(version),
		Reason:      strings.TrimSpace(reason),
		Findings:    findings,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if manifest.Reason == "" {
		manifest.Reason = "manually disabled"
	}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal disable manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, b, 0o600); err != nil {
		return "", fmt.Errorf("write disable manifest: %w", err)
	}
	return manifestPath, nil
}

func EnableInstalledPack(root, name, version string) error {
	dir, policyPath, err := installedPackPaths(root, name, version)
	if err != nil {
		return err
	}
	if err := requireInstalledPolicy(policyPath); err != nil {
		return err
	}
	manifestPath := filepath.Join(dir, "disabled.json")
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove disable manifest: %w", err)
	}
	return nil
}

func PackStatus(root, name, version string) (PackLifecycleStatus, error) {
	dir, policyPath, err := installedPackPaths(root, name, version)
	if err != nil {
		return PackLifecycleStatus{}, err
	}
	status := PackLifecycleStatus{
		PackName:    strings.TrimSpace(name),
		PackVersion: strings.TrimSpace(version),
		PolicyPath:  policyPath,
	}
	if _, err := os.Stat(policyPath); err != nil {
		if os.IsNotExist(err) {
			status.Installed = false
			return status, nil
		}
		return PackLifecycleStatus{}, fmt.Errorf("stat installed policy: %w", err)
	}
	status.Installed = true
	fplPath := filepath.Join(dir, "policy.fpl")
	if _, err := os.Stat(fplPath); err == nil {
		status.PolicyFPLPath = fplPath
	}
	compiledPath := filepath.Join(dir, compiledPolicyFile)
	if _, err := os.Stat(compiledPath); err == nil {
		status.PolicyCompiledPath = compiledPath
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if manifestBytes, readErr := os.ReadFile(manifestPath); readErr == nil {
		var manifest ManifestSidecar
		if jsonErr := json.Unmarshal(manifestBytes, &manifest); jsonErr == nil {
			status.AppliedMode = manifest.AppliedMode
			status.TrustTier = manifest.TrustTier
		}
	}

	manifestPath = filepath.Join(dir, "disabled.json")
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return status, nil
		}
		return PackLifecycleStatus{}, fmt.Errorf("read disable manifest: %w", err)
	}
	var manifest DisabledManifest
	if err := json.Unmarshal(b, &manifest); err != nil {
		return PackLifecycleStatus{}, fmt.Errorf("decode disable manifest: %w", err)
	}
	status.Disabled = true
	status.DisabledPath = manifestPath
	status.DisabledReason = manifest.Reason
	status.DisabledAt = manifest.CreatedAt
	status.DisableFindings = len(manifest.Findings)
	return status, nil
}

func SetInstalledPackMode(root, name, version, mode string) error {
	dir, policyPath, err := installedPackPaths(root, name, version)
	if err != nil {
		return err
	}
	if err := requireInstalledPolicy(policyPath); err != nil {
		return err
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read install manifest: %w", err)
	}
	var manifest ManifestSidecar
	if err := json.Unmarshal(b, &manifest); err != nil {
		return fmt.Errorf("decode install manifest: %w", err)
	}
	manifest.AppliedMode = normalizeInstallMode(mode)
	updated, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal install manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath, updated, 0o600); err != nil {
		return fmt.Errorf("write install manifest: %w", err)
	}
	return nil
}

func installedPackPaths(root, name, version string) (dir string, policyPath string, err error) {
	cleanName := strings.TrimSpace(name)
	cleanVersion := strings.TrimSpace(version)
	if cleanName == "" || cleanVersion == "" {
		return "", "", fmt.Errorf("pack name and version are required")
	}
	dir = PackInstallDir(root, cleanName, cleanVersion)
	policyPath = filepath.Join(dir, "policy.yaml")
	return dir, policyPath, nil
}

func requireInstalledPolicy(policyPath string) error {
	if _, err := os.Stat(policyPath); err != nil {
		if os.IsNotExist(err) {
			return ErrPackNotInstalled
		}
		return fmt.Errorf("stat installed policy: %w", err)
	}
	return nil
}
