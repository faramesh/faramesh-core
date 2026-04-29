package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type runtimeProfile struct {
	UpdatedAt  string                    `json:"updated_at,omitempty"`
	Credential *runtimeCredentialProfile `json:"credential,omitempty"`
}

type runtimeCredentialProfile struct {
	Enabled           bool   `json:"enabled"`
	Backend           string `json:"backend,omitempty"`
	VaultAddr         string `json:"vault_addr,omitempty"`
	VaultToken        string `json:"vault_token,omitempty"`
	VaultMount        string `json:"vault_mount,omitempty"`
	AWSRegion         string `json:"aws_region,omitempty"`
	GCPProject        string `json:"gcp_project,omitempty"`
	AzureVaultURL     string `json:"azure_vault_url,omitempty"`
	AzureTenantID     string `json:"azure_tenant_id,omitempty"`
	AzureClientID     string `json:"azure_client_id,omitempty"`
	AzureClientSecret string `json:"azure_client_secret,omitempty"`
	AllowEnvFallback  bool   `json:"allow_env_fallback,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
}

func runtimeProfilePath() string {
	return filepath.Join(runtimeStateDirPath(""), "profile.json")
}

func loadRuntimeProfile() (runtimeProfile, error) {
	path := runtimeProfilePath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return runtimeProfile{}, nil
		}
		return runtimeProfile{}, fmt.Errorf("read runtime profile: %w", err)
	}

	if len(strings.TrimSpace(string(raw))) == 0 {
		return runtimeProfile{}, nil
	}

	var profile runtimeProfile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return runtimeProfile{}, fmt.Errorf("parse runtime profile: %w", err)
	}
	return profile, nil
}

func saveRuntimeProfile(profile runtimeProfile) error {
	profile.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if profile.Credential != nil {
		profile.Credential.UpdatedAt = profile.UpdatedAt
	}

	path := runtimeProfilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create runtime profile directory: %w", err)
	}
	body, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runtime profile: %w", err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write runtime profile: %w", err)
	}
	return nil
}

func applyCredentialProfileToServeArgs(args []string, profile runtimeProfile) []string {
	cred := profile.Credential
	if cred == nil || !cred.Enabled {
		return args
	}

	backend := strings.ToLower(strings.TrimSpace(cred.Backend))
	switch backend {
	case "", "env":
		// Explicit env fallback profile does not require extra flags.
	case "local-vault", "vault":
		if addr := strings.TrimSpace(cred.VaultAddr); addr != "" {
			args = appendFlagIfMissing(args, "--vault-addr", addr)
		}
		if token := strings.TrimSpace(cred.VaultToken); token != "" {
			args = appendFlagIfMissing(args, "--vault-token", token)
		}
		if mount := strings.TrimSpace(cred.VaultMount); mount != "" {
			args = appendFlagIfMissing(args, "--vault-mount", mount)
		}
	case "aws":
		if region := strings.TrimSpace(cred.AWSRegion); region != "" {
			args = appendFlagIfMissing(args, "--aws-secrets-region", region)
		}
	case "gcp":
		if project := strings.TrimSpace(cred.GCPProject); project != "" {
			args = appendFlagIfMissing(args, "--gcp-secrets-project", project)
		}
	case "azure":
		if vaultURL := strings.TrimSpace(cred.AzureVaultURL); vaultURL != "" {
			args = appendFlagIfMissing(args, "--azure-vault-url", vaultURL)
		}
		if tenant := strings.TrimSpace(cred.AzureTenantID); tenant != "" {
			args = appendFlagIfMissing(args, "--azure-tenant-id", tenant)
		}
		if clientID := strings.TrimSpace(cred.AzureClientID); clientID != "" {
			args = appendFlagIfMissing(args, "--azure-client-id", clientID)
		}
		if secret := strings.TrimSpace(cred.AzureClientSecret); secret != "" {
			args = appendFlagIfMissing(args, "--azure-client-secret", secret)
		}
	}

	if cred.AllowEnvFallback {
		args = appendFlagIfMissing(args, "--allow-env-credential-fallback", "true")
	}

	return args
}

func appendFlagIfMissing(args []string, flagName, value string) []string {
	if value == "" || hasFlag(args, flagName) {
		return args
	}
	return append(args, flagName, value)
}

func hasFlag(args []string, flagName string) bool {
	for idx := range args {
		arg := strings.TrimSpace(args[idx])
		if arg == flagName {
			return true
		}
		if strings.HasPrefix(arg, flagName+"=") {
			return true
		}
	}
	return false
}
