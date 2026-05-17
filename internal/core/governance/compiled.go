package governance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/agentgov"
	"github.com/faramesh/faramesh-core/internal/daemon"
)

const compiledFormatVersion = 1

// Compiled is the durable output of governance compilation (written by apply).
type Compiled struct {
	Version        int       `json:"version"`
	StackDir       string    `json:"stack_dir"`
	SourcePath     string    `json:"source_path"`
	SourceSHA256   string    `json:"source_sha256"`
	CompiledAt     time.Time `json:"compiled_at"`
	PolicyFPL      string    `json:"policy_fpl"`
	PrimaryAgentID string             `json:"primary_agent_id"`
	Providers      []ProviderCompiled        `json:"providers,omitempty"`
	Agents         map[string]agentgov.Spec  `json:"agents,omitempty"`
	BudgetPools    []agentgov.BudgetPool     `json:"budget_pools,omitempty"`
	Daemon         DaemonSnapshot            `json:"daemon"`
}

// DaemonSnapshot holds daemon.Config fields produced from governance.fms runtime/providers.
type DaemonSnapshot struct {
	PolicyPath                 string `json:"policy_path"`
	DataDir                    string `json:"data_dir"`
	SocketPath                 string `json:"socket_path"`
	LogLevel                   string `json:"log_level"`
	RuntimeMode                string `json:"runtime_mode"`
	GRPCPort                   int    `json:"grpc_port,omitempty"`
	DPRDSN                     string `json:"dpr_dsn,omitempty"`
	RedisURL                   string `json:"redis_url,omitempty"`
	DeferBackend               string `json:"defer_backend,omitempty"`
	DeferRedisPrefix           string `json:"defer_redis_prefix,omitempty"`
	RequireGovernanceBootstrap bool   `json:"require_governance_before_network,omitempty"`
	VaultAddr                  string `json:"vault_addr,omitempty"`
	VaultToken                 string `json:"vault_token,omitempty"`
	VaultMount                 string `json:"vault_mount,omitempty"`
	VaultNamespace             string `json:"vault_namespace,omitempty"`
	AWSSecretsRegion           string `json:"aws_secrets_region,omitempty"`
	GCPSecretsProject          string `json:"gcp_secrets_project,omitempty"`
	AzureKeyVaultURL           string `json:"azure_key_vault_url,omitempty"`
	AzureTenantID              string `json:"azure_tenant_id,omitempty"`
	AzureClientID              string `json:"azure_client_id,omitempty"`
	AzureClientSecret          string `json:"azure_client_secret,omitempty"`
	SPIFFESocketPath           string `json:"spiffe_socket,omitempty"`
	OTLPEnabled                bool   `json:"otlp_enabled,omitempty"`
	OTLPEndpoint               string `json:"otlp_endpoint,omitempty"`
	DPRSigner                  string `json:"dpr_signer,omitempty"`
	DPRKMSProvider             string `json:"dpr_kms_provider,omitempty"`
	DPRKMSKeyRef               string `json:"dpr_kms_key_ref,omitempty"`
	TenantID                   string `json:"tenant_id,omitempty"`
	GovernToolResponses        bool   `json:"govern_tool_responses,omitempty"`
	ImmutableConfig            bool   `json:"immutable_config,omitempty"`
	OSTier                     bool   `json:"os_tier,omitempty"`
	StripAmbientCredentials    bool   `json:"strip_ambient_credentials,omitempty"`
	AgentEnforceProfile        string `json:"agent_enforce_profile,omitempty"`
	SupervisedCommand          string `json:"supervised_command,omitempty"`
	BudgetPools                []agentgov.BudgetPool `json:"budget_pools,omitempty"`
}

// Write persists the compiled artifact and policy FPL beside the stack.
func (c *Compiled) Write(stackDir string) error {
	compiledPath := CompiledPath(stackDir)
	if b, err := os.ReadFile(compiledPath); err == nil && len(b) > 0 {
		_ = os.WriteFile(compiledPath+".bak", b, 0o644)
	}
	if b, err := os.ReadFile(c.Daemon.PolicyPath); err == nil && len(b) > 0 {
		_ = os.WriteFile(c.Daemon.PolicyPath+".bak", b, 0o644)
	}
	if err := os.WriteFile(c.Daemon.PolicyPath, []byte(c.PolicyFPL), 0o644); err != nil {
		return fmt.Errorf("write policy fpl: %w", err)
	}
	path := CompiledPath(stackDir)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal compiled: %w", err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write compiled: %w", err)
	}
	return nil
}

// LoadCompiled reads governance.compiled.json from stackDir.
func LoadCompiled(stackDir string) (*Compiled, error) {
	b, err := os.ReadFile(CompiledPath(stackDir))
	if err != nil {
		return nil, err
	}
	var c Compiled
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse compiled: %w", err)
	}
	return &c, nil
}

// ToDaemonConfig maps the snapshot into daemon.Config (policy path must exist on disk).
func (c *Compiled) ToDaemonConfig() daemon.Config {
	if c == nil {
		return daemon.Config{}
	}
	s := c.Daemon
	cfg := daemon.Config{
		PolicyPath:                 s.PolicyPath,
		DataDir:                    s.DataDir,
		SocketPath:                 s.SocketPath,
		GRPCPort:                   s.GRPCPort,
		DPRDSN:                     s.DPRDSN,
		RedisURL:                   s.RedisURL,
		DeferBackend:               s.DeferBackend,
		DeferRedisPrefix:           s.DeferRedisPrefix,
		RequireGovernanceBootstrap: s.RequireGovernanceBootstrap,
		VaultAddr:                  s.VaultAddr,
		VaultToken:                 s.VaultToken,
		VaultMount:                 s.VaultMount,
		VaultNamespace:             s.VaultNamespace,
		AWSSecretsRegion:           s.AWSSecretsRegion,
		GCPSecretsProject:          s.GCPSecretsProject,
		AzureKeyVaultURL:           s.AzureKeyVaultURL,
		AzureTenantID:              s.AzureTenantID,
		AzureClientID:              s.AzureClientID,
		AzureClientSecret:          s.AzureClientSecret,
		SPIFFESocketPath:           s.SPIFFESocketPath,
		OTLPEnabled:                s.OTLPEnabled,
		OTLPEndpoint:               s.OTLPEndpoint,
	}
	cfg.RuntimeMode = parseRuntimeMode(s.RuntimeMode)
	cfg.Providers = c.ProviderSpecs()
	cfg.AgentGovernance = c.Agents
	cfg.DPRSigner = s.DPRSigner
	cfg.DPRKMSProvider = s.DPRKMSProvider
	cfg.DPRKMSKeyRef = s.DPRKMSKeyRef
	cfg.StackTenantID = s.TenantID
	cfg.GovernToolResponses = s.GovernToolResponses
	cfg.BudgetPools = append([]agentgov.BudgetPool(nil), c.BudgetPools...)
	cfg.StackDir = strings.TrimSpace(c.StackDir)
	cfg.ImmutableConfig = s.ImmutableConfig
	cfg.OSTier = s.OSTier
	cfg.StripAmbientCredentials = s.StripAmbientCredentials
	cfg.AgentEnforceProfile = s.AgentEnforceProfile
	cfg.SupervisedCommand = s.SupervisedCommand
	cfg.PrimaryAgentID = strings.TrimSpace(c.PrimaryAgentID)
	// Compiled stacks are load-once; changes require faramesh apply (privileged).
	cfg.PolicyHotReload = false
	return cfg
}

func parseRuntimeMode(mode string) core.RuntimeMode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shadow":
		return core.RuntimeModeShadow
	case "audit":
		return core.RuntimeModeAudit
	default:
		return core.RuntimeModeEnforce
	}
}

func absOrJoin(stackDir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(stackDir, p)
}
