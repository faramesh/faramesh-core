package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/cloud"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/daemon"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Faramesh governance runtime service",
	Long: `faramesh serve starts the governance runtime service. Agents submit tool calls
and receive PERMIT/DENY/DEFER decisions. The runtime loads policy, writes
tamper-evident DPR records, and serves governance control APIs.

To stream DPR records to Faramesh Horizon, authenticate first:

  faramesh auth login
  faramesh serve --policy policy.fpl --sync-horizon`,
	RunE: runServe,
}

var (
	servePolicy                      string
	servePolicyURL                   string
	servePolicyPollInterval          time.Duration
	serveDataDir                     string
	serveSocket                      string
	serveSlack                       string
	serveLogLevel                    string
	serveSyncHorizon                 bool
	serveProxyPort                   int
	serveProxyConnect                bool
	serveProxyForward                bool
	serveNetworkHardeningMode        string
	serveInferenceRoutesFile         string
	serveIntentClassifierURL         string
	serveIntentClassifierTimeout     time.Duration
	serveIntentClassifierBearerToken string
	serveAllowPrivateCIDRs           string
	serveAllowPrivateHosts           string
	serveGRPCPort                    int
	serveMCPProxyPort                int
	serveMCPTarget                   string
	serveMCPAllowedOrigins           string
	serveMCPEdgeAuthMode             string
	serveMCPEdgeAuthBearerToken      string
	serveMCPProtocolVersionMode      string
	serveMCPProtocolVersion          string
	serveMCPSessionTTL               time.Duration
	serveMCPSessionIdleTimeout       time.Duration
	serveMCPSSEReplayEnabled         bool
	serveMCPSSEReplayMaxEvents       int
	serveMCPSSEReplayMaxAge          time.Duration
	serveOTLPEnabled                 bool
	serveOTLPEndpoint                string
	serveOTLPProtocol                string
	serveOTLPInsecure                bool
	serveOTLPServiceName             string
	serveOTLPServiceVersion          string
	serveOTLPTracesEnabled           bool
	serveOTLPMetricsEnabled          bool
	serveOTLPLogsEnabled             bool
	serveMetricsPort                 int
	serveDPRDSN                      string
	serveRedisURL                    string
	serveDeferBackend                string
	serveDeferRedisPrefix            string
	serveRuntimeMode                 string
	serveRequireGovernanceBootstrap  bool
	serveDPRHMACKey                  string
	serveTLSCert                     string
	serveTLSKey                      string
	serveClientCA                    string
	serveTLSAuto                     bool
	servePagerDutyRoutingKey         string
	servePolicyAdminToken            string
	serveStandingAdminToken          string
	serveEnableEBPF                  bool
	serveEBPFObjectPath              string
	serveEBPFAttachTP                bool
	serveSPIFFESocketPath            string
	serveSPIFFEID                    string
	serveVaultAddr                   string
	serveVaultToken                  string
	serveVaultMount                  string
	serveVaultNamespace              string
	serveAWSSecretsRegion            string
	serveGCPSecretsProject           string
	serveAzureKeyVaultURL            string
	serveAzureTenantID               string
	serveAzureClientID               string
	serveAzureClientSecret           string
	serveStrictPreflight             bool
	serveIDPProvider                 string
	serveIntegrityManifest           string
	serveIntegrityBaseDir            string
	serveBuildinfoExpected           string
	serveAllowEnvCredFallback        bool
	serveSkipOnboardPreflight        bool
)

func init() {
	serveCmd.Flags().StringVar(&servePolicy, "policy", "policy.fpl", "path to policy file (.fpl or .yaml)")
	serveCmd.Flags().StringVar(&servePolicyURL, "policy-url", "", "HTTP/HTTPS URL for policy YAML (mutually exclusive with --policy)")
	serveCmd.Flags().DurationVar(&servePolicyPollInterval, "policy-poll-interval", 30*time.Second, "poll interval for --policy-url hot reload checks")
	serveCmd.MarkFlagsMutuallyExclusive("policy", "policy-url")
	serveCmd.Flags().StringVar(&serveDataDir, "data-dir", "", "directory for WAL and DPR SQLite (default: ~/.faramesh/runtime/data)")
	serveCmd.Flags().StringVar(&serveSocket, "socket", sdk.SocketPath, "Unix socket path")
	serveCmd.Flags().StringVar(&serveSlack, "slack-webhook", "", "Slack webhook URL for DEFER notifications")
	serveCmd.Flags().StringVar(&serveLogLevel, "log-level", "info", "log level: debug|info|warn|error")
	serveCmd.Flags().BoolVar(&serveSyncHorizon, "sync-horizon", false, "stream DPR records to Faramesh Horizon cloud (requires: faramesh auth login)")
	serveCmd.Flags().IntVar(&serveProxyPort, "proxy-port", 0, "start HTTP proxy adapter on this port (0 disables)")
	serveCmd.Flags().BoolVar(&serveProxyConnect, "proxy-connect", false, "with --proxy-port, enable governed HTTP CONNECT only (tool proxy/connect)")
	serveCmd.Flags().BoolVar(&serveProxyForward, "proxy-forward", false, "with --proxy-port, enable full governed forward proxy: CONNECT + HTTP absolute-form (tools proxy/connect and proxy/http)")
	serveCmd.Flags().StringVar(&serveNetworkHardeningMode, "network-hardening-mode", "off", "proxy network hardening mode: off|audit|enforce")
	serveCmd.Flags().StringVar(&serveInferenceRoutesFile, "inference-routes-file", "", "path to JSON file defining inference route auth/header/model rewrite controls")
	serveCmd.Flags().StringVar(&serveIntentClassifierURL, "intent-classifier-url", "", "HTTP endpoint for async L3 intent classification (writes back via governed session/write)")
	serveCmd.Flags().DurationVar(&serveIntentClassifierTimeout, "intent-classifier-timeout", 3*time.Second, "HTTP timeout for --intent-classifier-url")
	serveCmd.Flags().StringVar(&serveIntentClassifierBearerToken, "intent-classifier-bearer-token", "", "Bearer token used when calling --intent-classifier-url (or set FARAMESH_INTENT_CLASSIFIER_BEARER_TOKEN)")
	serveCmd.Flags().StringVar(&serveAllowPrivateCIDRs, "allow-private-cidrs", "", "comma-separated CIDRs exempt from private-range SSRF blocking (hardening mode only)")
	serveCmd.Flags().StringVar(&serveAllowPrivateHosts, "allow-private-hosts", "", "comma-separated host glob patterns exempt from private-range SSRF blocking (hardening mode only)")
	serveCmd.Flags().IntVar(&serveGRPCPort, "grpc-port", 0, "start gRPC daemon adapter on this port (0 disables)")
	serveCmd.Flags().IntVar(&serveMCPProxyPort, "mcp-proxy-port", 0, "start MCP HTTP gateway on this port (0 disables)")
	serveCmd.Flags().StringVar(&serveMCPTarget, "mcp-target", "", "upstream MCP HTTP server base URL (required when --mcp-proxy-port is set)")
	serveCmd.Flags().StringVar(&serveMCPAllowedOrigins, "mcp-allowed-origins", "", "comma-separated allowed HTTP Origin values for MCP gateway requests (exact origins, e.g. https://app.example.com)")
	serveCmd.Flags().StringVar(&serveMCPEdgeAuthMode, "mcp-edge-auth-mode", "off", "MCP edge auth mode: off|bearer|mtls|bearer_or_mtls")
	serveCmd.Flags().StringVar(&serveMCPEdgeAuthBearerToken, "mcp-edge-auth-bearer-token", "", "Bearer token required by MCP edge auth mode bearer/bearer_or_mtls (or set FARAMESH_MCP_EDGE_AUTH_BEARER_TOKEN)")
	serveCmd.Flags().StringVar(&serveMCPProtocolVersionMode, "mcp-protocol-version-mode", "off", "MCP protocol version enforcement mode: off|strict")
	serveCmd.Flags().StringVar(&serveMCPProtocolVersion, "mcp-protocol-version", "2025-06-18", "required MCP-Protocol-Version value when --mcp-protocol-version-mode=strict")
	serveCmd.Flags().DurationVar(&serveMCPSessionTTL, "mcp-session-ttl", 0, "absolute TTL for MCP sessions keyed by Mcp-Session-Id (0 disables)")
	serveCmd.Flags().DurationVar(&serveMCPSessionIdleTimeout, "mcp-session-idle-timeout", 0, "idle timeout for MCP sessions keyed by Mcp-Session-Id (0 disables)")
	serveCmd.Flags().BoolVar(&serveMCPSSEReplayEnabled, "mcp-sse-replay-enabled", false, "enable bounded Last-Event-ID replay cache for MCP SSE streams")
	serveCmd.Flags().IntVar(&serveMCPSSEReplayMaxEvents, "mcp-sse-replay-max-events", 256, "max cached SSE events per MCP session when replay is enabled")
	serveCmd.Flags().DurationVar(&serveMCPSSEReplayMaxAge, "mcp-sse-replay-max-age", 10*time.Minute, "max age for cached SSE replay events when replay is enabled")
	serveCmd.Flags().BoolVar(&serveOTLPEnabled, "otlp-enabled", false, "enable OpenTelemetry OTLP export for traces/logs/metrics")
	serveCmd.Flags().StringVar(&serveOTLPEndpoint, "otlp-endpoint", "", "OTLP collector endpoint host:port (default grpc=localhost:4317, http=localhost:4318)")
	serveCmd.Flags().StringVar(&serveOTLPProtocol, "otlp-protocol", "grpc", "OTLP transport protocol: grpc|http")
	serveCmd.Flags().BoolVar(&serveOTLPInsecure, "otlp-insecure", true, "use insecure OTLP transport (disable for TLS collectors)")
	serveCmd.Flags().StringVar(&serveOTLPServiceName, "otlp-service-name", "faramesh", "OTLP service.name resource attribute")
	serveCmd.Flags().StringVar(&serveOTLPServiceVersion, "otlp-service-version", "", "OTLP service.version resource attribute (default: policy version)")
	serveCmd.Flags().BoolVar(&serveOTLPTracesEnabled, "otlp-traces-enabled", true, "enable OTLP trace export")
	serveCmd.Flags().BoolVar(&serveOTLPMetricsEnabled, "otlp-metrics-enabled", true, "enable OTLP metric export")
	serveCmd.Flags().BoolVar(&serveOTLPLogsEnabled, "otlp-logs-enabled", true, "enable OTLP log export")
	serveCmd.Flags().IntVar(&serveMetricsPort, "metrics-port", 0, "start Prometheus metrics endpoint on this port (0 disables)")
	serveCmd.Flags().StringVar(&serveDPRDSN, "dpr-dsn", "", "PostgreSQL DSN for mirrored DPR writes")
	serveCmd.Flags().StringVar(&serveRedisURL, "redis-url", "", "Redis URL for shared session backend (optional)")
	serveCmd.Flags().StringVar(&serveDeferBackend, "defer-backend", "memory", "DEFER state backend: memory|redis")
	serveCmd.Flags().StringVar(&serveDeferRedisPrefix, "defer-redis-prefix", "faramesh:defer", "Redis key prefix for DEFER backend state when --defer-backend=redis")
	serveCmd.Flags().StringVar(&serveRuntimeMode, "mode", "enforce", "daemon runtime mode: enforce|shadow|audit")
	serveCmd.Flags().BoolVar(&serveRequireGovernanceBootstrap, "require-governance-before-network", false, "deny network-reaching tools until the agent has passed through governance bootstrap")
	serveCmd.Flags().StringVar(&serveDPRHMACKey, "dpr-hmac-key", "", "HMAC secret for DPR record signatures (default: ephemeral per daemon run)")
	serveCmd.Flags().StringVar(&serveTLSCert, "tls-cert", "", "TLS certificate PEM for adapter listeners (proxy/gRPC/MCP)")
	serveCmd.Flags().StringVar(&serveTLSKey, "tls-key", "", "TLS private key PEM for adapter listeners (proxy/gRPC/MCP)")
	serveCmd.Flags().StringVar(&serveClientCA, "client-ca", "", "Optional client CA PEM to require and verify mTLS client certificates")
	serveCmd.Flags().BoolVar(&serveTLSAuto, "tls-auto", false, "auto-generate an ephemeral self-signed TLS certificate when --tls-cert/--tls-key are not provided")
	serveCmd.Flags().StringVar(&servePagerDutyRoutingKey, "pagerduty-routing-key", "", "PagerDuty Events v2 routing key for DEFER SLA escalations")
	serveCmd.Flags().StringVar(&servePolicyAdminToken, "policy-admin-token", "", "admin token required for local programmatic policy push over gRPC")
	serveCmd.Flags().StringVar(&serveStandingAdminToken, "standing-admin-token", "", "secret required on standing_grant_* SDK messages (or set FARAMESH_STANDING_ADMIN_TOKEN; falls back to policy admin token if set)")
	serveCmd.Flags().BoolVar(&serveEnableEBPF, "ebpf", false, "enable minimal eBPF adapter bootstrap (also settable via FARAMESH_ENABLE_EBPF=true)")
	serveCmd.Flags().StringVar(&serveEBPFObjectPath, "ebpf-object", "", "path to compiled eBPF ELF object (.o), required when eBPF is enabled")
	serveCmd.Flags().BoolVar(&serveEBPFAttachTP, "ebpf-attach-tracepoints", false, "attempt best-effort tracepoint attach for tracepoint programs in the loaded object")
	serveCmd.Flags().StringVar(&serveSPIFFESocketPath, "spiffe-socket", "", "SPIFFE Workload API Unix socket path for workload identity resolution")
	serveCmd.Flags().StringVar(&serveSPIFFEID, "spiffe-id", "", "explicit SPIFFE workload ID override for strict preflight/runtime identity checks")
	serveCmd.Flags().StringVar(&serveVaultAddr, "vault-addr", "", "HashiCorp Vault address for credential broker (also: VAULT_ADDR)")
	serveCmd.Flags().StringVar(&serveVaultToken, "vault-token", "", "Vault token for credential broker (also: VAULT_TOKEN)")
	serveCmd.Flags().StringVar(&serveVaultMount, "vault-mount", "secret", "Vault mount path (e.g. secret, aws, database)")
	serveCmd.Flags().StringVar(&serveVaultNamespace, "vault-namespace", "", "Vault enterprise namespace")
	serveCmd.Flags().StringVar(&serveAWSSecretsRegion, "aws-secrets-region", "", "AWS Secrets Manager region for credential broker")
	serveCmd.Flags().StringVar(&serveGCPSecretsProject, "gcp-secrets-project", "", "GCP Secret Manager project for credential broker")
	serveCmd.Flags().StringVar(&serveAzureKeyVaultURL, "azure-vault-url", "", "Azure Key Vault URL (e.g. https://myvault.vault.azure.net)")
	serveCmd.Flags().StringVar(&serveAzureTenantID, "azure-tenant-id", "", "Azure AD tenant ID for Key Vault auth")
	serveCmd.Flags().StringVar(&serveAzureClientID, "azure-client-id", "", "Azure AD client ID for Key Vault auth")
	serveCmd.Flags().StringVar(&serveAzureClientSecret, "azure-client-secret", "", "Azure AD client secret for Key Vault auth")
	serveCmd.Flags().BoolVar(&serveStrictPreflight, "strict-preflight", false, "enforce mandatory startup preflight gates (identity, provenance, credential sequestration, defer/idp requirements, integrity manifest/buildinfo, sbom generation)")
	serveCmd.Flags().StringVar(&serveIDPProvider, "idp-provider", "", "identity provider used for principal verification preflight (default=ephemeral|local|okta|azure_ad|auth0|google|ldap)")
	serveCmd.Flags().StringVar(&serveIntegrityManifest, "integrity-manifest", "", "artifact manifest JSON required for strict preflight integrity checks")
	serveCmd.Flags().StringVar(&serveIntegrityBaseDir, "integrity-base-dir", ".", "base directory used to verify paths in --integrity-manifest")
	serveCmd.Flags().StringVar(&serveBuildinfoExpected, "buildinfo-expected", "", "expected buildinfo JSON fingerprint required for strict preflight integrity checks")
	serveCmd.Flags().BoolVar(&serveAllowEnvCredFallback, "allow-env-credential-fallback", false, "allow env-based credential broker fallback (development-only escape hatch; keep disabled in production)")
	serveCmd.Flags().BoolVar(&serveSkipOnboardPreflight, "skip-onboard-preflight", false, "skip pre-daemon onboarding readiness checks before strict startup")
}

func runServe(cmd *cobra.Command, args []string) error {
	log, err := buildLogger(serveLogLevel)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	defer log.Sync()

	if spiffeID := resolveSPIFFEID(); spiffeID != "" {
		_ = os.Setenv("FARAMESH_SPIFFE_ID", spiffeID)
	}

	strictPreflight := resolveStrictPreflight()
	if strictPreflight && !serveSkipOnboardPreflight {
		if err := runServeOnboardPreflight(); err != nil {
			return fmt.Errorf("onboard preflight: %w", err)
		}
	}

	cfg := daemon.Config{
		PolicyPath:                  servePolicy,
		PolicyURL:                   servePolicyURL,
		PolicyPollInterval:          servePolicyPollInterval,
		DataDir:                     serveDataDir,
		SocketPath:                  serveSocket,
		SlackWebhook:                serveSlack,
		Log:                         log,
		ProxyPort:                   serveProxyPort,
		ProxyConnect:                serveProxyConnect,
		ProxyForward:                serveProxyForward,
		NetworkHardeningMode:        strings.ToLower(strings.TrimSpace(serveNetworkHardeningMode)),
		InferenceRoutesFile:         strings.TrimSpace(serveInferenceRoutesFile),
		IntentClassifierURL:         strings.TrimSpace(serveIntentClassifierURL),
		IntentClassifierTimeout:     serveIntentClassifierTimeout,
		IntentClassifierBearerToken: strings.TrimSpace(serveIntentClassifierBearerToken),
		AllowedPrivateCIDRs:         splitCSVList(serveAllowPrivateCIDRs),
		AllowedPrivateHosts:         splitCSVList(serveAllowPrivateHosts),
		GRPCPort:                    serveGRPCPort,
		MCPProxyPort:                serveMCPProxyPort,
		MCPTarget:                   serveMCPTarget,
		MCPAllowedOrigins:           splitCSVList(serveMCPAllowedOrigins),
		MCPEdgeAuthMode:             strings.ToLower(strings.TrimSpace(serveMCPEdgeAuthMode)),
		MCPEdgeAuthBearerToken:      resolveMCPEdgeAuthBearerToken(),
		MCPProtocolVersionMode:      strings.ToLower(strings.TrimSpace(serveMCPProtocolVersionMode)),
		MCPProtocolVersion:          strings.TrimSpace(serveMCPProtocolVersion),
		MCPSessionTTL:               serveMCPSessionTTL,
		MCPSessionIdleTimeout:       serveMCPSessionIdleTimeout,
		MCPSSEReplayEnabled:         serveMCPSSEReplayEnabled,
		MCPSSEReplayMaxEvents:       serveMCPSSEReplayMaxEvents,
		MCPSSEReplayMaxAge:          serveMCPSSEReplayMaxAge,
		OTLPEnabled:                 serveOTLPEnabled,
		OTLPEndpoint:                strings.TrimSpace(serveOTLPEndpoint),
		OTLPProtocol:                strings.ToLower(strings.TrimSpace(serveOTLPProtocol)),
		OTLPInsecure:                serveOTLPInsecure,
		OTLPServiceName:             strings.TrimSpace(serveOTLPServiceName),
		OTLPServiceVersion:          strings.TrimSpace(serveOTLPServiceVersion),
		OTLPTracesEnabled:           serveOTLPTracesEnabled,
		OTLPMetricsEnabled:          serveOTLPMetricsEnabled,
		OTLPLogsEnabled:             serveOTLPLogsEnabled,
		MetricsPort:                 serveMetricsPort,
		DPRDSN:                      serveDPRDSN,
		RedisURL:                    serveRedisURL,
		DeferBackend:                strings.ToLower(strings.TrimSpace(serveDeferBackend)),
		DeferRedisPrefix:            strings.TrimSpace(serveDeferRedisPrefix),
		RuntimeMode:                 core.RuntimeMode(strings.ToLower(strings.TrimSpace(serveRuntimeMode))),
		RequireGovernanceBootstrap:  serveRequireGovernanceBootstrap,
		DPRHMACKey:                  serveDPRHMACKey,
		TLSCertFile:                 serveTLSCert,
		TLSKeyFile:                  serveTLSKey,
		ClientCAFile:                serveClientCA,
		TLSAuto:                     resolveTLSAuto(),
		PagerDutyRoutingKey:         servePagerDutyRoutingKey,
		PolicyAdminToken:            resolvePolicyAdminToken(),
		StandingAdminToken:          resolveStandingAdminToken(),
		EnableEBPF:                  resolveServeEBPFEnabled(),
		EBPFObjectPath:              resolveServeEBPFObjectPath(),
		EBPFAttachTracepoints:       resolveServeEBPFAttachTracepoints(),
		SPIFFESocketPath:            strings.TrimSpace(serveSPIFFESocketPath),
		VaultAddr:                   resolveVaultAddr(),
		VaultToken:                  resolveVaultToken(),
		VaultMount:                  serveVaultMount,
		VaultNamespace:              serveVaultNamespace,
		AWSSecretsRegion:            serveAWSSecretsRegion,
		GCPSecretsProject:           serveGCPSecretsProject,
		AzureKeyVaultURL:            serveAzureKeyVaultURL,
		AzureTenantID:               serveAzureTenantID,
		AzureClientID:               serveAzureClientID,
		AzureClientSecret:           serveAzureClientSecret,
		StrictPreflight:             strictPreflight,
		IDPProvider:                 resolveIDPProvider(),
		IntegrityManifestPath:       resolveIntegrityManifestPath(),
		IntegrityBaseDir:            resolveIntegrityBaseDir(),
		BuildInfoExpectedPath:       resolveBuildinfoExpectedPath(),
		AllowEnvCredentialFallback:  serveAllowEnvCredFallback,
	}

	if serveSyncHorizon {
		tok, err := cloud.LoadToken()
		if err != nil {
			return fmt.Errorf("read Horizon credentials: %w\nRun: faramesh auth login", err)
		}
		if tok == nil {
			return fmt.Errorf("not authenticated with Horizon\nRun: faramesh auth login")
		}
		if tok.IsExpired() {
			return fmt.Errorf("Horizon token expired\nRun: faramesh auth login")
		}
		cfg.HorizonToken = tok.Token
		cfg.HorizonURL = tok.HorizonURL
		cfg.HorizonOrgID = tok.OrgID
		log.Info("horizon sync enabled",
			zap.String("org", tok.OrgName),
			zap.String("user", tok.UserEmail),
			zap.String("url", tok.HorizonURL),
		)
	}

	d, err := daemon.New(cfg)
	if err != nil {
		return fmt.Errorf("init daemon: %w", err)
	}

	return d.Run(context.Background())
}

func runServeOnboardPreflight() error {
	if strings.TrimSpace(servePolicyURL) != "" {
		fmt.Fprintln(os.Stderr, "strict preflight: skipping local onboard policy compile check for --policy-url source")
		return nil
	}

	prevPolicyPath := onboardPolicyPath
	prevStrict := onboardStrict
	prevJSON := onboardJSON
	prevSlack := onboardSlackWebhook
	prevPagerDuty := onboardPagerDutyRoutingKey
	prevIDP := onboardIDPProvider
	prevSPIFFE := onboardSPIFFESocket
	prevSPIFFEID := onboardSPIFFEID
	prevVault := onboardVaultAddr
	prevAWS := onboardAWSRegion
	prevGCP := onboardGCPProject
	prevAzure := onboardAzureVaultURL
	prevInteractive := onboardInteractive
	prevCredentialProfile := onboardCredentialProfile
	prevCredentialBackend := onboardCredentialBackend
	prevAllowEnvFallbackRaw, prevAllowEnvFallbackSet := os.LookupEnv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK")
	prevSPIFFEIDRaw, prevSPIFFEIDSet := os.LookupEnv("FARAMESH_SPIFFE_ID")
	defer func() {
		onboardPolicyPath = prevPolicyPath
		onboardStrict = prevStrict
		onboardJSON = prevJSON
		onboardSlackWebhook = prevSlack
		onboardPagerDutyRoutingKey = prevPagerDuty
		onboardIDPProvider = prevIDP
		onboardSPIFFESocket = prevSPIFFE
		onboardSPIFFEID = prevSPIFFEID
		onboardVaultAddr = prevVault
		onboardAWSRegion = prevAWS
		onboardGCPProject = prevGCP
		onboardAzureVaultURL = prevAzure
		onboardInteractive = prevInteractive
		onboardCredentialProfile = prevCredentialProfile
		onboardCredentialBackend = prevCredentialBackend
		if prevAllowEnvFallbackSet {
			_ = os.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", prevAllowEnvFallbackRaw)
		} else {
			_ = os.Unsetenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK")
		}
		if prevSPIFFEIDSet {
			_ = os.Setenv("FARAMESH_SPIFFE_ID", prevSPIFFEIDRaw)
		} else {
			_ = os.Unsetenv("FARAMESH_SPIFFE_ID")
		}
	}()

	onboardPolicyPath = strings.TrimSpace(servePolicy)
	onboardStrict = true
	onboardJSON = false
	onboardSlackWebhook = strings.TrimSpace(serveSlack)
	onboardPagerDutyRoutingKey = strings.TrimSpace(servePagerDutyRoutingKey)
	onboardIDPProvider = resolveIDPProvider()
	onboardSPIFFESocket = strings.TrimSpace(serveSPIFFESocketPath)
	onboardSPIFFEID = resolveSPIFFEID()
	onboardVaultAddr = resolveVaultAddr()
	onboardAWSRegion = strings.TrimSpace(serveAWSSecretsRegion)
	onboardGCPProject = strings.TrimSpace(serveGCPSecretsProject)
	onboardAzureVaultURL = strings.TrimSpace(serveAzureKeyVaultURL)
	onboardInteractive = false
	onboardCredentialProfile = "production"
	onboardCredentialBackend = "auto"
	if onboardSPIFFEID != "" {
		_ = os.Setenv("FARAMESH_SPIFFE_ID", onboardSPIFFEID)
	}
	if serveAllowEnvCredFallback {
		_ = os.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "true")
	}

	return runOnboard(nil, nil)
}

func resolveServeEBPFEnabled() bool {
	if serveEnableEBPF {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("FARAMESH_ENABLE_EBPF")), "true")
}

func resolveServeEBPFObjectPath() string {
	if strings.TrimSpace(serveEBPFObjectPath) != "" {
		return strings.TrimSpace(serveEBPFObjectPath)
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_EBPF_OBJECT"))
}

func resolveServeEBPFAttachTracepoints() bool {
	if serveEBPFAttachTP {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("FARAMESH_EBPF_ATTACH_TRACEPOINTS")), "true")
}

func resolvePolicyAdminToken() string {
	if strings.TrimSpace(servePolicyAdminToken) != "" {
		return strings.TrimSpace(servePolicyAdminToken)
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_POLICY_ADMIN_TOKEN"))
}

// resolveStandingAdminToken authenticates standing_grant_add|revoke|list.
// Order: --standing-admin-token, FARAMESH_STANDING_ADMIN_TOKEN, then policy admin token.
func resolveStandingAdminToken() string {
	if strings.TrimSpace(serveStandingAdminToken) != "" {
		return strings.TrimSpace(serveStandingAdminToken)
	}
	if v := strings.TrimSpace(os.Getenv("FARAMESH_STANDING_ADMIN_TOKEN")); v != "" {
		return v
	}
	return resolvePolicyAdminToken()
}

func resolveMCPEdgeAuthBearerToken() string {
	if strings.TrimSpace(serveMCPEdgeAuthBearerToken) != "" {
		return strings.TrimSpace(serveMCPEdgeAuthBearerToken)
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_MCP_EDGE_AUTH_BEARER_TOKEN"))
}

func resolveVaultAddr() string {
	if strings.TrimSpace(serveVaultAddr) != "" {
		return strings.TrimSpace(serveVaultAddr)
	}
	return strings.TrimSpace(os.Getenv("VAULT_ADDR"))
}

func resolveVaultToken() string {
	if strings.TrimSpace(serveVaultToken) != "" {
		return strings.TrimSpace(serveVaultToken)
	}
	return strings.TrimSpace(os.Getenv("VAULT_TOKEN"))
}

func resolveStrictPreflight() bool {
	if serveStrictPreflight {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("FARAMESH_STRICT_PREFLIGHT")), "true")
}

func resolveIDPProvider() string {
	if strings.TrimSpace(serveIDPProvider) != "" {
		return strings.ToLower(strings.TrimSpace(serveIDPProvider))
	}
	if env := strings.ToLower(strings.TrimSpace(os.Getenv("FARAMESH_IDP_PROVIDER"))); env != "" {
		return env
	}
	return "default"
}

func resolveSPIFFEID() string {
	if strings.TrimSpace(serveSPIFFEID) != "" {
		return strings.TrimSpace(serveSPIFFEID)
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_SPIFFE_ID"))
}

func resolveTLSAuto() bool {
	if serveTLSAuto {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("FARAMESH_TLS_AUTO")), "true")
}

func resolveIntegrityManifestPath() string {
	if strings.TrimSpace(serveIntegrityManifest) != "" {
		return strings.TrimSpace(serveIntegrityManifest)
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_INTEGRITY_MANIFEST"))
}

func resolveIntegrityBaseDir() string {
	if strings.TrimSpace(serveIntegrityBaseDir) != "" {
		return strings.TrimSpace(serveIntegrityBaseDir)
	}
	if env := strings.TrimSpace(os.Getenv("FARAMESH_INTEGRITY_BASE_DIR")); env != "" {
		return env
	}
	return "."
}

func resolveBuildinfoExpectedPath() string {
	if strings.TrimSpace(serveBuildinfoExpected) != "" {
		return strings.TrimSpace(serveBuildinfoExpected)
	}
	return strings.TrimSpace(os.Getenv("FARAMESH_BUILDINFO_EXPECTED"))
}

func splitCSVList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	switch level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	return cfg.Build()
}
