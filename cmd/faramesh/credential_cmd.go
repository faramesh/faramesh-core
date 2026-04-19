package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/policy"
)

func credentialSocketRequestWithHTTPFallback(op string, payload map[string]any, httpMethod, httpPath string) (json.RawMessage, error) {
	req := map[string]any{"type": "credential", "op": op}
	for k, v := range payload {
		req[k] = v
	}
	resp, err := daemonSocketRequest(req)
	if err == nil {
		return resp, nil
	}
	if !daemonHTTPFallback {
		return nil, err
	}
	if httpMethod == "GET" {
		return daemonGet(httpPath)
	}
	return daemonPost(httpPath, payload)
}

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage credential sequestration for governed runs",
	Long: `Set up and verify Faramesh credential sequestration for governed execution.

Default path:
  faramesh credential enable --policy <policy> --import-env
  faramesh credential status`,
}

// ── credential register ─────────────────────────────────────────────────────

var (
	credRegisterKey      string
	credRegisterScope    string
	credRegisterMaxScope string
)

var credentialRegisterCmd = &cobra.Command{
	Use:   "register <name>",
	Short: "Register a new credential with the broker",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		if cmd.Flags().Changed("key") {
			body["key"] = credRegisterKey
		}
		if cmd.Flags().Changed("scope") {
			body["scope"] = credRegisterScope
		}
		if cmd.Flags().Changed("max-scope") {
			body["max_scope"] = credRegisterMaxScope
		}
		data, err := credentialSocketRequestWithHTTPFallback("register", body, "POST", "/api/v1/credential/register")
		if err != nil {
			return err
		}
		printHeader("Credential Registered")
		printJSON(data)
		return nil
	},
}

// ── credential list ─────────────────────────────────────────────────────────

var credentialListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered credentials",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := credentialSocketRequestWithHTTPFallback("list", map[string]any{}, "GET", "/api/v1/credential/list")
		if err != nil {
			return err
		}
		printHeader("Credentials")
		printJSON(data)
		return nil
	},
}

// ── credential inspect ──────────────────────────────────────────────────────

var credentialInspectCmd = &cobra.Command{
	Use:   "inspect <name>",
	Short: "Inspect a credential's metadata and usage",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		httpPath := "/api/v1/credential/inspect/" + url.PathEscape(args[0])
		data, err := credentialSocketRequestWithHTTPFallback("inspect", map[string]any{"name": args[0]}, "GET", httpPath)
		if err != nil {
			return err
		}
		printHeader("Credential Details")
		printJSON(data)
		return nil
	},
}

// ── credential rotate ───────────────────────────────────────────────────────

var credRotateKey string

var credentialRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Rotate a credential's key material",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		if cmd.Flags().Changed("key") {
			body["key"] = credRotateKey
		}
		data, err := credentialSocketRequestWithHTTPFallback("rotate", body, "POST", "/api/v1/credential/rotate")
		if err != nil {
			return err
		}
		printHeader("Credential Rotated")
		printJSON(data)
		return nil
	},
}

// ── credential health ───────────────────────────────────────────────────────

var credentialHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check health of all credential backends",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := credentialSocketRequestWithHTTPFallback("health", map[string]any{}, "GET", "/api/v1/credential/health")
		if err != nil {
			return err
		}
		printHeader("Credential Backend Health")
		printJSON(data)
		return nil
	},
}

var credentialStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show credential readiness for governed runs",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		profile, err := loadRuntimeProfile()
		if err != nil {
			return err
		}

		health := map[string]any{}
		routing := map[string]any{}
		connectivityErr := ""

		healthRaw, err := credentialSocketRequestWithHTTPFallback("health", map[string]any{}, "GET", "/api/v1/credential/health")
		if err != nil {
			connectivityErr = strings.TrimSpace(err.Error())
		} else if err := json.Unmarshal(healthRaw, &health); err != nil {
			connectivityErr = strings.TrimSpace(err.Error())
		}

		routingRaw, routingErr := credentialSocketRequestWithHTTPFallback("routing_map", map[string]any{}, "GET", "/api/v1/credential/map")
		if routingErr != nil {
			if connectivityErr == "" {
				connectivityErr = strings.TrimSpace(routingErr.Error())
			}
		} else if err := json.Unmarshal(routingRaw, &routing); err != nil {
			if connectivityErr == "" {
				connectivityErr = strings.TrimSpace(err.Error())
			}
		}

		state, hasState := readCurrentRuntimeStartState()
		runtimeRunning := hasState && state.DaemonPID > 0 && socketStatusOK(state.SocketPath)

		healthy := boolValue(health["healthy"])
		routerConfigured := boolValue(routing["router_configured"])
		brokeredToolCount := 0
		if tools, ok := routing["tools"].([]any); ok {
			brokeredToolCount = len(tools)
		}

		backendNames := make([]string, 0)
		if backends, ok := health["backends"].(map[string]any); ok {
			for name := range backends {
				backendNames = append(backendNames, name)
			}
			sort.Strings(backendNames)
		}

		profileConfigured := profile.Credential != nil && profile.Credential.Enabled
		profileBackend := "not configured"
		if profileConfigured {
			profileBackend = firstNonEmpty(strings.TrimSpace(profile.Credential.Backend), "local-vault")
		}

		ready := runtimeRunning && healthy && routerConfigured && profileConfigured
		out := map[string]any{
			"ready": ready,
			"runtime": map[string]any{
				"running": runtimeRunning,
				"socket":  strings.TrimSpace(state.SocketPath),
			},
			"profile": map[string]any{
				"configured": profileConfigured,
				"backend":    profileBackend,
				"path":       runtimeProfilePath(),
			},
			"credential_sequestration": map[string]any{
				"healthy":             healthy,
				"router_configured":   routerConfigured,
				"brokered_tool_count": brokeredToolCount,
				"backends":            backendNames,
			},
			"connectivity_error": connectivityErr,
			"next_steps": []string{
				"faramesh credential enable --policy <policy> --import-env",
				"faramesh up --policy <policy>",
				"faramesh run --broker -- <agent-command>",
			},
		}

		if credStatusJSON {
			data, _ := json.Marshal(out)
			printResponse("Credential Sequestration Status", data)
			return nil
		}

		printCredentialStatusSummary(out, credStatusDetails)
		return nil
	},
}

var (
	credStatusJSON           bool
	credStatusDetails        bool
	credEnableBackend        string
	credEnablePolicyPath     string
	credEnableProviderKeys   []string
	credEnableImportEnv      bool
	credEnableVaultAddr      string
	credEnableVaultToken     string
	credEnableVaultMount     string
	credEnableVaultNamespace string
	credEnableVaultStateDir  string
	credEnableApplyRuntime   bool
	credEnableRestartRuntime bool
)

type credentialBrokerMapTool struct {
	ToolID        string `json:"tool_id"`
	Scope         string `json:"scope"`
	BrokerEnabled bool   `json:"broker_enabled"`
}

type credentialBrokerMapSnapshot struct {
	RouterConfigured bool                      `json:"router_configured"`
	Tools            []credentialBrokerMapTool `json:"tools"`
}

var credentialEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable global credential sequestration defaults",
	Long: `Configure the default credential sequestration profile used by governed runs
and import provider credentials from environment.

Normal path:
  faramesh credential enable --policy <policy> --import-env

This removes most manual shell credential choreography from the normal flow.`,
	Args: cobra.NoArgs,
	RunE: runCredentialEnable,
}

var credentialProfileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Show persisted credential sequestration profile",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		profile, err := loadRuntimeProfile()
		if err != nil {
			return err
		}
		if profile.Credential == nil {
			printNoteLine("no credential sequestration profile found")
			printNextStepLine("run: faramesh credential enable --policy <policy> --import-env")
			return nil
		}

		data, _ := json.Marshal(profile)
		printHeader("Credential Profile")
		printJSON(data)
		return nil
	},
}

// ── credential map ──────────────────────────────────────────────────────────

var credentialMapCmd = &cobra.Command{
	Use:   "map",
	Short: "Show policy-to-broker routing map",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		data, err := credentialSocketRequestWithHTTPFallback("routing_map", map[string]any{}, "GET", "/api/v1/credential/map")
		if err != nil {
			return err
		}
		printHeader("Credential Broker Routing")
		printJSON(data)
		return nil
	},
}

// ── credential revoke ───────────────────────────────────────────────────────

var credentialRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke a credential and invalidate active leases",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		body := map[string]any{"name": args[0]}
		data, err := credentialSocketRequestWithHTTPFallback("revoke", body, "POST", "/api/v1/credential/revoke")
		if err != nil {
			return err
		}
		printHeader("Credential Revoked")
		printJSON(data)
		return nil
	},
}

// ── credential audit ────────────────────────────────────────────────────────

var credAuditWindow string

var credentialAuditCmd = &cobra.Command{
	Use:   "audit <name>",
	Short: "View audit log for a credential",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "/api/v1/credential/audit/" + url.PathEscape(args[0])
		payload := map[string]any{"name": args[0]}
		if cmd.Flags().Changed("window") {
			payload["window"] = credAuditWindow
			path += "?" + url.Values{"window": {credAuditWindow}}.Encode()
		}
		data, err := credentialSocketRequestWithHTTPFallback("audit", payload, "GET", path)
		if err != nil {
			return err
		}
		printHeader("Credential Audit Log")
		printJSON(data)
		return nil
	},
}

func runCredentialEnable(_ *cobra.Command, _ []string) error {
	backend := strings.ToLower(strings.TrimSpace(credEnableBackend))
	if backend == "" {
		backend = "local-vault"
	}
	switch backend {
	case "local-vault", "vault", "env":
	default:
		return fmt.Errorf("unsupported --backend %q (expected local-vault, vault, or env)", backend)
	}

	policyPath := resolveCredentialEnablePolicyPath(credEnablePolicyPath)
	providerSecrets, err := resolveCredentialProviderSecrets(credEnableProviderKeys, credEnableImportEnv)
	if err != nil {
		return err
	}

	profile, err := loadRuntimeProfile()
	if err != nil {
		return err
	}

	credentialProfile := &runtimeCredentialProfile{
		Enabled:          true,
		Backend:          backend,
		AllowEnvFallback: false,
	}

	switch backend {
	case "local-vault":
		addr := firstNonEmpty(strings.TrimSpace(credEnableVaultAddr), defaultLocalVaultAddr)
		token := firstNonEmpty(strings.TrimSpace(credEnableVaultToken), defaultLocalVaultToken)
		mount := firstNonEmpty(strings.TrimSpace(credEnableVaultMount), defaultVaultMount)

		state, err := resolveVaultStatePaths(credEnableVaultStateDir)
		if err != nil {
			return err
		}

		started, err := ensureLocalVaultRunning(addr, token, state)
		if err != nil {
			return err
		}
		if err := writeLocalVaultEnv(state, addr, token, mount); err != nil {
			return err
		}

		credentialProfile.VaultAddr = addr
		credentialProfile.VaultToken = token
		credentialProfile.VaultMount = mount

		if started {
			printSuccessLine("local credential vault provisioned")
		} else {
			printNoteLine("local credential vault already running")
		}

		tools, source, err := collectCredentialEnableTools(policyPath)
		if err != nil {
			printWarningLine(fmt.Sprintf("tool discovery unavailable: %v", err))
		} else {
			printNoteLine(fmt.Sprintf("discovered %d brokered tool targets from %s", len(tools), source))
			seeded, missingProviders, seedErr := seedVaultSecretsForTools(addr, token, strings.TrimSpace(credEnableVaultNamespace), mount, tools, providerSecrets)
			if seedErr != nil {
				return seedErr
			}
			if seeded > 0 {
				printSuccessLine(fmt.Sprintf("seeded %d brokered tool secrets in vault", seeded))
			} else {
				printWarningLine("no brokered secrets were seeded; discovered tools did not match imported providers")
			}
			if len(missingProviders) > 0 {
				printWarningLine("missing provider secrets for: " + strings.Join(missingProviders, ", "))
				printTipLine("export provider credentials (for example OPENAI_API_KEY, STRIPE_SECRET_KEY) and rerun with --import-env")
			}
		}

	case "vault":
		addr := strings.TrimSpace(credEnableVaultAddr)
		token := strings.TrimSpace(credEnableVaultToken)
		if addr == "" || token == "" {
			return fmt.Errorf("--backend vault requires --vault-addr and --vault-token")
		}
		mount := firstNonEmpty(strings.TrimSpace(credEnableVaultMount), defaultVaultMount)
		credentialProfile.VaultAddr = addr
		credentialProfile.VaultToken = token
		credentialProfile.VaultMount = mount
		printSuccessLine("configured external Vault credential profile")

	case "env":
		printWarningLine("environment fallback enabled; credentials remain ambient in process environment")
		credentialProfile.AllowEnvFallback = true
	}

	profile.Credential = credentialProfile
	if err := saveRuntimeProfile(profile); err != nil {
		return err
	}

	printSuccessLine("saved credential profile for runtime lifecycle commands")
	printNoteLine("profile saved at: " + runtimeProfilePath())

	if credEnableApplyRuntime {
		if err := applyCredentialProfileRuntime(policyPath, credEnableRestartRuntime); err != nil {
			return err
		}
	}

	printReadyLine("credential sequestration defaults are active")
	printNextStepLine("review readiness: faramesh credential status")
	printNextStepLine("run governed command: faramesh run --broker -- <agent-command>")
	printNextStepLine("open approval queue: faramesh approvals")
	return nil
}

func resolveCredentialEnablePolicyPath(raw string) string {
	explicit := strings.TrimSpace(raw)
	if explicit != "" {
		if abs, err := filepath.Abs(explicit); err == nil {
			return abs
		}
		return explicit
	}

	if state, ok := readCurrentRuntimeStartState(); ok {
		if policyPath := strings.TrimSpace(state.PolicyPath); policyPath != "" {
			return policyPath
		}
	}

	return detectDefaultPolicyPath()
}

func resolveCredentialProviderSecrets(providerKeys []string, importEnv bool) (map[string]string, error) {
	providers := map[string]string{}
	for _, entry := range providerKeys {
		raw := strings.TrimSpace(entry)
		if raw == "" {
			continue
		}
		parts := strings.SplitN(raw, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --provider-key %q (expected provider=value)", raw)
		}
		provider := normalizeCredentialProvider(parts[0])
		secret := strings.TrimSpace(parts[1])
		if provider == "" {
			return nil, fmt.Errorf("invalid provider name in --provider-key %q", raw)
		}
		if secret == "" {
			continue
		}
		providers[provider] = secret
	}

	if importEnv {
		mergeProviderEnvSecret(providers, "stripe", "STRIPE_SECRET_KEY")
		mergeProviderEnvSecret(providers, "openrouter", "OPENROUTER_API_KEY")
		mergeProviderEnvSecret(providers, "openai", "OPENAI_API_KEY")
		mergeProviderEnvSecret(providers, "anthropic", "ANTHROPIC_API_KEY")
		mergeProviderEnvSecret(providers, "github", "GITHUB_TOKEN")
	}

	return providers, nil
}

func mergeProviderEnvSecret(target map[string]string, provider, envKey string) {
	if _, exists := target[provider]; exists {
		return
	}
	if secret := strings.TrimSpace(os.Getenv(envKey)); secret != "" {
		target[provider] = secret
	}
}

func normalizeCredentialProvider(raw string) string {
	provider := strings.ToLower(strings.TrimSpace(raw))
	provider = strings.TrimPrefix(provider, "provider:")
	provider = strings.ReplaceAll(provider, "-", "_")
	provider = strings.ReplaceAll(provider, " ", "_")
	provider = strings.ReplaceAll(provider, "/", "_")
	return provider
}

func collectCredentialEnableTools(policyPath string) ([]credentialBrokerMapTool, string, error) {
	if raw, err := credentialSocketRequestWithHTTPFallback("routing_map", map[string]any{}, "GET", "/api/v1/credential/map"); err == nil {
		var snapshot credentialBrokerMapSnapshot
		if decodeErr := json.Unmarshal(raw, &snapshot); decodeErr == nil {
			tools := make([]credentialBrokerMapTool, 0, len(snapshot.Tools))
			for _, tool := range snapshot.Tools {
				if !tool.BrokerEnabled {
					continue
				}
				if normalized, ok := normalizePolicyToolID(tool.ToolID); ok {
					tools = append(tools, credentialBrokerMapTool{ToolID: normalized, Scope: tool.Scope, BrokerEnabled: true})
				}
			}
			if len(tools) > 0 {
				return dedupeCredentialTools(tools), "runtime routing map", nil
			}
		}
	}

	if strings.TrimSpace(policyPath) == "" {
		return nil, "", fmt.Errorf("policy path unavailable")
	}

	doc, _, err := policy.LoadFile(policyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load policy for tool discovery: %w", err)
	}

	tools := make([]credentialBrokerMapTool, 0, len(doc.Tools)+len(doc.Rules))
	for toolID := range doc.Tools {
		if normalized, ok := normalizePolicyToolID(toolID); ok {
			tools = append(tools, credentialBrokerMapTool{ToolID: normalized, BrokerEnabled: true})
		}
	}
	for _, rule := range doc.Rules {
		if normalized, ok := normalizePolicyToolID(rule.Match.Tool); ok {
			tools = append(tools, credentialBrokerMapTool{ToolID: normalized, BrokerEnabled: true})
		}
	}

	tools = dedupeCredentialTools(tools)
	if len(tools) == 0 {
		return nil, "", fmt.Errorf("no tool IDs discovered in policy")
	}
	return tools, "policy document", nil
}

func normalizePolicyToolID(raw string) (string, bool) {
	toolID := strings.TrimSpace(raw)
	if toolID == "" || toolID == "*" {
		return "", false
	}
	toolID = strings.TrimSuffix(toolID, "/*")
	toolID = strings.TrimSuffix(toolID, "*")
	toolID = strings.Trim(toolID, "/")
	if toolID == "" || strings.Contains(toolID, "*") || strings.Contains(toolID, " ") {
		return "", false
	}
	return toolID, true
}

func dedupeCredentialTools(in []credentialBrokerMapTool) []credentialBrokerMapTool {
	uniq := map[string]credentialBrokerMapTool{}
	for _, item := range in {
		if strings.TrimSpace(item.ToolID) == "" {
			continue
		}
		if existing, ok := uniq[item.ToolID]; ok {
			if strings.TrimSpace(existing.Scope) == "" && strings.TrimSpace(item.Scope) != "" {
				uniq[item.ToolID] = item
			}
			continue
		}
		uniq[item.ToolID] = item
	}
	out := make([]credentialBrokerMapTool, 0, len(uniq))
	for _, item := range uniq {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ToolID < out[j].ToolID })
	return out
}

func inferCredentialProvider(toolID, scope string) string {
	if normalizedScope := normalizeCredentialProvider(scope); normalizedScope != "" {
		if idx := strings.Index(normalizedScope, ":"); idx > 0 {
			normalizedScope = normalizedScope[:idx]
		}
		return normalizedScope
	}

	normalizedTool := strings.ToLower(strings.TrimSpace(toolID))
	if strings.Contains(normalizedTool, "openrouter") || strings.Contains(normalizedTool, "web_request") {
		return "openrouter"
	}
	if strings.Contains(normalizedTool, "stripe") {
		return "stripe"
	}
	if strings.Contains(normalizedTool, "anthropic") {
		return "anthropic"
	}
	if strings.Contains(normalizedTool, "openai") {
		return "openai"
	}

	for _, sep := range []string{"/", "_", "-"} {
		if idx := strings.Index(normalizedTool, sep); idx > 0 {
			return normalizeCredentialProvider(normalizedTool[:idx])
		}
	}
	return normalizeCredentialProvider(normalizedTool)
}

func seedVaultSecretsForTools(addr, token, namespace, mount string, tools []credentialBrokerMapTool, providerSecrets map[string]string) (int, []string, error) {
	if len(tools) == 0 {
		return 0, nil, nil
	}

	missing := map[string]struct{}{}
	seeded := 0
	for _, tool := range tools {
		provider := inferCredentialProvider(tool.ToolID, tool.Scope)
		if provider == "" {
			continue
		}
		secret := strings.TrimSpace(providerSecrets[provider])
		if secret == "" {
			missing[provider] = struct{}{}
			continue
		}
		if err := putVaultSecret(addr, token, namespace, mount, tool.ToolID, "value", secret); err != nil {
			return seeded, nil, fmt.Errorf("seed vault secret for %s: %w", tool.ToolID, err)
		}
		seeded++
	}

	missingProviders := make([]string, 0, len(missing))
	for provider := range missing {
		missingProviders = append(missingProviders, provider)
	}
	sort.Strings(missingProviders)
	return seeded, missingProviders, nil
}

func applyCredentialProfileRuntime(policyPath string, restart bool) error {
	state, hasState := readCurrentRuntimeStartState()
	running := hasState && state.DaemonPID > 0 && socketStatusOK(state.SocketPath)

	if running && !restart {
		printWarningLine("runtime is already running; restart was skipped")
		printNextStepLine("restart when convenient: faramesh down && faramesh up")
		return nil
	}

	if running && restart {
		printNoteLine("restarting runtime to apply credential profile")
		if err := runFaramesh("down"); err != nil {
			return err
		}
	}

	args := []string{"up"}
	if strings.TrimSpace(policyPath) != "" {
		args = append(args, "--policy", policyPath)
	}
	if err := runFaramesh(args...); err != nil {
		return err
	}
	return nil
}

func init() {
	rootCmd.AddCommand(credentialCmd)

	credentialRegisterCmd.Flags().StringVar(&credRegisterKey, "key", "", "credential key or secret value")
	credentialRegisterCmd.Flags().StringVar(&credRegisterScope, "scope", "", "allowed scope for this credential")
	credentialRegisterCmd.Flags().StringVar(&credRegisterMaxScope, "max-scope", "", "maximum scope ceiling")

	credentialRotateCmd.Flags().StringVar(&credRotateKey, "key", "", "new key material")

	credentialAuditCmd.Flags().StringVar(&credAuditWindow, "window", "", "audit time window (e.g. 24h, 7d)")
	credentialStatusCmd.Flags().BoolVar(&credStatusJSON, "json", false, "output raw JSON status payload")
	credentialStatusCmd.Flags().BoolVar(&credStatusDetails, "details", false, "show detailed backend and routing diagnostics")

	credentialEnableCmd.Flags().StringVar(&credEnableBackend, "backend", "local-vault", "default credential backend: local-vault|vault|env")
	credentialEnableCmd.Flags().StringVar(&credEnablePolicyPath, "policy", "", "policy path used to discover brokered tool targets")
	credentialEnableCmd.Flags().StringArrayVar(&credEnableProviderKeys, "provider-key", nil, "provider secret mapping in provider=value form (repeatable)")
	credentialEnableCmd.Flags().BoolVar(&credEnableImportEnv, "import-env", true, "import known provider credentials from environment when available")
	credentialEnableCmd.Flags().StringVar(&credEnableVaultAddr, "vault-addr", "", "vault address override for local-vault or vault backend")
	credentialEnableCmd.Flags().StringVar(&credEnableVaultToken, "vault-token", "", "vault token override for local-vault or vault backend")
	credentialEnableCmd.Flags().StringVar(&credEnableVaultMount, "vault-mount", defaultVaultMount, "vault mount used for brokered tool secret storage")
	credentialEnableCmd.Flags().StringVar(&credEnableVaultNamespace, "vault-namespace", "", "vault namespace for enterprise vault deployments")
	credentialEnableCmd.Flags().StringVar(&credEnableVaultStateDir, "state-dir", "", "state directory for local vault metadata")
	credentialEnableCmd.Flags().BoolVar(&credEnableApplyRuntime, "apply-runtime", true, "apply profile by ensuring runtime lifecycle picks up profile now")
	credentialEnableCmd.Flags().BoolVar(&credEnableRestartRuntime, "restart-runtime", true, "restart running runtime before applying credential profile")

	credentialCmd.AddCommand(credentialRegisterCmd)
	credentialCmd.AddCommand(credentialListCmd)
	credentialCmd.AddCommand(credentialInspectCmd)
	credentialCmd.AddCommand(credentialRotateCmd)
	credentialCmd.AddCommand(credentialEnableCmd)
	credentialCmd.AddCommand(credentialProfileCmd)
	credentialCmd.AddCommand(credentialStatusCmd)
	credentialCmd.AddCommand(credentialHealthCmd)
	credentialCmd.AddCommand(credentialMapCmd)
	credentialCmd.AddCommand(credentialRevokeCmd)
	credentialCmd.AddCommand(credentialAuditCmd)
	credentialCmd.AddCommand(credentialVaultCmd)

	// Hide low-level credential management mechanics from default UX.
	credentialRegisterCmd.Hidden = true
	credentialListCmd.Hidden = true
	credentialInspectCmd.Hidden = true
	credentialRotateCmd.Hidden = true
	credentialRevokeCmd.Hidden = true
	credentialAuditCmd.Hidden = true
	credentialHealthCmd.Hidden = true
	credentialMapCmd.Hidden = true

	// Keep advanced backend/routing knobs available without surfacing in default help.
	_ = credentialEnableCmd.Flags().MarkHidden("backend")
	_ = credentialEnableCmd.Flags().MarkHidden("provider-key")
	_ = credentialEnableCmd.Flags().MarkHidden("vault-addr")
	_ = credentialEnableCmd.Flags().MarkHidden("vault-token")
	_ = credentialEnableCmd.Flags().MarkHidden("vault-mount")
	_ = credentialEnableCmd.Flags().MarkHidden("vault-namespace")
	_ = credentialEnableCmd.Flags().MarkHidden("state-dir")
	_ = credentialEnableCmd.Flags().MarkHidden("apply-runtime")
	_ = credentialEnableCmd.Flags().MarkHidden("restart-runtime")
}

func printCredentialStatusSummary(out map[string]any, showDetails bool) {
	printHeader("Credential Sequestration Status")

	ready := boolValue(out["ready"])
	runtimeRunning := false
	runtimeSocket := ""
	if runtimeBlock, ok := out["runtime"].(map[string]any); ok {
		runtimeRunning = boolValue(runtimeBlock["running"])
		runtimeSocket = strings.TrimSpace(fmt.Sprint(runtimeBlock["socket"]))
	}

	profileConfigured := false
	profileBackend := "not configured"
	profilePath := ""
	if profileBlock, ok := out["profile"].(map[string]any); ok {
		profileConfigured = boolValue(profileBlock["configured"])
		profileBackend = firstNonEmpty(strings.TrimSpace(fmt.Sprint(profileBlock["backend"])), "not configured")
		profilePath = strings.TrimSpace(fmt.Sprint(profileBlock["path"]))
	}

	healthy := false
	routerConfigured := false
	brokeredToolCount := 0
	if secBlock, ok := out["credential_sequestration"].(map[string]any); ok {
		healthy = boolValue(secBlock["healthy"])
		routerConfigured = boolValue(secBlock["router_configured"])
		if v, ok := secBlock["brokered_tool_count"].(float64); ok {
			brokeredToolCount = int(v)
		}
	}

	if ready {
		printReadyLine("Credential sequestration is active for governed runs")
	} else {
		printWarningLine("Credential sequestration is not fully ready yet")
	}

	fmt.Printf("Runtime:        %s\n", ternary(runtimeRunning, "running", "not running"))
	fmt.Printf("Profile:        %s (backend: %s)\n", ternary(profileConfigured, "configured", "not configured"), profileBackend)
	fmt.Printf("Routing:        %s\n", ternary(routerConfigured, "configured", "not configured"))
	fmt.Printf("Health:         %s\n", ternary(healthy, "healthy", "degraded"))
	fmt.Printf("Tool coverage:  %d brokered target(s)\n", brokeredToolCount)
	if runtimeSocket != "" {
		fmt.Printf("Runtime socket: %s\n", runtimeSocket)
	}
	if profilePath != "" {
		fmt.Printf("Profile path:   %s\n", profilePath)
	}

	if connErr := strings.TrimSpace(fmt.Sprint(out["connectivity_error"])); connErr != "" {
		printWarningLine("runtime connectivity: " + connErr)
	}

	if showDetails {
		printHeader("Credential Status Details")
		data, _ := json.Marshal(out)
		printJSON(data)
	} else {
		printTipLine("Show detailed diagnostics: faramesh credential status --details")
		printTipLine("Show raw JSON: faramesh credential status --json")
	}

	printNextStepLine("Enable defaults: faramesh credential enable --policy <policy> --import-env")
	printNextStepLine("Run governed agent: faramesh run --broker -- <agent-command>")
}

func ternary(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}
