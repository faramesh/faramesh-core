package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	principalidp "github.com/faramesh/faramesh-core/internal/core/principal/idp"
	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
)

var onboardCmd = &cobra.Command{
	Use:   "onboard",
	Short: "Run onboarding readiness checks for core governance priorities",
	Long: `faramesh onboard validates the priority governance path before runtime:
- interception readiness
- auto-patching readiness
- action governance policy compilation
- HITL/defer backend readiness
- workload identity readiness
- credential sequestration readiness

Use this command as a preflight before faramesh serve --strict-preflight.`,
	Args: cobra.NoArgs,
	RunE: runOnboard,
}

var (
	onboardPolicyPath          string
	onboardStrict              bool
	onboardJSON                bool
	onboardSlackWebhook        string
	onboardPagerDutyRoutingKey string
	onboardIDPProvider         string
	onboardSPIFFESocket        string
	onboardVaultAddr           string
	onboardAWSRegion           string
	onboardGCPProject          string
	onboardAzureVaultURL       string
)

func init() {
	onboardCmd.Flags().StringVar(&onboardPolicyPath, "policy", "", "policy path (default probe order: faramesh/policy.yaml, policy.yaml, policies/default.fpl)")
	onboardCmd.Flags().BoolVar(&onboardStrict, "strict", true, "fail with non-zero exit if blocking checks fail")
	onboardCmd.Flags().BoolVar(&onboardJSON, "json", false, "emit machine-readable JSON report")
	onboardCmd.Flags().StringVar(&onboardSlackWebhook, "slack-webhook", "", "Slack webhook URL for HITL routing checks")
	onboardCmd.Flags().StringVar(&onboardPagerDutyRoutingKey, "pagerduty-routing-key", "", "PagerDuty routing key for HITL routing checks")
	onboardCmd.Flags().StringVar(&onboardIDPProvider, "idp-provider", "", "IdP provider for principal-aware policy checks (default|local|okta|azure_ad|auth0|google|ldap)")
	onboardCmd.Flags().StringVar(&onboardSPIFFESocket, "spiffe-socket", "", "SPIFFE Workload API socket path for workload identity checks")
	onboardCmd.Flags().StringVar(&onboardVaultAddr, "vault-addr", "", "Vault address for credential sequestration checks")
	onboardCmd.Flags().StringVar(&onboardAWSRegion, "aws-secrets-region", "", "AWS Secrets Manager region for credential sequestration checks")
	onboardCmd.Flags().StringVar(&onboardGCPProject, "gcp-secrets-project", "", "GCP project for Secret Manager credential checks")
	onboardCmd.Flags().StringVar(&onboardAzureVaultURL, "azure-vault-url", "", "Azure Key Vault URL for credential sequestration checks")
}

type onboardStatus string

const (
	onboardStatusPass onboardStatus = "pass"
	onboardStatusWarn onboardStatus = "warn"
	onboardStatusFail onboardStatus = "fail"
)

type onboardCheck struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Status      onboardStatus `json:"status"`
	Details     string        `json:"details"`
	Remediation string        `json:"remediation,omitempty"`
}

type onboardCredentialConfig struct {
	VaultAddr       string
	AWSRegion       string
	GCPProject      string
	AzureVaultURL   string
	OnePasswordHost string
	OnePasswordTok  string
	InfisicalHost   string
	InfisicalTok    string
}

type onboardReport struct {
	Strict     bool                            `json:"strict"`
	Ready      bool                            `json:"ready"`
	PolicyPath string                          `json:"policy_path,omitempty"`
	Runtime    *runtimeenv.DetectedEnvironment `json:"runtime"`
	Checks     []onboardCheck                  `json:"checks"`
}

func runOnboard(_ *cobra.Command, _ []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getwd: %w", err)
	}
	detected := runtimeenv.DetectEnvironment(cwd)

	checks := make([]onboardCheck, 0, 8)
	checks = append(checks, evaluateInterceptionReadiness(detected))
	checks = append(checks, evaluatePatchingReadiness(detected))

	policyPath, resolveErr := resolveOnboardPolicyPath(onboardPolicyPath, cwd)
	var (
		doc     *policy.Doc
		version string
	)
	if resolveErr != nil {
		checks = append(checks, onboardCheck{
			ID:          "policy_compilation",
			Title:       "Policy/FPL compilation",
			Status:      onboardStatusFail,
			Details:     resolveErr.Error(),
			Remediation: "Create a policy file or pass --policy to faramesh onboard.",
		})
		checks = append(checks, onboardCheck{
			ID:          "action_governance",
			Title:       "Action governance",
			Status:      onboardStatusFail,
			Details:     "Policy is unavailable, so no governance rules can be enforced.",
			Remediation: "Provide a valid policy file and rerun onboarding.",
		})
	} else {
		doc, version, err = policy.LoadFile(policyPath)
		if err != nil {
			checks = append(checks, onboardCheck{
				ID:          "policy_compilation",
				Title:       "Policy/FPL compilation",
				Status:      onboardStatusFail,
				Details:     fmt.Sprintf("Failed to load policy: %v", err),
				Remediation: "Fix parse/format errors in the policy file.",
			})
			checks = append(checks, onboardCheck{
				ID:          "action_governance",
				Title:       "Action governance",
				Status:      onboardStatusFail,
				Details:     "Policy failed to load, so action governance cannot execute.",
				Remediation: "Fix policy load errors and rerun onboarding.",
			})
		} else {
			diagnostics := policy.Validate(doc)
			hardErrs := policy.ValidationErrorsOnly(diagnostics)
			summary := fmt.Sprintf("Loaded %s with %d rule(s), version=%s", policyPath, len(doc.Rules), version)
			if len(hardErrs) > 0 {
				checks = append(checks, onboardCheck{
					ID:          "policy_compilation",
					Title:       "Policy/FPL compilation",
					Status:      onboardStatusFail,
					Details:     "Validation errors: " + strings.Join(hardErrs, "; "),
					Remediation: "Resolve policy validation errors before runtime.",
				})
			} else if _, err := policy.NewEngine(doc, version); err != nil {
				checks = append(checks, onboardCheck{
					ID:          "policy_compilation",
					Title:       "Policy/FPL compilation",
					Status:      onboardStatusFail,
					Details:     fmt.Sprintf("Compilation failed: %v", err),
					Remediation: "Fix invalid rule expressions and compile again.",
				})
			} else {
				checks = append(checks, onboardCheck{
					ID:      "policy_compilation",
					Title:   "Policy/FPL compilation",
					Status:  onboardStatusPass,
					Details: summary,
				})
			}

			if len(doc.Rules) == 0 {
				checks = append(checks, onboardCheck{
					ID:          "action_governance",
					Title:       "Action governance",
					Status:      onboardStatusFail,
					Details:     "Policy has zero rules; action governance is not configured.",
					Remediation: "Add permit/deny/defer rules to policy rules: and rerun onboarding.",
				})
			} else {
				checks = append(checks, onboardCheck{
					ID:      "action_governance",
					Title:   "Action governance",
					Status:  onboardStatusPass,
					Details: fmt.Sprintf("Action governance active with %d rule(s); default_effect=%s", len(doc.Rules), doc.DefaultEffect),
				})
			}
		}
	}

	checks = append(checks, evaluateHITLReadiness(doc, onboardSlackWebhook, onboardPagerDutyRoutingKey))
	checks = append(checks, evaluateIdentityReadiness(onboardStrict, onboardSPIFFESocket))
	checks = append(checks, evaluateIDPReadiness(doc, onboardStrict, onboardIDPProvider))
	checks = append(checks, evaluateCredentialSequestrationReadiness(doc, onboardStrict, resolveOnboardCredentialConfig()))

	report := onboardReport{
		Strict:     onboardStrict,
		PolicyPath: policyPath,
		Runtime:    detected,
		Checks:     checks,
	}
	report.Ready = onboardFailCount(report.Checks) == 0

	if err := printOnboardReport(report); err != nil {
		return err
	}
	if onboardStrict {
		if fails := onboardFailCount(report.Checks); fails > 0 {
			return fmt.Errorf("onboarding blocked: %d fail check(s)", fails)
		}
	}
	return nil
}

func evaluateInterceptionReadiness(det *runtimeenv.DetectedEnvironment) onboardCheck {
	if det == nil {
		return onboardCheck{
			ID:      "interception",
			Title:   "Interception",
			Status:  onboardStatusWarn,
			Details: "Runtime detection unavailable; interception capabilities could not be profiled.",
		}
	}
	switch runtime.GOOS {
	case "linux":
		return onboardCheck{
			ID:      "interception",
			Title:   "Interception",
			Status:  onboardStatusPass,
			Details: "Linux runtime detected. Proxy env interception is available and network namespace interception is available when run with sufficient privileges.",
		}
	case "darwin":
		return onboardCheck{
			ID:      "interception",
			Title:   "Interception",
			Status:  onboardStatusPass,
			Details: "macOS runtime detected. Proxy env interception path is available.",
		}
	case "windows":
		return onboardCheck{
			ID:      "interception",
			Title:   "Interception",
			Status:  onboardStatusPass,
			Details: "Windows runtime detected. Proxy env interception path is available.",
		}
	default:
		return onboardCheck{
			ID:      "interception",
			Title:   "Interception",
			Status:  onboardStatusWarn,
			Details: "Unknown OS. Use proxy env interception as fallback and verify runtime behavior.",
		}
	}
}

func evaluatePatchingReadiness(det *runtimeenv.DetectedEnvironment) onboardCheck {
	hasPython := commandExists("python3") || commandExists("python")
	hasNode := commandExists("node")
	if hasPython || hasNode || (det != nil && (det.Framework != "" || det.AgentHarness != "")) {
		return onboardCheck{
			ID:      "patching",
			Title:   "Patching",
			Status:  onboardStatusPass,
			Details: "Runtime supports auto-patching path. Use faramesh run to enforce FARAMESH_AUTOLOAD=1 for governed tool interception.",
		}
	}
	return onboardCheck{
		ID:          "patching",
		Title:       "Patching",
		Status:      onboardStatusWarn,
		Details:     "No Python/Node runtime detected for autopatch interception.",
		Remediation: "Install runtime dependencies or run in an environment with supported agent harnesses.",
	}
}

func evaluateHITLReadiness(doc *policy.Doc, slackWebhook, pagerdutyKey string) onboardCheck {
	if doc == nil {
		return onboardCheck{
			ID:      "hitl",
			Title:   "HITL",
			Status:  onboardStatusWarn,
			Details: "Policy unavailable; defer/HITL requirements could not be evaluated.",
		}
	}
	if !onboardPolicyHasDeferEffects(doc) {
		return onboardCheck{
			ID:      "hitl",
			Title:   "HITL",
			Status:  onboardStatusWarn,
			Details: "Current policy has no defer effects. HITL workflow is currently inactive.",
		}
	}
	missing := onboardMissingDeferBackends(doc, slackWebhook, pagerdutyKey)
	if len(missing) > 0 {
		return onboardCheck{
			ID:          "hitl",
			Title:       "HITL",
			Status:      onboardStatusFail,
			Details:     "Policy requires defer channels without configured backends: " + strings.Join(missing, ", "),
			Remediation: "Provide required HITL backends via flags or environment before strict startup.",
		}
	}
	return onboardCheck{
		ID:      "hitl",
		Title:   "HITL",
		Status:  onboardStatusPass,
		Details: "Policy defer effects are configured with available backend channels.",
	}
}

func evaluateIdentityReadiness(strict bool, spiffeSocket string) onboardCheck {
	provider := resolveOnboardWorkloadProvider(spiffeSocket)
	if provider == nil {
		if strict {
			return onboardCheck{
				ID:          "identity",
				Title:       "Identity",
				Status:      onboardStatusFail,
				Details:     "No workload identity provider detected.",
				Remediation: "Configure SPIFFE socket or supported cloud workload identity before strict runtime.",
			}
		}
		return onboardCheck{
			ID:      "identity",
			Title:   "Identity",
			Status:  onboardStatusWarn,
			Details: "No workload identity provider detected.",
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if !provider.Available(ctx) {
		if strict {
			return onboardCheck{
				ID:          "identity",
				Title:       "Identity",
				Status:      onboardStatusFail,
				Details:     fmt.Sprintf("Identity provider %q is configured but unavailable.", provider.Name()),
				Remediation: "Fix provider availability and rerun onboarding.",
			}
		}
		return onboardCheck{
			ID:      "identity",
			Title:   "Identity",
			Status:  onboardStatusWarn,
			Details: fmt.Sprintf("Identity provider %q is configured but unavailable.", provider.Name()),
		}
	}

	identity, err := provider.Identity(ctx)
	if err != nil || identity == nil {
		if strict {
			return onboardCheck{
				ID:          "identity",
				Title:       "Identity",
				Status:      onboardStatusFail,
				Details:     fmt.Sprintf("Identity provider %q failed to resolve identity: %v", provider.Name(), err),
				Remediation: "Ensure provider credentials and workload identity plumbing are configured.",
			}
		}
		return onboardCheck{
			ID:      "identity",
			Title:   "Identity",
			Status:  onboardStatusWarn,
			Details: fmt.Sprintf("Identity provider %q did not resolve identity: %v", provider.Name(), err),
		}
	}
	if !identity.Verified || !principal.IsTrustedVerificationMethod(identity.Method) {
		if strict {
			return onboardCheck{
				ID:          "identity",
				Title:       "Identity",
				Status:      onboardStatusFail,
				Details:     fmt.Sprintf("Identity resolved but is not trusted (method=%q, verified=%t).", identity.Method, identity.Verified),
				Remediation: "Use a trusted verification method (spiffe/aws_irsa/aws_ecs/aws_ec2/gcp_workload/azure_managed/github_oidc).",
			}
		}
		return onboardCheck{
			ID:      "identity",
			Title:   "Identity",
			Status:  onboardStatusWarn,
			Details: fmt.Sprintf("Identity resolved but is not trusted (method=%q, verified=%t).", identity.Method, identity.Verified),
		}
	}
	return onboardCheck{
		ID:      "identity",
		Title:   "Identity",
		Status:  onboardStatusPass,
		Details: fmt.Sprintf("Workload identity verified via %s (id=%s).", identity.Method, identity.ID),
	}
}

func evaluateIDPReadiness(doc *policy.Doc, strict bool, idpProvider string) onboardCheck {
	if doc == nil {
		return onboardCheck{
			ID:      "idp",
			Title:   "IdP",
			Status:  onboardStatusWarn,
			Details: "Policy unavailable; principal-aware IdP requirement check skipped.",
		}
	}
	if !onboardPolicyRequiresIDPProvider(doc) {
		return onboardCheck{
			ID:      "idp",
			Title:   "IdP",
			Status:  onboardStatusWarn,
			Details: "Policy does not currently require principal/delegation claim verification.",
		}
	}
	provider := strings.ToLower(strings.TrimSpace(idpProvider))
	if provider == "" {
		provider = strings.ToLower(strings.TrimSpace(os.Getenv("FARAMESH_IDP_PROVIDER")))
	}
	if provider == "" {
		provider = "default"
	}
	if provider == "" {
		if strict {
			return onboardCheck{
				ID:          "idp",
				Title:       "IdP",
				Status:      onboardStatusFail,
				Details:     "Policy requires principal/delegation verification but no IdP provider is configured.",
				Remediation: "Set --idp-provider or FARAMESH_IDP_PROVIDER.",
			}
		}
		return onboardCheck{
			ID:      "idp",
			Title:   "IdP",
			Status:  onboardStatusWarn,
			Details: "Policy requires principal/delegation verification but no IdP provider is configured.",
		}
	}
	if err := principalidp.ValidateProviderConfigFromEnv(provider); err != nil {
		if strict {
			return onboardCheck{
				ID:          "idp",
				Title:       "IdP",
				Status:      onboardStatusFail,
				Details:     fmt.Sprintf("Provider %q is configured but not ready: %v", provider, err),
				Remediation: "Provide provider configuration or use --idp-provider default for local bootstrap.",
			}
		}
		return onboardCheck{
			ID:      "idp",
			Title:   "IdP",
			Status:  onboardStatusWarn,
			Details: fmt.Sprintf("Provider %q is configured but not ready: %v", provider, err),
		}
	}
	details := fmt.Sprintf("Principal-aware policy checks enabled with IdP provider %q.", provider)
	if provider == "default" || provider == "local" {
		details = "Principal-aware policy checks enabled with built-in local IdP (no external dependency)."
	}
	return onboardCheck{
		ID:      "idp",
		Title:   "IdP",
		Status:  onboardStatusPass,
		Details: details,
	}
}

func evaluateCredentialSequestrationReadiness(doc *policy.Doc, strict bool, cfg onboardCredentialConfig) onboardCheck {
	if doc == nil {
		return onboardCheck{
			ID:      "credential_sequestration",
			Title:   "Credential sequestration",
			Status:  onboardStatusWarn,
			Details: "Policy unavailable; credential sequestration requirement check skipped.",
		}
	}
	if !onboardPolicyRequiresCredentialSequestration(doc) {
		return onboardCheck{
			ID:      "credential_sequestration",
			Title:   "Credential sequestration",
			Status:  onboardStatusWarn,
			Details: "Policy tools do not declare credential:required or credential:broker tags.",
		}
	}
	if onboardHasExternalCredentialSequestrationBackend(cfg) {
		return onboardCheck{
			ID:      "credential_sequestration",
			Title:   "Credential sequestration",
			Status:  onboardStatusPass,
			Details: "External credential backend configuration detected for brokered execution.",
		}
	}
	if onboardAllowEnvCredentialFallback() {
		return onboardCheck{
			ID:      "credential_sequestration",
			Title:   "Credential sequestration",
			Status:  onboardStatusWarn,
			Details: "Using built-in env credential broker fallback. Configure Vault/AWS/GCP/Azure/1Password/Infisical for stronger external sequestration.",
		}
	}
	if !onboardHasCredentialSequestrationBackend(cfg) {
		if strict {
			return onboardCheck{
				ID:          "credential_sequestration",
				Title:       "Credential sequestration",
				Status:      onboardStatusFail,
				Details:     "Policy requires brokered credentials but no credential backend is configured.",
				Remediation: "Configure Vault/AWS/GCP/Azure/1Password/Infisical backend via flags or env vars.",
			}
		}
		return onboardCheck{
			ID:      "credential_sequestration",
			Title:   "Credential sequestration",
			Status:  onboardStatusWarn,
			Details: "Policy requires brokered credentials but no credential backend is configured.",
		}
	}
	return onboardCheck{ID: "credential_sequestration", Title: "Credential sequestration", Status: onboardStatusPass, Details: "Credential backend configuration detected for brokered execution."}
}

func resolveOnboardPolicyPath(rawPath, cwd string) (string, error) {
	if p := strings.TrimSpace(rawPath); p != "" {
		return absolutize(cwd, p), nil
	}
	candidates := []string{"faramesh/policy.yaml", "policy.yaml", "policies/default.fpl"}
	for _, c := range candidates {
		candidate := absolutize(cwd, c)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no policy file found in default locations")
}

func absolutize(cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(cwd, path))
}

func resolveOnboardWorkloadProvider(spiffeSocket string) principal.WorkloadProvider {
	if v := strings.TrimSpace(spiffeSocket); v != "" {
		return principal.NewSPIFFEProvider(v)
	}
	if v := strings.TrimSpace(os.Getenv("FARAMESH_SPIFFE_SOCKET_PATH")); v != "" {
		return principal.NewSPIFFEProvider(v)
	}
	return principal.DetectWorkloadProvider()
}

func resolveOnboardCredentialConfig() onboardCredentialConfig {
	vaultAddr := strings.TrimSpace(onboardVaultAddr)
	if vaultAddr == "" {
		vaultAddr = strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	}
	if vaultAddr == "" {
		vaultAddr = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_ADDR"))
	}
	awsRegion := strings.TrimSpace(onboardAWSRegion)
	if awsRegion == "" {
		awsRegion = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_AWS_REGION"))
	}
	gcpProject := strings.TrimSpace(onboardGCPProject)
	if gcpProject == "" {
		gcpProject = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_GCP_PROJECT"))
	}
	azureVaultURL := strings.TrimSpace(onboardAzureVaultURL)
	if azureVaultURL == "" {
		azureVaultURL = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_AZURE_VAULT_URL"))
	}
	return onboardCredentialConfig{
		VaultAddr:       vaultAddr,
		AWSRegion:       awsRegion,
		GCPProject:      gcpProject,
		AzureVaultURL:   azureVaultURL,
		OnePasswordHost: strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_HOST")),
		OnePasswordTok:  strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_TOKEN")),
		InfisicalHost:   strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_HOST")),
		InfisicalTok:    strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_TOKEN")),
	}
}

func onboardPolicyRequiresCredentialSequestration(doc *policy.Doc) bool {
	if doc == nil {
		return false
	}
	for _, tool := range doc.Tools {
		for _, tag := range tool.Tags {
			normalized := strings.ToLower(strings.TrimSpace(tag))
			if normalized == "credential:required" || normalized == "credential:broker" {
				return true
			}
		}
	}
	return false
}

func onboardHasExternalCredentialSequestrationBackend(cfg onboardCredentialConfig) bool {
	if strings.TrimSpace(cfg.VaultAddr) != "" {
		return true
	}
	if strings.TrimSpace(cfg.AWSRegion) != "" {
		return true
	}
	if strings.TrimSpace(cfg.GCPProject) != "" {
		return true
	}
	if strings.TrimSpace(cfg.AzureVaultURL) != "" {
		return true
	}
	if strings.TrimSpace(cfg.OnePasswordHost) != "" && strings.TrimSpace(cfg.OnePasswordTok) != "" {
		return true
	}
	if strings.TrimSpace(cfg.InfisicalHost) != "" && strings.TrimSpace(cfg.InfisicalTok) != "" {
		return true
	}
	return false
}

func onboardAllowEnvCredentialFallback() bool {
	raw := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK"))
	if raw == "" {
		return true
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return true
	}
	return parsed
}

func onboardHasCredentialSequestrationBackend(cfg onboardCredentialConfig) bool {
	if onboardHasExternalCredentialSequestrationBackend(cfg) {
		return true
	}
	return onboardAllowEnvCredentialFallback()
}

func onboardPolicyRequiresIDPProvider(doc *policy.Doc) bool {
	if doc == nil {
		return false
	}
	requiresFromExpr := func(expr string) bool {
		e := strings.ToLower(strings.TrimSpace(expr))
		return strings.Contains(e, "principal.") || strings.Contains(e, "delegation.")
	}
	for _, rule := range doc.Rules {
		if requiresFromExpr(rule.Match.When) {
			return true
		}
	}
	for _, tr := range doc.PhaseTransitions {
		if requiresFromExpr(tr.Conditions) {
			return true
		}
	}
	for _, guard := range doc.CrossSessionGuards {
		if strings.EqualFold(strings.TrimSpace(guard.Scope), "principal") {
			return true
		}
	}
	return false
}

func onboardPolicyHasDeferEffects(doc *policy.Doc) bool {
	if doc == nil {
		return false
	}
	for _, rule := range doc.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.Effect), "defer") {
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(doc.DefaultEffect), "defer") {
		return true
	}
	if doc.Budget != nil && strings.EqualFold(strings.TrimSpace(doc.Budget.OnExceed), "defer") {
		return true
	}
	for _, guard := range doc.ContextGuards {
		if strings.EqualFold(strings.TrimSpace(guard.OnStale), "defer") ||
			strings.EqualFold(strings.TrimSpace(guard.OnMissing), "defer") ||
			strings.EqualFold(strings.TrimSpace(guard.OnInconsistent), "defer") {
			return true
		}
	}
	for _, tr := range doc.PhaseTransitions {
		if strings.EqualFold(strings.TrimSpace(tr.Effect), "defer") {
			return true
		}
	}
	if doc.PhaseEnforcement != nil && strings.EqualFold(strings.TrimSpace(doc.PhaseEnforcement.OnOutOfPhaseCall), "defer") {
		return true
	}
	for _, guard := range doc.CrossSessionGuards {
		if strings.EqualFold(strings.TrimSpace(guard.OnExceed), "defer") {
			return true
		}
	}
	if doc.LoopGovernance != nil && strings.EqualFold(strings.TrimSpace(doc.LoopGovernance.OnMaxReached), "defer") {
		return true
	}
	if doc.LoopGovernance != nil && doc.LoopGovernance.ConvergenceTrack != nil {
		if strings.EqualFold(strings.TrimSpace(doc.LoopGovernance.ConvergenceTrack.OnEvasion), "defer") {
			return true
		}
	}
	for _, out := range doc.OutputPolicies {
		for _, rule := range out.Rules {
			if strings.EqualFold(strings.TrimSpace(rule.OnMatch), "defer") {
				return true
			}
		}
	}
	return false
}

func onboardMissingDeferBackends(doc *policy.Doc, slackWebhook, pagerdutyKey string) []string {
	if !onboardPolicyHasDeferEffects(doc) || doc == nil || doc.DeferPriority == nil {
		return nil
	}
	channels := map[string]struct{}{}
	addChannel := func(tier *policy.DeferTier) {
		if tier == nil {
			return
		}
		channel := strings.ToLower(strings.TrimSpace(tier.Channel))
		if channel != "" {
			channels[channel] = struct{}{}
		}
	}
	addChannel(doc.DeferPriority.Critical)
	addChannel(doc.DeferPriority.High)
	addChannel(doc.DeferPriority.Normal)

	slack := strings.TrimSpace(slackWebhook)
	if slack == "" {
		slack = strings.TrimSpace(os.Getenv("FARAMESH_SLACK_WEBHOOK"))
	}
	pagerduty := strings.TrimSpace(pagerdutyKey)
	if pagerduty == "" {
		pagerduty = strings.TrimSpace(os.Getenv("FARAMESH_PAGERDUTY_ROUTING_KEY"))
	}

	missing := []string{}
	if _, ok := channels["slack"]; ok && slack == "" {
		missing = append(missing, "--slack-webhook")
	}
	if _, ok := channels["pagerduty"]; ok && pagerduty == "" {
		missing = append(missing, "--pagerduty-routing-key")
	}
	return missing
}

func onboardFailCount(checks []onboardCheck) int {
	count := 0
	for _, c := range checks {
		if c.Status == onboardStatusFail {
			count++
		}
	}
	return count
}

func printOnboardReport(report onboardReport) error {
	if onboardJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	fmt.Println("Faramesh Onboarding Readiness")
	fmt.Printf("  strict: %t\n", report.Strict)
	if report.PolicyPath != "" {
		fmt.Printf("  policy: %s\n", report.PolicyPath)
	}
	if report.Runtime != nil {
		fmt.Printf("  runtime: %s\n", report.Runtime.Runtime)
		fmt.Printf("  framework: %s\n", report.Runtime.Framework)
		fmt.Printf("  harness: %s\n", report.Runtime.AgentHarness)
	}
	fmt.Println()

	for _, c := range report.Checks {
		fmt.Printf("[%s] %s\n", strings.ToUpper(string(c.Status)), c.Title)
		if c.Details != "" {
			fmt.Printf("  %s\n", c.Details)
		}
		if c.Remediation != "" {
			fmt.Printf("  remediation: %s\n", c.Remediation)
		}
		fmt.Println()
	}

	if report.Ready {
		fmt.Println("Overall: READY")
	} else {
		fmt.Printf("Overall: BLOCKED (%d fail checks)\n", onboardFailCount(report.Checks))
	}
	fmt.Println("Next: faramesh serve --strict-preflight --policy <policy-file>")
	return nil
}
