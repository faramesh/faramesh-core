package hub

// APIVersion is the wire contract revision for Hub HTTP JSON responses.
const APIVersion = "1"

// SearchResponse is returned by GET /v1/search.
type SearchResponse struct {
	APIVersion string        `json:"api_version"`
	Packs      []PackSummary `json:"packs"`
}

// PackSummary is one row in search results.
type PackSummary struct {
	Name          string `json:"name"`
	LatestVersion string `json:"latest_version"`
	Description   string `json:"description"`
	Downloads     int64  `json:"downloads"`
	TrustTier     string `json:"trust_tier,omitempty"`
}

// PackVersionResponse is returned by GET /v1/packs/{name}/versions/{version}.
type PackVersionResponse struct {
	APIVersion string `json:"api_version"`
	Name       string `json:"name"`
	Version    string `json:"version"`

	Description         string                 `json:"description,omitempty"`
	PolicyYAML          string                 `json:"policy_yaml"`
	// PolicyFPL is optional authored FPL; when set, install writes policy.fpl beside policy.yaml.
	PolicyFPL           string                 `json:"policy_fpl,omitempty"`
	SHA256Hex           string                 `json:"sha256_hex"`
	TrustTier           string                 `json:"trust_tier,omitempty"`
	Publisher           *PackPublisher         `json:"publisher,omitempty"`
	RiskModel           *PackRiskModel         `json:"risk_model,omitempty"`
	SupportedFrameworks []string               `json:"supported_frameworks,omitempty"`
	ActionSurfaces      []string               `json:"supported_action_surfaces,omitempty"`
	Assumptions         []string               `json:"assumptions,omitempty"`
	RulesSummary        *PackRulesSummary      `json:"starter_rules_summary,omitempty"`
	ApprovalDefaults    []PackApprovalDefault  `json:"approval_defaults,omitempty"`
	CredentialExpect    []PackCredentialExpect `json:"credential_expectations,omitempty"`
	ObserveEnforce      *PackObserveEnforce    `json:"observe_enforce_recommendation,omitempty"`
	ExampleIncidents    []string               `json:"example_incidents_prevented,omitempty"`
	Dependencies        []string               `json:"dependencies,omitempty"`
	FarameshVersion     string                 `json:"faramesh_version,omitempty"`
	Compatibility       map[string]string      `json:"compatibility,omitempty"`
	Changelog           string                 `json:"changelog,omitempty"`

	Signature *PackSignature `json:"signature,omitempty"`
}

// PackVersionResponseV2 exposes the richer registry metadata shape.
type PackVersionResponseV2 struct {
	PackVersionResponse
}

// PackSignature describes an Ed25519 detached signature over raw policy YAML bytes.
type PackSignature struct {
	Algorithm    string `json:"algorithm"` // "ed25519"
	KeyID        string `json:"key_id,omitempty"`
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	ValueB64     string `json:"value_b64"`
}

// PublishRequest is the JSON body for POST /v1/packs.
type PublishRequest struct {
	APIVersion          string                 `json:"api_version,omitempty"`
	Name                string                 `json:"name"`
	Version             string                 `json:"version"`
	Description         string                 `json:"description,omitempty"`
	PolicyYAML          string                 `json:"policy_yaml"`
	PolicyFPL           string                 `json:"policy_fpl,omitempty"`
	TrustTier           string                 `json:"trust_tier,omitempty"`
	Publisher           *PackPublisher         `json:"publisher,omitempty"`
	RiskModel           *PackRiskModel         `json:"risk_model,omitempty"`
	SupportedFrameworks []string               `json:"supported_frameworks,omitempty"`
	ActionSurfaces      []string               `json:"supported_action_surfaces,omitempty"`
	Assumptions         []string               `json:"assumptions,omitempty"`
	RulesSummary        *PackRulesSummary      `json:"starter_rules_summary,omitempty"`
	ApprovalDefaults    []PackApprovalDefault  `json:"approval_defaults,omitempty"`
	CredentialExpect    []PackCredentialExpect `json:"credential_expectations,omitempty"`
	ObserveEnforce      *PackObserveEnforce    `json:"observe_enforce_recommendation,omitempty"`
	ExampleIncidents    []string               `json:"example_incidents_prevented,omitempty"`
	Dependencies        []string               `json:"dependencies,omitempty"`
	FarameshVersion     string                 `json:"faramesh_version,omitempty"`
	Compatibility       map[string]string      `json:"compatibility,omitempty"`
	Changelog           string                 `json:"changelog,omitempty"`
}

type PackPublisher struct {
	ID           string `json:"id"`
	DisplayName  string `json:"display_name"`
	Verified     bool   `json:"verified"`
	SigningKeyID string `json:"signing_key_id,omitempty"`
}

type PackRiskModel struct {
	Categories  []string `json:"categories,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	BlastRadius string   `json:"blast_radius,omitempty"`
}

type PackRulesSummary struct {
	Permit []string `json:"permit,omitempty"`
	Defer  []string `json:"defer,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

type PackApprovalDefault struct {
	Rule    string `json:"rule"`
	Type    string `json:"type"`
	Timeout string `json:"timeout,omitempty"`
	Channel string `json:"channel,omitempty"`
}

type PackCredentialExpect struct {
	Backend  string `json:"backend"`
	Required bool   `json:"required"`
	Scope    string `json:"scope,omitempty"`
	Note     string `json:"note,omitempty"`
}

type PackObserveEnforce struct {
	ObservePeriod     string             `json:"observe_period,omitempty"`
	EnforcementStages []PackEnforceStage `json:"enforcement_stages,omitempty"`
}

type PackEnforceStage struct {
	Stage       string `json:"stage"`
	Duration    string `json:"duration,omitempty"`
	Description string `json:"description,omitempty"`
}
