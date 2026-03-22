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

	Description string `json:"description,omitempty"`
	PolicyYAML  string `json:"policy_yaml"`
	SHA256Hex   string `json:"sha256_hex"`
	TrustTier   string `json:"trust_tier,omitempty"`

	Signature *PackSignature `json:"signature,omitempty"`
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
	APIVersion  string `json:"api_version,omitempty"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	PolicyYAML  string `json:"policy_yaml"`
	TrustTier   string `json:"trust_tier,omitempty"`
}
