package registry

// WellKnown is served at GET /.well-known/faramesh.json (FARAMESH_REGISTRY_PLATFORM.md §4.1).
type WellKnown struct {
	APIVersion  string            `json:"api_version"`
	RegistryID  string            `json:"registry_id"`
	Search      string            `json:"search"`
	Artifact    ArtifactEndpoints `json:"artifact"`
	LegacyPacks string            `json:"legacy_packs_path,omitempty"`
	Trust       *TrustEndpoints   `json:"trust,omitempty"`
}

// ArtifactEndpoints lists relative paths for each kind.
type ArtifactEndpoints struct {
	Providers  string `json:"providers"`
	Policies   string `json:"policies"`
	Frameworks string `json:"frameworks"`
}

// TrustEndpoints points to publisher key material.
type TrustEndpoints struct {
	OfficialKeyIDs []string `json:"official_key_ids,omitempty"`
	KeysURL        string   `json:"keys_url,omitempty"`
}
