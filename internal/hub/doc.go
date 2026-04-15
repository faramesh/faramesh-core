// Package hub implements the open-binary Hub registry **client** for policy packs.
//
// It targets a small versioned HTTP JSON API so any compatible registry (self-hosted,
// future Faramesh Hub, or tests) can be used without proprietary server code in this repo.
//
// A **public** browse/publish website (Terraform Registry–style for packs) is **not** implemented
// here and is **not** the same product as the gated SaaS console in Faramesh-cloud-platform/;
// expect that UX to live in its **own** repository while this package remains the HTTP client.
//
// # Registry API v1 (compatibility contract)
//
// Base URL has no trailing slash requirement; clients normalize it.
//
//	GET /v1/search?q={query}
//	→ {"api_version":"1","packs":[{"name":"org/pack","latest_version":"1.0.0","description":"...","downloads":0}]}
//
//	GET /v1/packs/{name}/versions/{version}
//	→ PackVersionResponse: policy_yaml, sha256_hex, optional signature (ed25519 over raw policy bytes).
//
//	name is a single path segment: URL-encode slashes as %2F (e.g. faramesh%2Ffinancial-saas).
//
//	POST /v1/packs  (publish; optional Bearer token)
//	→ JSON body with name, version, policy_yaml, description.
//
// Signature verification uses Ed25519 over the raw policy YAML bytes when signature.public_key_pem
// and signature.value_b64 are present (Terraform-registry-style trust: TLS to registry + embedded key).
package hub
