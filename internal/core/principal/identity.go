// Package principal defines principal (invoking human/system) identity
// and delegation chain types. These are first-class governance primitives:
// policy rules can reference principal.* and delegation.* conditions.
//
// This implements Layer 6 (Identity) and Layer 7 (Multi-Agent Delegation)
// from the Faramesh architecture spec.
package principal

// Identity represents the invoking principal — the human or system
// that started the agent session. Tracked separately from agent identity.
type Identity struct {
	// ID is the IDP-verified identity (e.g. "user@company.com").
	ID string `json:"id" yaml:"id"`

	// Tier is the SaaS tier for multi-tier platforms (free, pro, enterprise).
	Tier string `json:"tier,omitempty" yaml:"tier"`

	// Role is the organizational role (analyst, operator, admin).
	Role string `json:"role,omitempty" yaml:"role"`

	// Org is the organization identifier.
	Org string `json:"org,omitempty" yaml:"org"`

	// Verified indicates if the identity was IDP-verified.
	Verified bool `json:"verified" yaml:"verified"`

	// Method is how identity was verified (okta, azure_ad, google, api_key, spiffe).
	Method string `json:"method,omitempty" yaml:"method"`
}

// DelegationLink is one hop in a delegation chain.
type DelegationLink struct {
	// AgentID is the delegating agent's identity.
	AgentID string `json:"agent_id" yaml:"agent_id"`

	// IdentityVerified indicates if the delegating agent's identity was verified.
	IdentityVerified bool `json:"identity_verified" yaml:"identity_verified"`

	// DelegatedAt is the Unix timestamp when delegation occurred.
	DelegatedAt int64 `json:"delegated_at" yaml:"delegated_at"`

	// Scope is the set of tool patterns the delegation permits.
	Scope []string `json:"scope" yaml:"scope"`

	// Depth is the delegation depth (1 = direct from orchestrator).
	Depth int `json:"depth" yaml:"depth"`

	// OriginOrg is the origin organization (for cross-org federation).
	OriginOrg string `json:"origin_org,omitempty" yaml:"origin_org"`
}

// DelegationChain represents the full delegation path to the current agent.
type DelegationChain struct {
	Links []DelegationLink `json:"links" yaml:"links"`
}

// Len returns the number of links in the delegation chain.
func (dc *DelegationChain) Len() int {
	if dc == nil {
		return 0
	}
	return len(dc.Links)
}

// Depth returns the current delegation depth (0 if no delegation).
func (dc *DelegationChain) Depth() int {
	if dc == nil || len(dc.Links) == 0 {
		return 0
	}
	return len(dc.Links)
}

// OriginAgent returns the ID of the original orchestrator (the root of the chain).
func (dc *DelegationChain) OriginAgent() string {
	if dc == nil || len(dc.Links) == 0 {
		return ""
	}
	return dc.Links[0].AgentID
}

// OriginOrg returns the organization of the original orchestrator.
func (dc *DelegationChain) OriginOrg() string {
	if dc == nil || len(dc.Links) == 0 {
		return ""
	}
	return dc.Links[0].OriginOrg
}

// IsExternal returns true if the delegation originates from a different organization.
func (dc *DelegationChain) IsExternal(selfOrg string) bool {
	origin := dc.OriginOrg()
	return origin != "" && origin != selfOrg
}

// ToolInScope returns true if the given tool ID is within the delegated scope.
// An empty scope means all tools are permitted (unrestricted delegation).
func (dc *DelegationChain) ToolInScope(toolID string) bool {
	if dc == nil || len(dc.Links) == 0 {
		return true
	}
	// Check the most restrictive scope (last link — authority reduction).
	lastLink := dc.Links[len(dc.Links)-1]
	if len(lastLink.Scope) == 0 {
		return true // unrestricted delegation
	}
	for _, pattern := range lastLink.Scope {
		if matchToolGlob(pattern, toolID) {
			return true
		}
	}
	return false
}

// AllIdentitiesVerified returns true if every agent in the chain is verified.
func (dc *DelegationChain) AllIdentitiesVerified() bool {
	if dc == nil || len(dc.Links) == 0 {
		return true
	}
	for _, link := range dc.Links {
		if !link.IdentityVerified {
			return false
		}
	}
	return true
}

func matchToolGlob(pattern, toolID string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	n := len(pattern)
	if n > 0 && pattern[n-1] == '*' {
		prefix := pattern[:n-1]
		return len(toolID) >= len(prefix) && toolID[:len(prefix)] == prefix
	}
	return pattern == toolID
}
