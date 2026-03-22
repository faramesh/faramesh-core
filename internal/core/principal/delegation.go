package principal

import "strings"

// DelegationLink represents one hop in a delegation chain.
type DelegationLink struct {
	AgentID          string   `json:"agent_id"`
	IdentityVerified bool     `json:"identity_verified"`
	DelegatedAt      int64    `json:"delegated_at,omitempty"`
	Scope            []string `json:"scope,omitempty"`
	Depth            int      `json:"depth,omitempty"`
	OriginOrg        string   `json:"origin_org,omitempty"`
}

// DelegationChain carries delegation context for policy/runtime checks.
type DelegationChain struct {
	Links []DelegationLink `json:"links"`
}

func (d *DelegationChain) Len() int {
	if d == nil {
		return 0
	}
	return len(d.Links)
}

func (d *DelegationChain) Depth() int {
	return d.Len()
}

func (d *DelegationChain) OriginAgent() string {
	if d == nil || len(d.Links) == 0 {
		return ""
	}
	return d.Links[0].AgentID
}

func (d *DelegationChain) OriginOrg() string {
	if d == nil || len(d.Links) == 0 {
		return ""
	}
	return d.Links[0].OriginOrg
}

func (d *DelegationChain) AllIdentitiesVerified() bool {
	if d == nil {
		return false
	}
	for _, link := range d.Links {
		if !link.IdentityVerified {
			return false
		}
	}
	return len(d.Links) > 0
}

func (d *DelegationChain) ToolInScope(toolID string) bool {
	if d == nil || len(d.Links) == 0 {
		return false
	}
	lastLink := d.Links[len(d.Links)-1]
	if len(lastLink.Scope) == 0 {
		return true
	}
	for _, pattern := range lastLink.Scope {
		if matchToolGlob(pattern, toolID) {
			return true
		}
	}
	return false
}

func matchToolGlob(pattern, toolID string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(toolID, strings.TrimSuffix(pattern, "*"))
	}
	return toolID == pattern
}
