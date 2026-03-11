// Package principal — cross-org trust federation.
//
// Implements trust documents for multi-organization federation. When Agent A
// (org Alpha) needs to invoke Agent B (org Beta), the delegation chain must
// carry a signed trust document proving Alpha→Beta trust.
//
// Trust is:
//   - Non-transitive: Alpha trusts Beta ≠ Alpha trusts Beta's partners
//   - Scope-bounded: trust permits specific tool patterns only
//   - Time-bounded: trust documents expire
//   - Delegated-authority: the maximum tier that can be delegated
//
// This corresponds to Layer 7 (Multi-Agent Delegation) of the architecture.
package principal

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// TrustDocument is a signed assertion that one org trusts another
// for specific tool invocations within bounded authority.
type TrustDocument struct {
	// DocumentID is the unique identifier for this trust document.
	DocumentID string `json:"document_id" yaml:"document_id"`

	// GrantorOrg is the organization granting trust.
	GrantorOrg string `json:"grantor_org" yaml:"grantor_org"`

	// GranteeOrg is the organization receiving trust.
	GranteeOrg string `json:"grantee_org" yaml:"grantee_org"`

	// ToolScopes defines which tool patterns are permitted.
	// e.g. ["db/*", "api/billing/*"]
	ToolScopes []string `json:"tool_scopes" yaml:"tool_scopes"`

	// MaxTier is the maximum principal tier that can be delegated.
	MaxTier string `json:"max_tier" yaml:"max_tier"`

	// MaxDelegationDepth limits how deep delegation can go.
	MaxDelegationDepth int `json:"max_delegation_depth" yaml:"max_delegation_depth"`

	// IssuedAt is when the trust document was created.
	IssuedAt time.Time `json:"issued_at" yaml:"issued_at"`

	// ExpiresAt is when the trust document expires.
	ExpiresAt time.Time `json:"expires_at" yaml:"expires_at"`

	// SignatureHash is the SHA-256 hash of the signed content.
	// In production, this would be a proper cryptographic signature.
	SignatureHash string `json:"signature_hash" yaml:"signature_hash"`

	// Revoked marks the document as revoked before expiry.
	Revoked bool `json:"revoked" yaml:"revoked"`
}

// Valid returns true if the trust document is active.
func (td *TrustDocument) Valid() bool {
	now := time.Now()
	return !td.Revoked && now.After(td.IssuedAt) && now.Before(td.ExpiresAt)
}

// Hash computes the content hash of the trust document (excluding signature).
func (td *TrustDocument) Hash() string {
	content := fmt.Sprintf("%s|%s|%s|%v|%s|%d|%s|%s",
		td.DocumentID, td.GrantorOrg, td.GranteeOrg,
		td.ToolScopes, td.MaxTier, td.MaxDelegationDepth,
		td.IssuedAt.Format(time.RFC3339), td.ExpiresAt.Format(time.RFC3339))
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

// FederationRegistry manages trust documents between organizations.
type FederationRegistry struct {
	mu        sync.RWMutex
	documents map[string]*TrustDocument          // documentID → doc
	trustMap  map[string]map[string][]string      // grantorOrg → granteeOrg → []documentIDs
}

// NewFederationRegistry creates a new federation registry.
func NewFederationRegistry() *FederationRegistry {
	return &FederationRegistry{
		documents: make(map[string]*TrustDocument),
		trustMap:  make(map[string]map[string][]string),
	}
}

// Register adds a trust document to the registry.
func (fr *FederationRegistry) Register(doc *TrustDocument) error {
	if doc.DocumentID == "" {
		return fmt.Errorf("trust document must have an ID")
	}
	if doc.GrantorOrg == "" || doc.GranteeOrg == "" {
		return fmt.Errorf("trust document must specify grantor and grantee orgs")
	}
	if doc.GrantorOrg == doc.GranteeOrg {
		return fmt.Errorf("self-trust is implicit and not allowed as a document")
	}

	doc.SignatureHash = doc.Hash()

	fr.mu.Lock()
	defer fr.mu.Unlock()

	fr.documents[doc.DocumentID] = doc
	if fr.trustMap[doc.GrantorOrg] == nil {
		fr.trustMap[doc.GrantorOrg] = make(map[string][]string)
	}
	fr.trustMap[doc.GrantorOrg][doc.GranteeOrg] = append(
		fr.trustMap[doc.GrantorOrg][doc.GranteeOrg], doc.DocumentID)
	return nil
}

// CheckTrust verifies that grantorOrg trusts granteeOrg for the given tool.
// Returns the applicable trust document or nil.
func (fr *FederationRegistry) CheckTrust(grantorOrg, granteeOrg, toolID string) *TrustDocument {
	// Self-trust is implicit.
	if grantorOrg == granteeOrg {
		return &TrustDocument{
			DocumentID: "self-trust",
			GrantorOrg: grantorOrg,
			GranteeOrg: granteeOrg,
			ToolScopes: []string{"*"},
			MaxTier:    "enterprise",
			IssuedAt:   time.Time{},
			ExpiresAt:  time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		}
	}

	fr.mu.RLock()
	defer fr.mu.RUnlock()

	grantees, ok := fr.trustMap[grantorOrg]
	if !ok {
		return nil
	}
	docIDs, ok := grantees[granteeOrg]
	if !ok {
		return nil
	}

	for _, docID := range docIDs {
		doc := fr.documents[docID]
		if doc == nil || !doc.Valid() {
			continue
		}
		// Check if the tool is in scope.
		for _, pattern := range doc.ToolScopes {
			if matchToolGlob(pattern, toolID) {
				return doc
			}
		}
	}
	return nil
}

// Revoke revokes a trust document by ID.
func (fr *FederationRegistry) Revoke(documentID string) error {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	doc, ok := fr.documents[documentID]
	if !ok {
		return fmt.Errorf("trust document %s not found", documentID)
	}
	doc.Revoked = true
	return nil
}

// TrustDocumentsFor returns all valid trust documents where the given org is the grantee.
func (fr *FederationRegistry) TrustDocumentsFor(granteeOrg string) []*TrustDocument {
	fr.mu.RLock()
	defer fr.mu.RUnlock()
	var docs []*TrustDocument
	for _, grantees := range fr.trustMap {
		for grantee, docIDs := range grantees {
			if grantee != granteeOrg {
				continue
			}
			for _, docID := range docIDs {
				if doc := fr.documents[docID]; doc != nil && doc.Valid() {
					docs = append(docs, doc)
				}
			}
		}
	}
	return docs
}

// ValidateDelegationChain checks that every cross-org hop in a delegation chain
// is backed by a valid trust document.
func (fr *FederationRegistry) ValidateDelegationChain(chain *DelegationChain, toolID string) error {
	if chain == nil || len(chain.Links) < 2 {
		return nil // no cross-org hops
	}

	for i := 1; i < len(chain.Links); i++ {
		prev := chain.Links[i-1]
		curr := chain.Links[i]
		if prev.OriginOrg == curr.OriginOrg || prev.OriginOrg == "" || curr.OriginOrg == "" {
			continue // same org or unknown — skip
		}
		doc := fr.CheckTrust(prev.OriginOrg, curr.OriginOrg, toolID)
		if doc == nil {
			return fmt.Errorf("no trust document for %s → %s (tool %s)",
				prev.OriginOrg, curr.OriginOrg, toolID)
		}
		if doc.MaxDelegationDepth > 0 && curr.Depth > doc.MaxDelegationDepth {
			return fmt.Errorf("delegation depth %d exceeds max %d for trust %s → %s",
				curr.Depth, doc.MaxDelegationDepth, prev.OriginOrg, curr.OriginOrg)
		}
	}
	return nil
}

// Cleanup removes expired and revoked trust documents older than maxAge.
func (fr *FederationRegistry) Cleanup(maxAge time.Duration) int {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, doc := range fr.documents {
		if doc.ExpiresAt.Before(cutoff) || (doc.Revoked && doc.ExpiresAt.Before(time.Now())) {
			delete(fr.documents, id)
			removed++
		}
	}
	return removed
}
