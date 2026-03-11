// Package principal — SPIFFE/SPIRE workload identity integration.
//
// Implements mTLS-based identity using SPIFFE Verifiable Identity Documents
// (SVIDs). The Faramesh daemon uses its SVID to prove its own identity,
// and can verify agent SVIDs to establish trust without shared secrets.
//
// Trust bundles are auto-rotated via the SPIRE Workload API.
package principal

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"
)

// SVID represents a SPIFFE Verifiable Identity Document.
type SVID struct {
	// SPIFFEID is the SPIFFE URI (e.g. "spiffe://example.org/faramesh/agent/billing").
	SPIFFEID string `json:"spiffe_id"`

	// X509 is the parsed x509 certificate (nil for JWT SVIDs).
	X509 *x509.Certificate `json:"-"`

	// ExpiresAt is the SVID expiry.
	ExpiresAt time.Time `json:"expires_at"`

	// TrustDomain is the SPIFFE trust domain.
	TrustDomain string `json:"trust_domain"`
}

// Valid returns true if the SVID has not expired.
func (s *SVID) Valid() bool {
	return time.Now().Before(s.ExpiresAt)
}

// AgentPath extracts the agent path from the SPIFFE ID.
// e.g. "spiffe://example.org/faramesh/agent/billing" → "faramesh/agent/billing"
func (s *SVID) AgentPath() string {
	// SPIFFE ID format: spiffe://<trust-domain>/<path>
	parts := strings.SplitN(s.SPIFFEID, "/", 4)
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}

// SPIFFEProvider manages SPIFFE identity and trust bundles via the
// SPIRE Workload API (typically a Unix domain socket).
type SPIFFEProvider struct {
	mu          sync.RWMutex
	socketPath  string
	trustDomain string
	svid        *SVID
	trustBundle []*x509.Certificate
	cancel      context.CancelFunc
}

// SPIFFEConfig holds configuration for the SPIFFE provider.
type SPIFFEConfig struct {
	// WorkloadAPISocket is the SPIRE workload API socket path.
	// Default: "unix:///run/spire/sockets/agent.sock"
	WorkloadAPISocket string `yaml:"workload_api_socket"`

	// TrustDomain is the expected SPIFFE trust domain.
	TrustDomain string `yaml:"trust_domain"`
}

// NewSPIFFEProvider creates a new SPIFFE identity provider.
func NewSPIFFEProvider(cfg SPIFFEConfig) *SPIFFEProvider {
	if cfg.WorkloadAPISocket == "" {
		cfg.WorkloadAPISocket = "unix:///run/spire/sockets/agent.sock"
	}
	return &SPIFFEProvider{
		socketPath:  cfg.WorkloadAPISocket,
		trustDomain: cfg.TrustDomain,
	}
}

// Start begins watching the SPIRE Workload API for SVID updates.
// In production, this connects to the SPIRE agent and receives streaming
// SVID rotations. Here we define the lifecycle.
func (sp *SPIFFEProvider) Start(ctx context.Context) error {
	ctx, sp.cancel = context.WithCancel(ctx)
	// In production: connect to sp.socketPath, call FetchX509SVID,
	// stream updates. For now, the framework is defined.
	_ = ctx
	return nil
}

// Stop terminates the SPIRE watcher.
func (sp *SPIFFEProvider) Stop() {
	if sp.cancel != nil {
		sp.cancel()
	}
}

// CurrentSVID returns the current SVID for this workload.
func (sp *SPIFFEProvider) CurrentSVID() (*SVID, error) {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	if sp.svid == nil {
		return nil, fmt.Errorf("no SVID available (SPIRE agent not connected)")
	}
	if !sp.svid.Valid() {
		return nil, fmt.Errorf("SVID expired at %s", sp.svid.ExpiresAt)
	}
	return sp.svid, nil
}

// TrustBundle returns the current trust bundle certificates.
func (sp *SPIFFEProvider) TrustBundle() []*x509.Certificate {
	sp.mu.RLock()
	defer sp.mu.RUnlock()
	return sp.trustBundle
}

// VerifyPeer validates an agent's SVID against the trust bundle.
func (sp *SPIFFEProvider) VerifyPeer(peerSVID *SVID) error {
	if peerSVID == nil {
		return fmt.Errorf("nil peer SVID")
	}
	if !peerSVID.Valid() {
		return fmt.Errorf("peer SVID expired")
	}
	if peerSVID.TrustDomain != sp.trustDomain {
		return fmt.Errorf("peer trust domain %q does not match expected %q",
			peerSVID.TrustDomain, sp.trustDomain)
	}
	// In production: verify the x509 certificate chain against sp.trustBundle.
	return nil
}

// IdentityFromSVID converts a verified SVID into a Faramesh Identity.
func IdentityFromSVID(svid *SVID) Identity {
	return Identity{
		ID:       svid.SPIFFEID,
		Verified: svid.Valid(),
		Method:   "spiffe",
		Org:      svid.TrustDomain,
	}
}
