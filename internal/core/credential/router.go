package credential

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// RouteResolution describes how a tool ID maps to a broker backend.
type RouteResolution struct {
	Pattern      string `json:"pattern,omitempty"`
	Backend      string `json:"backend,omitempty"`
	UsedFallback bool   `json:"used_fallback,omitempty"`
}

// Router routes credential requests to the appropriate broker based on
// tool-to-backend mappings defined in the policy. It also implements
// credential lifecycle: Fetch → Inject → Execute → Revoke.
type Router struct {
	mu       sync.RWMutex
	backends map[string]Broker // name -> broker
	routes   map[string]string // tool pattern -> broker name
	fallback Broker            // used when no route matches
}

// NewRouter creates a credential router with the given backends.
func NewRouter(backends []Broker, fallback Broker) *Router {
	r := &Router{
		backends: make(map[string]Broker, len(backends)),
		routes:   make(map[string]string),
		fallback: fallback,
	}
	for _, b := range backends {
		r.backends[b.Name()] = b
	}
	return r
}

// AddRoute maps a tool pattern to a broker backend.
// Tool patterns support glob: "stripe/*" → "vault", "aws/*" → "aws_secrets_manager".
func (r *Router) AddRoute(toolPattern, brokerName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.backends[brokerName]; !ok {
		return fmt.Errorf("unknown broker backend: %s", brokerName)
	}
	r.routes[toolPattern] = brokerName
	return nil
}

// RoutesSnapshot returns a copy of the configured tool-pattern routes.
func (r *Router) RoutesSnapshot() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.routes))
	for pattern, backend := range r.routes {
		out[pattern] = backend
	}
	return out
}

// BackendNames returns all configured broker backend names, sorted.
func (r *Router) BackendNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.backends))
	for name := range r.backends {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// FallbackBackendName returns the fallback backend name, if configured.
func (r *Router) FallbackBackendName() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.fallback == nil {
		return ""
	}
	return r.fallback.Name()
}

// ResolveRoute returns route-level resolution details for diagnostics.
func (r *Router) ResolveRoute(toolID string) RouteResolution {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if name, ok := r.routes[toolID]; ok {
		if _, backendOK := r.backends[name]; backendOK {
			return RouteResolution{Pattern: toolID, Backend: name}
		}
	}

	bestPattern := ""
	bestBackend := ""
	for pattern, name := range r.routes {
		if pattern == toolID {
			continue
		}
		if !matchToolPattern(pattern, toolID) {
			continue
		}
		if _, backendOK := r.backends[name]; !backendOK {
			continue
		}
		if len(pattern) > len(bestPattern) {
			bestPattern = pattern
			bestBackend = name
		}
	}
	if bestBackend != "" {
		return RouteResolution{Pattern: bestPattern, Backend: bestBackend}
	}

	if r.fallback != nil {
		return RouteResolution{Backend: r.fallback.Name(), UsedFallback: true}
	}

	return RouteResolution{}
}

// Resolve finds the appropriate broker for a tool call.
// Uses longest-match semantics consistent with ResolveRoute.
func (r *Router) Resolve(toolID string) Broker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match first.
	if name, ok := r.routes[toolID]; ok {
		if b, ok := r.backends[name]; ok {
			return b
		}
	}
	// Longest glob match (deterministic, consistent with ResolveRoute).
	bestPattern := ""
	var bestBroker Broker
	for pattern, name := range r.routes {
		if pattern == toolID {
			continue
		}
		if !matchToolPattern(pattern, toolID) {
			continue
		}
		b, ok := r.backends[name]
		if !ok {
			continue
		}
		if len(pattern) > len(bestPattern) {
			bestPattern = pattern
			bestBroker = b
		}
	}
	if bestBroker != nil {
		return bestBroker
	}
	return r.fallback
}

// BrokerCall manages the full credential lifecycle for a single tool call:
// Fetch → inject into environment → caller executes tool → Revoke.
// The Credential value is zeroed after revocation.
func (r *Router) BrokerCall(ctx context.Context, req FetchRequest) (*CredentialHandle, error) {
	broker := r.Resolve(req.ToolID)
	if broker == nil {
		return nil, fmt.Errorf("no credential broker for tool %q", req.ToolID)
	}

	if req.TTL == 0 {
		req.TTL = 5 * time.Minute // default TTL per plan
	}

	cred, err := broker.Fetch(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("credential fetch from %s: %w", broker.Name(), err)
	}

	return &CredentialHandle{
		Credential: cred,
		broker:     broker,
	}, nil
}

// CredentialHandle wraps a Credential with lifecycle management.
// The credential value is automatically zeroed on Release().
type CredentialHandle struct {
	Credential *Credential
	broker     Broker
	released   bool
}

// Release revokes and zeros the credential.
// Safe to call multiple times (idempotent).
func (h *CredentialHandle) Release(ctx context.Context) error {
	if h.released {
		return nil
	}
	h.released = true

	var err error
	if h.Credential.Revocable {
		err = h.broker.Revoke(ctx, h.Credential)
	}
	// Zero the value regardless of revocation outcome.
	h.Credential.Value = ""
	return err
}

func matchToolPattern(pattern, toolID string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(toolID, prefix+"/")
	}
	return pattern == toolID
}
