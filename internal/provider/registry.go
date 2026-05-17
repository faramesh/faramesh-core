package provider

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/credential"
	"github.com/faramesh/faramesh-core/internal/provider/builtin"
	"github.com/faramesh/faramesh-core/internal/provider/launcher"
	providerv1 "github.com/faramesh/faramesh-core/proto/provider/v1"
)

// Entry is a running provider instance.
type Entry struct {
	Spec     Spec
	Info     *providerv1.ProviderInfo
	Client   providerv1.ProviderServiceClient
	sidecar  *launcher.Sidecar
	healthy  bool
	healthMu sync.RWMutex
}

// Registry holds initialized providers for a stack.
type Registry struct {
	stackDir string
	entries  map[string]*Entry
	mu       sync.Mutex
}

// NewRegistry creates an empty provider registry.
func NewRegistry(stackDir string) *Registry {
	return &Registry{stackDir: stackDir, entries: make(map[string]*Entry)}
}

// Register adds a provider spec (does not call Init).
func (r *Registry) Register(spec Spec) error {
	name := strings.TrimSpace(spec.Name)
	if name == "" {
		return fmt.Errorf("provider name is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[name]; exists {
		return fmt.Errorf("duplicate provider %q", name)
	}
	r.entries[name] = &Entry{Spec: spec}
	return nil
}

// InitAll initializes every registered provider.
func (r *Registry) InitAll(ctx context.Context, dryRun bool) error {
	r.mu.Lock()
	names := make([]string, 0, len(r.entries))
	for name := range r.entries {
		names = append(names, name)
	}
	r.mu.Unlock()

	for _, name := range names {
		if err := r.initOne(ctx, name, dryRun); err != nil {
			return fmt.Errorf("provider %q: %w", name, err)
		}
	}
	return nil
}

func (r *Registry) initOne(ctx context.Context, name string, dryRun bool) error {
	r.mu.Lock()
	ent := r.entries[name]
	r.mu.Unlock()
	if ent == nil {
		return fmt.Errorf("not registered")
	}
	cfg := map[string]string{}
	for k, v := range ent.Spec.Config {
		cfg[k] = v
	}

	var client providerv1.ProviderServiceClient
	source := strings.TrimSpace(ent.Spec.Source)
	if source != "" {
		sc, err := launcher.Start(ctx, name, source, r.stackDir)
		if err != nil {
			return err
		}
		ent.sidecar = sc
		client = sc.Client
	} else {
		srv, err := builtin.NewServer(ent.Spec.Type, cfg)
		if err != nil {
			return err
		}
		client = newLocalClient(srv)
	}

	info, err := client.Init(ctx, &providerv1.InitRequest{Config: cfg, DryRun: dryRun})
	if err != nil {
		if ent.sidecar != nil {
			_ = ent.sidecar.Stop()
		}
		return err
	}
	if info.GetHealth() != nil && !info.GetHealth().GetHealthy() {
		return fmt.Errorf("init unhealthy: %s", info.GetHealth().GetDetail())
	}
	ent.Client = client
	ent.Info = info
	ent.setHealthy(true)
	return nil
}

// Close stops sidecars and releases resources.
func (r *Registry) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var first error
	for _, ent := range r.entries {
		if ent.sidecar != nil {
			if err := ent.sidecar.Stop(); err != nil && first == nil {
				first = err
			}
		}
	}
	_ = ctx
	return first
}

// CredentialRouter builds a credential router from SECRETS-capable providers.
func (r *Registry) CredentialRouter() *credential.Router {
	r.mu.Lock()
	defer r.mu.Unlock()
	var backends []credential.Broker
	for name, ent := range r.entries {
		if ent.Client == nil {
			continue
		}
		if !hasCapability(ent.Info, providerv1.Capability_CAPABILITY_SECRETS) {
			continue
		}
		backends = append(backends, &SecretsBroker{BrokerName: name, Client: ent.Client})
	}
	if len(backends) == 0 {
		return credential.NewRouter([]credential.Broker{&credential.EnvBroker{}}, &credential.EnvBroker{})
	}
	return credential.NewRouter(backends, &credential.EnvBroker{})
}

// StartHealthLoop polls provider health in the background.
func (r *Registry) StartHealthLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.pollHealth(ctx)
			}
		}
	}()
}

func (r *Registry) pollHealth(ctx context.Context) {
	r.mu.Lock()
	entries := make([]*Entry, 0, len(r.entries))
	for _, e := range r.entries {
		entries = append(entries, e)
	}
	r.mu.Unlock()
	for _, ent := range entries {
		if ent.Client == nil {
			continue
		}
		st, err := ent.Client.HealthCheck(ctx, &providerv1.HealthRequest{})
		healthy := err == nil && st != nil && st.GetHealthy()
		ent.setHealthy(healthy)
	}
}

func (e *Entry) setHealthy(v bool) {
	e.healthMu.Lock()
	e.healthy = v
	e.healthMu.Unlock()
}

// Healthy reports the last known health status.
func (e *Entry) Healthy() bool {
	e.healthMu.RLock()
	defer e.healthMu.RUnlock()
	return e.healthy
}

// AllHealthy reports whether every initialized provider passed the last health poll.
func (r *Registry) AllHealthy() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return true
	}
	for _, ent := range r.entries {
		if ent == nil || ent.Client == nil {
			continue
		}
		if !ent.Healthy() {
			return false
		}
	}
	return true
}

// UnhealthyDetail returns a short message for the first unhealthy provider.
func (r *Registry) UnhealthyDetail() string {
	if r == nil {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, ent := range r.entries {
		if ent != nil && ent.Client != nil && !ent.Healthy() {
			return fmt.Sprintf("provider %q is unhealthy", name)
		}
	}
	return ""
}

// AuditSinkClients returns clients with AUDIT_SINK capability.
func (r *Registry) AuditSinkClients() []providerv1.ProviderServiceClient {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []providerv1.ProviderServiceClient
	for _, ent := range r.entries {
		if ent == nil || ent.Client == nil {
			continue
		}
		if hasCapability(ent.Info, providerv1.Capability_CAPABILITY_AUDIT_SINK) {
			out = append(out, ent.Client)
		}
	}
	return out
}

// KMSClient returns the named provider when it exposes KMS capability.
func (r *Registry) KMSClient(name string) providerv1.ProviderServiceClient {
	if r == nil {
		return nil
	}
	name = strings.TrimSpace(name)
	r.mu.Lock()
	defer r.mu.Unlock()
	ent := r.entries[name]
	if ent == nil || ent.Client == nil {
		return nil
	}
	if !hasCapability(ent.Info, providerv1.Capability_CAPABILITY_KMS) {
		return nil
	}
	return ent.Client
}

// FirstKMSClient returns any KMS-capable provider.
func (r *Registry) FirstKMSClient() (string, providerv1.ProviderServiceClient) {
	if r == nil {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, ent := range r.entries {
		if ent == nil || ent.Client == nil {
			continue
		}
		if hasCapability(ent.Info, providerv1.Capability_CAPABILITY_KMS) {
			return name, ent.Client
		}
	}
	return "", nil
}

// CostEstimator returns the first COST-capable client, if any.
func (r *Registry) CostEstimator() providerv1.ProviderServiceClient {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ent := range r.entries {
		if ent == nil || ent.Client == nil {
			continue
		}
		if hasCapability(ent.Info, providerv1.Capability_CAPABILITY_COST) {
			return ent.Client
		}
	}
	return nil
}

func hasCapability(info *providerv1.ProviderInfo, cap providerv1.Capability) bool {
	if info == nil {
		return false
	}
	for _, c := range info.GetCapabilities() {
		if c == cap {
			return true
		}
	}
	return false
}
