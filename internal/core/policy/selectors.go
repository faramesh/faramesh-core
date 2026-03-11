// Package policy — custom data source selectors.
//
// Selectors provide external data to policy conditions via a namespaced
// lazy-evaluation model. Data is fetched on first access within a policy
// evaluation and cached for the remainder of the evaluation.
//
// Example usage in YAML policy:
//
//	when: "data.risk_score(args.account_id) > 0.8"
//	when: "data.feature_flag('new_billing') == true"
//	when: "data.account_state(principal.id).plan == 'enterprise'"
package policy

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SelectorFunc is a function that fetches external data.
// It receives the evaluation context and arbitrary arguments.
type SelectorFunc func(ctx context.Context, args ...any) (any, error)

// SelectorMeta describes a registered data selector.
type SelectorMeta struct {
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Timeout     time.Duration `json:"timeout"`
	CacheTTL    time.Duration `json:"cache_ttl"`
	Namespace   string        `json:"namespace"` // e.g. "data", "ext"
}

// SelectorSnapshot records selector evaluations for DPR.
type SelectorSnapshot struct {
	Selector string        `json:"selector"`
	Args     []any         `json:"args"`
	Result   any           `json:"result"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration_ns"`
	Cached   bool          `json:"cached"`
}

// SelectorRegistry manages custom data source selectors.
type SelectorRegistry struct {
	mu        sync.RWMutex
	selectors map[string]SelectorFunc
	meta      map[string]SelectorMeta
	cache     map[string]*selectorCacheEntry
}

type selectorCacheEntry struct {
	value    any
	cachedAt time.Time
	ttl      time.Duration
}

func (e *selectorCacheEntry) expired() bool {
	return time.Since(e.cachedAt) > e.ttl
}

// NewSelectorRegistry creates a new selector registry.
func NewSelectorRegistry() *SelectorRegistry {
	return &SelectorRegistry{
		selectors: make(map[string]SelectorFunc),
		meta:      make(map[string]SelectorMeta),
		cache:     make(map[string]*selectorCacheEntry),
	}
}

// Register adds a data source selector.
func (r *SelectorRegistry) Register(meta SelectorMeta, fn SelectorFunc) error {
	if meta.Name == "" {
		return fmt.Errorf("selector name is required")
	}
	if fn == nil {
		return fmt.Errorf("selector function is required")
	}
	if meta.Timeout == 0 {
		meta.Timeout = 50 * time.Millisecond
	}
	if meta.CacheTTL == 0 {
		meta.CacheTTL = 30 * time.Second
	}
	if meta.Namespace == "" {
		meta.Namespace = "data"
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.selectors[meta.Name] = fn
	r.meta[meta.Name] = meta
	return nil
}

// Fetch invokes a selector with caching and timeout enforcement.
func (r *SelectorRegistry) Fetch(name string, args ...any) (any, *SelectorSnapshot, error) {
	r.mu.RLock()
	fn, ok := r.selectors[name]
	meta := r.meta[name]
	r.mu.RUnlock()

	if !ok {
		return nil, nil, fmt.Errorf("unknown selector: %s", name)
	}

	snap := &SelectorSnapshot{
		Selector: name,
		Args:     args,
	}

	// Check cache.
	cacheKey := selectorCacheKey(name, args)
	r.mu.RLock()
	if entry, ok := r.cache[cacheKey]; ok && !entry.expired() {
		r.mu.RUnlock()
		snap.Result = entry.value
		snap.Cached = true
		return entry.value, snap, nil
	}
	r.mu.RUnlock()

	// Fetch with timeout.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), meta.Timeout)
	defer cancel()

	type fetchResult struct {
		val any
		err error
	}
	ch := make(chan fetchResult, 1)
	go func() {
		val, err := fn(ctx, args...)
		ch <- fetchResult{val, err}
	}()

	select {
	case <-ctx.Done():
		snap.Duration = time.Since(start)
		snap.Error = "timeout"
		return nil, snap, fmt.Errorf("selector %s timed out after %s", name, meta.Timeout)
	case fr := <-ch:
		snap.Duration = time.Since(start)
		if fr.err != nil {
			snap.Error = fr.err.Error()
			return nil, snap, fr.err
		}
		snap.Result = fr.val

		// Cache the result.
		r.mu.Lock()
		r.cache[cacheKey] = &selectorCacheEntry{
			value:    fr.val,
			cachedAt: time.Now(),
			ttl:      meta.CacheTTL,
		}
		r.mu.Unlock()

		return fr.val, snap, nil
	}
}

// InjectIntoEnv adds all registered selectors as callable functions
// under their namespace in the expression environment.
func (r *SelectorRegistry) InjectIntoEnv(env map[string]any, snapshots *[]SelectorSnapshot) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Group by namespace.
	namespaces := make(map[string]map[string]any)
	for name := range r.selectors {
		meta := r.meta[name]
		ns := meta.Namespace
		if namespaces[ns] == nil {
			namespaces[ns] = make(map[string]any)
		}
		sName := name
		namespaces[ns][sName] = func(args ...any) any {
			val, snap, err := r.Fetch(sName, args...)
			if snapshots != nil && snap != nil {
				*snapshots = append(*snapshots, *snap)
			}
			if err != nil {
				return nil
			}
			return val
		}
	}

	for ns, fns := range namespaces {
		env[ns] = fns
	}
}

// List returns metadata for all registered selectors.
func (r *SelectorRegistry) List() []SelectorMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	metas := make([]SelectorMeta, 0, len(r.meta))
	for _, m := range r.meta {
		metas = append(metas, m)
	}
	return metas
}

// ClearCache removes all cached selector results.
func (r *SelectorRegistry) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*selectorCacheEntry)
}

func selectorCacheKey(name string, args []any) string {
	key := name
	for _, a := range args {
		key += fmt.Sprintf("|%v", a)
	}
	return key
}
