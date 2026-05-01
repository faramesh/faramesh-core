// Package policy — custom condition operator registry.
//
// Allows Go functions to be registered as YAML condition operators,
// extending the policy language beyond built-in expressions.
//
// Registry rules:
//   - Operators must be deterministic (same input → same output)
//   - Operators must complete within a timeout (default 10ms)
//   - Operators must have no side effects
//   - DPR records which custom operators were evaluated and their results
//
// Example usage in YAML policy:
//
//	when: "risk_score(args.account_id) > 0.8"
//	when: "geo_fence(args.ip_address, 'us-east-1')"
package policy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// OperatorFunc is the signature for custom condition operators.
// It takes arbitrary arguments and returns a value for the expression engine.
type OperatorFunc func(args ...any) (any, error)

// OperatorMeta describes a registered operator's properties.
type OperatorMeta struct {
	Name          string        `json:"name"`
	Description   string        `json:"description"`
	Deterministic bool          `json:"deterministic"`
	Timeout       time.Duration `json:"timeout"`
	ArgTypes      []string      `json:"arg_types"` // for documentation
	ReturnType    string        `json:"return_type"`
	RegisteredAt  time.Time     `json:"registered_at"`
}

// OperatorResult records the evaluation of a custom operator for DPR.
type OperatorResult struct {
	Operator string        `json:"operator"`
	Args     []any         `json:"args"`
	Result   any           `json:"result"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration_ns"`
	Cached   bool          `json:"cached"`
}

// OperatorRegistry manages custom condition operators.
type OperatorRegistry struct {
	mu        sync.RWMutex
	operators map[string]OperatorFunc
	meta      map[string]OperatorMeta
	cache     map[string]cachedResult
	cacheTTL  time.Duration
}

type cachedResult struct {
	value    any
	cachedAt time.Time
}

// NewOperatorRegistry creates a new operator registry.
func NewOperatorRegistry() *OperatorRegistry {
	return &OperatorRegistry{
		operators: make(map[string]OperatorFunc),
		meta:      make(map[string]OperatorMeta),
		cache:     make(map[string]cachedResult),
		cacheTTL:  30 * time.Second,
	}
}

// Register adds a custom operator to the registry.
func (r *OperatorRegistry) Register(meta OperatorMeta, fn OperatorFunc) error {
	if meta.Name == "" {
		return fmt.Errorf("operator name is required")
	}
	if fn == nil {
		return fmt.Errorf("operator function is required")
	}
	if meta.Timeout == 0 {
		meta.Timeout = 10 * time.Millisecond
	}
	meta.RegisteredAt = time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.operators[meta.Name] = fn
	r.meta[meta.Name] = meta
	return nil
}

// Unregister removes an operator.
func (r *OperatorRegistry) Unregister(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.operators, name)
	delete(r.meta, name)
}

// Call invokes a custom operator with timeout enforcement.
func (r *OperatorRegistry) Call(name string, args ...any) (any, *OperatorResult, error) {
	r.mu.RLock()
	fn, ok := r.operators[name]
	meta := r.meta[name]
	r.mu.RUnlock()

	if !ok {
		return nil, nil, fmt.Errorf("unknown operator: %s", name)
	}

	result := &OperatorResult{
		Operator: name,
		Args:     args,
	}

	// Check cache for deterministic operators.
	if meta.Deterministic {
		cacheKey := operatorCacheKey(name, args)
		r.mu.RLock()
		if cached, ok := r.cache[cacheKey]; ok && time.Since(cached.cachedAt) < r.cacheTTL {
			r.mu.RUnlock()
			result.Result = cached.value
			result.Cached = true
			return cached.value, result, nil
		}
		r.mu.RUnlock()
	}

	// Execute with timeout.
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), meta.Timeout)
	defer cancel()

	type callResult struct {
		val any
		err error
	}
	ch := make(chan callResult, 1)
	go func() {
		val, err := fn(args...)
		ch <- callResult{val, err}
	}()

	select {
	case <-ctx.Done():
		result.Duration = time.Since(start)
		result.Error = "timeout"
		return nil, result, fmt.Errorf("operator %s timed out after %s", name, meta.Timeout)
	case cr := <-ch:
		result.Duration = time.Since(start)
		if cr.err != nil {
			result.Error = cr.err.Error()
			return nil, result, cr.err
		}
		result.Result = cr.val

		// Cache deterministic results.
		if meta.Deterministic {
			cacheKey := operatorCacheKey(name, args)
			r.mu.Lock()
			r.cache[cacheKey] = cachedResult{value: cr.val, cachedAt: time.Now()}
			r.mu.Unlock()
		}

		return cr.val, result, nil
	}
}

// InjectIntoEnv adds all registered operators as callable functions
// into the expression evaluation environment.
func (r *OperatorRegistry) InjectIntoEnv(env map[string]any, results *[]OperatorResult) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, fn := range r.operators {
		opName := name
		opFn := fn
		_ = opFn
		env[opName] = func(args ...any) any {
			val, result, err := r.Call(opName, args...)
			if results != nil && result != nil {
				*results = append(*results, *result)
			}
			if err != nil {
				// expr-lang coerces nil to "false" for bool conditions; surfacing the error
				// as a failed evaluation matches fail-closed semantics (see EXPR_RUNTIME_ERROR).
				panic(err)
			}
			return val
		}
	}
}

// List returns metadata for all registered operators.
func (r *OperatorRegistry) List() []OperatorMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	metas := make([]OperatorMeta, 0, len(r.meta))
	for _, m := range r.meta {
		metas = append(metas, m)
	}
	return metas
}

// RegistryHash returns a hash of the current registry state.
// Used for DPR's operator_registry_hash field.
func (r *OperatorRegistry) RegistryHash() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h := sha256.New()
	for name, meta := range r.meta {
		fmt.Fprintf(h, "%s:%v:%s|", name, meta.Deterministic, meta.RegisteredAt)
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:16]
}

// ClearCache removes all cached operator results.
func (r *OperatorRegistry) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]cachedResult)
}

func operatorCacheKey(name string, args []any) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s:", name)
	for _, a := range args {
		fmt.Fprintf(h, "%v|", a)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
