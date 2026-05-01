package semantic

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Provider embeds text into a semantic vector space.
// Implementations may call a local model, a remote embedding API, or a mock.
type Provider interface {
	ID() string
	Embed(ctx context.Context, texts []string) ([][]float64, error)
}

// ProviderFunc adapts a function into a Provider.
type ProviderFunc struct {
	ProviderID string
	EmbedFunc  func(context.Context, []string) ([][]float64, error)
}

func (p ProviderFunc) ID() string { return p.ProviderID }

func (p ProviderFunc) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	if p.EmbedFunc == nil {
		return nil, errors.New("semantic provider embed function is nil")
	}
	return p.EmbedFunc(ctx, texts)
}

// CosineSimilarity returns the cosine similarity between two vectors.
func CosineSimilarity(a, b []float64) (float64, error) {
	if len(a) == 0 || len(b) == 0 {
		return 0, fmt.Errorf("cosine similarity requires non-empty vectors")
	}
	if len(a) != len(b) {
		return 0, fmt.Errorf("cosine similarity requires equal vector lengths: %d != %d", len(a), len(b))
	}
	var dot, magA, magB float64
	for i := range a {
		dot += a[i] * b[i]
		magA += a[i] * a[i]
		magB += b[i] * b[i]
	}
	if magA == 0 || magB == 0 {
		return 0, fmt.Errorf("cosine similarity requires non-zero vectors")
	}
	return dot / (math.Sqrt(magA) * math.Sqrt(magB)), nil
}

// CosineDistance returns 1 - cosine similarity.
func CosineDistance(a, b []float64) (float64, error) {
	sim, err := CosineSimilarity(a, b)
	if err != nil {
		return 0, err
	}
	return 1 - sim, nil
}

// Centroid returns the arithmetic mean vector for the supplied vectors.
func Centroid(vectors [][]float64) ([]float64, error) {
	if len(vectors) == 0 {
		return nil, fmt.Errorf("centroid requires at least one vector")
	}
	width := len(vectors[0])
	if width == 0 {
		return nil, fmt.Errorf("centroid requires non-empty vectors")
	}
	centroid := make([]float64, width)
	for i, vec := range vectors {
		if len(vec) != width {
			return nil, fmt.Errorf("centroid requires equal vector lengths: vector 0 has %d dims, vector %d has %d dims", width, i, len(vec))
		}
		for j, v := range vec {
			centroid[j] += v
		}
	}
	for i := range centroid {
		centroid[i] /= float64(len(vectors))
	}
	return centroid, nil
}

// CachingProvider wraps another provider with a bounded TTL cache.
// It is safe for concurrent use and returns deep copies of cached vectors.
type CachingProvider struct {
	base        Provider
	ttl         time.Duration
	maxEntries  int
	mu          sync.Mutex
	entries     map[string]cachedEmbedding
	order       []string
}

type cachedEmbedding struct {
	storedAt time.Time
	vecs     [][]float64
}

// NewCachingProvider creates a cache wrapper around a provider.
// ttl <= 0 disables expiry. maxEntries <= 0 disables eviction.
func NewCachingProvider(base Provider, ttl time.Duration, maxEntries int) *CachingProvider {
	return &CachingProvider{
		base:       base,
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]cachedEmbedding),
	}
}

func (c *CachingProvider) ID() string {
	if c == nil || c.base == nil {
		return ""
	}
	return c.base.ID()
}

func (c *CachingProvider) Embed(ctx context.Context, texts []string) ([][]float64, error) {
	if c == nil || c.base == nil {
		return nil, fmt.Errorf("caching provider base is nil")
	}
	key := cacheKey(c.base.ID(), texts)
	now := time.Now().UTC()

	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		if c.ttl <= 0 || now.Sub(entry.storedAt) <= c.ttl {
			vecs := cloneVectors(entry.vecs)
			c.mu.Unlock()
			return vecs, nil
		}
		delete(c.entries, key)
	}
	c.mu.Unlock()

	vecs, err := c.base.Embed(ctx, texts)
	if err != nil {
		return nil, err
	}
	clone := cloneVectors(vecs)

	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[string]cachedEmbedding)
	}
	c.entries[key] = cachedEmbedding{storedAt: now, vecs: cloneVectors(clone)}
	c.order = append(c.order, key)
	if c.maxEntries > 0 {
		for len(c.order) > c.maxEntries {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
	}
	c.mu.Unlock()

	return cloneVectors(clone), nil
}

func cacheKey(providerID string, texts []string) string {
	h := sha256.New()
	h.Write([]byte(providerID))
	for _, text := range texts {
		h.Write([]byte{0})
		h.Write([]byte(text))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func cloneVectors(vecs [][]float64) [][]float64 {
	out := make([][]float64, len(vecs))
	for i, vec := range vecs {
		if vec == nil {
			continue
		}
		out[i] = append([]float64(nil), vec...)
	}
	return out
}

// SortedKeys returns the cache keys in insertion order for testing and diagnostics.
func (c *CachingProvider) SortedKeys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]string(nil), c.order...)
	sort.Strings(out)
	return out
}
