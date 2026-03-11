// Package policy — programmatic policy loading from multiple sources.
//
// Supports loading policies from:
//   - String: inline YAML content
//   - File: local filesystem path
//   - URL: HTTP/HTTPS endpoint
//   - Callable: Go function returning policy bytes
//   - Environment: FARAMESH_POLICY env var
//
// All sources go through validation-before-activation: the new policy is
// compiled and validated against the current engine before swapping.
// DPR records policy_source_type for each loaded policy.
package policy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// SourceType identifies how a policy was loaded.
type SourceType string

const (
	SourceString   SourceType = "string"
	SourceFile     SourceType = "file"
	SourceURL      SourceType = "url"
	SourceCallable SourceType = "callable"
	SourceEnv      SourceType = "env"
)

// PolicySource represents a loaded policy with provenance metadata.
type PolicySource struct {
	// Doc is the parsed policy document.
	Doc *Doc

	// Engine is the compiled policy engine.
	Engine *Engine

	// Type is how the policy was loaded.
	Type SourceType `json:"type"`

	// Origin is the source location (file path, URL, etc.).
	Origin string `json:"origin"`

	// Hash is the SHA-256 hash of the raw policy content.
	Hash string `json:"hash"`

	// LoadedAt is when the policy was loaded.
	LoadedAt time.Time `json:"loaded_at"`

	// Version is the policy's declared version.
	Version string `json:"version"`
}

// PolicyLoader manages policy loading with validation.
type PolicyLoader struct {
	mu       sync.RWMutex
	current  *PolicySource
	previous *PolicySource
	client   *http.Client
}

// NewPolicyLoader creates a new policy loader.
func NewPolicyLoader() *PolicyLoader {
	return &PolicyLoader{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// FromString loads a policy from inline YAML content.
func (pl *PolicyLoader) FromString(content string) (*PolicySource, error) {
	return pl.load([]byte(content), SourceString, "inline")
}

// FromFile loads a policy from a local file.
func (pl *PolicyLoader) FromFile(path string) (*PolicySource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy file: %w", err)
	}
	return pl.load(data, SourceFile, path)
}

// FromURL loads a policy from an HTTP/HTTPS endpoint.
func (pl *PolicyLoader) FromURL(ctx context.Context, url string) (*PolicySource, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("policy URL request: %w", err)
	}
	req.Header.Set("Accept", "application/yaml, text/yaml, text/plain")
	resp, err := pl.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("policy URL fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy URL returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("policy URL read: %w", err)
	}
	return pl.load(data, SourceURL, url)
}

// FromCallable loads a policy from a Go function that returns YAML bytes.
func (pl *PolicyLoader) FromCallable(fn func() ([]byte, error), name string) (*PolicySource, error) {
	data, err := fn()
	if err != nil {
		return nil, fmt.Errorf("policy callable: %w", err)
	}
	return pl.load(data, SourceCallable, name)
}

// FromEnv loads a policy from the FARAMESH_POLICY environment variable.
func (pl *PolicyLoader) FromEnv() (*PolicySource, error) {
	content := os.Getenv("FARAMESH_POLICY")
	if content == "" {
		return nil, fmt.Errorf("FARAMESH_POLICY environment variable not set")
	}
	return pl.load([]byte(content), SourceEnv, "FARAMESH_POLICY")
}

// Activate makes a validated policy source the current active policy.
func (pl *PolicyLoader) Activate(src *PolicySource) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	pl.previous = pl.current
	pl.current = src
}

// Current returns the currently active policy source.
func (pl *PolicyLoader) Current() *PolicySource {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return pl.current
}

// Previous returns the previously active policy source.
func (pl *PolicyLoader) Previous() *PolicySource {
	pl.mu.RLock()
	defer pl.mu.RUnlock()
	return pl.previous
}

// Rollback reverts to the previous policy.
func (pl *PolicyLoader) Rollback() error {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	if pl.previous == nil {
		return fmt.Errorf("no previous policy to rollback to")
	}
	pl.current, pl.previous = pl.previous, pl.current
	return nil
}

// load parses, validates, and compiles a policy from raw bytes.
func (pl *PolicyLoader) load(data []byte, sourceType SourceType, origin string) (*PolicySource, error) {
	// Parse YAML.
	var doc Doc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("policy parse error: %w", err)
	}

	// Validate.
	if err := validateDoc(&doc); err != nil {
		return nil, fmt.Errorf("policy validation: %w", err)
	}

	// Compute hash.
	h := sha256.Sum256(data)
	hash := fmt.Sprintf("%x", h)

	// Compile engine.
	engine, err := NewEngine(&doc, hash[:16])
	if err != nil {
		return nil, fmt.Errorf("policy compile: %w", err)
	}

	return &PolicySource{
		Doc:      &doc,
		Engine:   engine,
		Type:     sourceType,
		Origin:   origin,
		Hash:     hash,
		LoadedAt: time.Now(),
		Version:  hash[:16],
	}, nil
}

// validateDoc performs structural validation on a policy document.
func validateDoc(doc *Doc) error {
	if doc.DefaultEffect == "" {
		return fmt.Errorf("default_effect is required")
	}
	effect := strings.ToLower(doc.DefaultEffect)
	if effect != "deny" && effect != "permit" && effect != "halt" && effect != "shadow" {
		return fmt.Errorf("invalid default_effect: %s", doc.DefaultEffect)
	}
	for i, rule := range doc.Rules {
		if rule.ID == "" {
			return fmt.Errorf("rule[%d] missing id", i)
		}
		if rule.Effect == "" {
			return fmt.Errorf("rule[%d] (%s) missing effect", i, rule.ID)
		}
	}
	return nil
}
