// Package policy — tool schema registry.
//
// ToolSchemaRegistry maintains declarations for all known tools,
// including their parameter schemas, reversibility, blast radius, and
// cost metadata. This enables:
//   - Policy-validate compatibility checks at policy load time
//   - Schema-aware argument validation before policy evaluation
//   - Policy-migrate command for schema evolution
package policy

import (
	"fmt"
	"strings"
	"sync"
)

// ToolSchemaEntry is a registered tool's schema declaration.
type ToolSchemaEntry struct {
	// ToolID is the tool identifier (e.g., "stripe/charge", "shell/exec").
	ToolID string `json:"tool_id" yaml:"tool_id"`

	// Description is human-readable tool description.
	Description string `json:"description,omitempty" yaml:"description"`

	// Params defines the expected parameters and their types.
	Params []ParamDecl `json:"params,omitempty" yaml:"params"`

	// Reversibility is "irreversible", "reversible", or "compensatable".
	Reversibility string `json:"reversibility" yaml:"reversibility"`

	// BlastRadius is "none", "local", "scoped", "system", or "external".
	BlastRadius string `json:"blast_radius" yaml:"blast_radius"`

	// CostPerCall is the estimated cost per invocation (USD).
	CostPerCall float64 `json:"cost_per_call,omitempty" yaml:"cost_per_call"`

	// Tags are arbitrary labels for policy matching.
	Tags []string `json:"tags,omitempty" yaml:"tags"`

	// Deprecated marks a tool as deprecated with a migration hint.
	Deprecated string `json:"deprecated,omitempty" yaml:"deprecated"`
}

// ParamDecl declares a tool parameter.
type ParamDecl struct {
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type" yaml:"type"` // string, number, boolean, object, array
	Required bool   `json:"required" yaml:"required"`
}

// ToolSchemaRegistry manages tool schema declarations.
type ToolSchemaRegistry struct {
	mu      sync.RWMutex
	schemas map[string]*ToolSchemaEntry // toolID → schema
}

// NewToolSchemaRegistry creates a new tool schema registry.
func NewToolSchemaRegistry() *ToolSchemaRegistry {
	return &ToolSchemaRegistry{
		schemas: make(map[string]*ToolSchemaEntry),
	}
}

// Register adds or updates a tool schema.
func (r *ToolSchemaRegistry) Register(entry ToolSchemaEntry) error {
	if entry.ToolID == "" {
		return fmt.Errorf("tool_id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schemas[entry.ToolID] = &entry
	return nil
}

// Get retrieves a tool's schema.
func (r *ToolSchemaRegistry) Get(toolID string) *ToolSchemaEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.schemas[toolID]
}

// ValidateArgs checks that the provided args match the tool's schema.
func (r *ToolSchemaRegistry) ValidateArgs(toolID string, args map[string]any) []string {
	r.mu.RLock()
	entry, ok := r.schemas[toolID]
	r.mu.RUnlock()

	if !ok {
		return nil // unknown tool = no schema validation
	}

	var errors []string
	for _, param := range entry.Params {
		val, exists := args[param.Name]
		if param.Required && !exists {
			errors = append(errors, fmt.Sprintf("missing required param: %s", param.Name))
			continue
		}
		if exists && !checkParamType(val, param.Type) {
			errors = append(errors, fmt.Sprintf("param %s: expected %s", param.Name, param.Type))
		}
	}
	return errors
}

// ValidatePolicy checks that all tools referenced in policy rules
// have registered schemas.
func (r *ToolSchemaRegistry) ValidatePolicy(doc *Doc) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var warnings []string
	for _, rule := range doc.Rules {
		pattern := rule.Match.Tool
		if pattern == "*" || pattern == "" {
			continue
		}
		// For non-glob patterns, check exact match.
		if !strings.ContainsAny(pattern, "*?") {
			if _, ok := r.schemas[pattern]; !ok {
				warnings = append(warnings, fmt.Sprintf("rule %s references unregistered tool: %s", rule.ID, pattern))
			}
		}
	}

	// Check for deprecated tools.
	for _, rule := range doc.Rules {
		pattern := rule.Match.Tool
		if entry, ok := r.schemas[pattern]; ok && entry.Deprecated != "" {
			warnings = append(warnings, fmt.Sprintf("rule %s uses deprecated tool %s: %s", rule.ID, pattern, entry.Deprecated))
		}
	}

	return warnings
}

// List returns all registered tool schemas.
func (r *ToolSchemaRegistry) List() []ToolSchemaEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]ToolSchemaEntry, 0, len(r.schemas))
	for _, e := range r.schemas {
		entries = append(entries, *e)
	}
	return entries
}

// ToolMetaForEval returns tool metadata for policy evaluation context.
func (r *ToolSchemaRegistry) ToolMetaForEval(toolID string) (reversibility, blastRadius string, tags []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.schemas[toolID]
	if !ok {
		return "", "", nil
	}
	return entry.Reversibility, entry.BlastRadius, entry.Tags
}

func checkParamType(val any, expectedType string) bool {
	switch expectedType {
	case "string":
		_, ok := val.(string)
		return ok
	case "number":
		switch val.(type) {
		case int, int64, float64:
			return true
		}
		return false
	case "boolean":
		_, ok := val.(bool)
		return ok
	case "object":
		_, ok := val.(map[string]any)
		return ok
	case "array":
		_, ok := val.([]any)
		return ok
	default:
		return true // unknown type = accept
	}
}
