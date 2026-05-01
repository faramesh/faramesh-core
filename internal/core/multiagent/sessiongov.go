// Package multiagent — session state governance.
//
// Governs reads and writes to shared session state in multi-agent scenarios.
// Provides:
//   - Namespace isolation: agent-scoped keys prevent cross-agent interference
//   - Write scanning: detect injection, PII, secrets before writes
//   - Read sanitization: redact sensitive data on cross-agent reads
//   - Schema validation: enforce key schemas declared in policy
package multiagent

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// StateNamespace represents an agent's isolated state scope.
type StateNamespace struct {
	AgentID string
	Prefix  string // "agent:{agentID}:"
}

// NewStateNamespace creates a namespace for an agent.
func NewStateNamespace(agentID string) StateNamespace {
	return StateNamespace{
		AgentID: agentID,
		Prefix:  "agent:" + agentID + ":",
	}
}

// ScopedKey returns the namespaced version of a key.
func (ns StateNamespace) ScopedKey(key string) string {
	if strings.HasPrefix(key, ns.Prefix) {
		return key // already scoped
	}
	return ns.Prefix + key
}

// IsOwned checks if a key belongs to this namespace.
func (ns StateNamespace) IsOwned(key string) bool {
	return strings.HasPrefix(key, ns.Prefix)
}

// SharedKey checks if a key is in the shared namespace.
func SharedKey(key string) bool {
	return strings.HasPrefix(key, "shared:")
}

// WriteScanResult records what was detected in a write operation.
type WriteScanResult struct {
	Key           string   `json:"key"`
	InjectionRisk bool     `json:"injection_risk"`
	PIIDetected   []string `json:"pii_detected,omitempty"`
	SecretsFound  bool     `json:"secrets_found"`
	Violations    []string `json:"violations,omitempty"`
}

// SessionGovernor manages session state access control.
type SessionGovernor struct {
	mu            sync.RWMutex
	namespaces    map[string]StateNamespace // agentID → namespace
	keySchemas    map[string]KeySchema
	piiPatterns   []*regexp.Regexp
	secretPattern *regexp.Regexp
}

// KeySchema defines the expected schema for a session state key.
type KeySchema struct {
	Key       string `yaml:"key"`
	Type      string `yaml:"type"` // string, number, boolean, object
	MaxLength int    `yaml:"max_length"`
	ReadOnly  bool   `yaml:"read_only"`
	SharedBy  string `yaml:"shared_by"` // which agent can write (empty = any)
}

// NewSessionGovernor creates a new session state governor.
func NewSessionGovernor() *SessionGovernor {
	return &SessionGovernor{
		namespaces: make(map[string]StateNamespace),
		keySchemas: make(map[string]KeySchema),
		piiPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`), // email
			regexp.MustCompile(`\b\d{3}[-.]?\d{2}[-.]?\d{4}\b`),                       // SSN-like
			regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),                         // credit card-like
			regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),              // IPv4
		},
		secretPattern: regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|private[_-]?key|credentials?)\s*[=:]\s*\S+`),
	}
}

// RegisterAgent creates a namespace for an agent.
func (sg *SessionGovernor) RegisterAgent(agentID string) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	sg.namespaces[agentID] = NewStateNamespace(agentID)
}

// RegisterKeySchema adds a key schema.
func (sg *SessionGovernor) RegisterKeySchema(schema KeySchema) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	sg.keySchemas[schema.Key] = schema
}

// CanWrite checks if an agent can write to a key and scans the value.
func (sg *SessionGovernor) CanWrite(agentID, key string, value any) (bool, *WriteScanResult) {
	sg.mu.RLock()
	ns, hasNS := sg.namespaces[agentID]
	schema, hasSchema := sg.keySchemas[key]
	sg.mu.RUnlock()

	result := &WriteScanResult{Key: key}

	// Check namespace ownership.
	if hasNS && !ns.IsOwned(key) && !SharedKey(key) {
		result.Violations = append(result.Violations,
			fmt.Sprintf("agent %s cannot write to key %s (not in namespace)", agentID, key))
		return false, result
	}

	// Check schema constraints.
	if hasSchema {
		if schema.ReadOnly {
			result.Violations = append(result.Violations, "key is read-only")
			return false, result
		}
		if schema.SharedBy != "" && schema.SharedBy != agentID {
			result.Violations = append(result.Violations,
				fmt.Sprintf("key owned by %s, not %s", schema.SharedBy, agentID))
			return false, result
		}
	}

	// Scan value for injection, PII, secrets.
	if strVal, ok := value.(string); ok {
		sg.scanValue(strVal, result)
	}

	return len(result.Violations) == 0 && !result.InjectionRisk && !result.SecretsFound, result
}

// CanRead checks if an agent can read a key.
func (sg *SessionGovernor) CanRead(agentID, key string) bool {
	sg.mu.RLock()
	ns, hasNS := sg.namespaces[agentID]
	sg.mu.RUnlock()

	if !hasNS {
		return true // no namespace tracking = unrestricted
	}

	// Agents can read their own keys and shared keys.
	return ns.IsOwned(key) || SharedKey(key)
}

// SanitizeForRead redacts sensitive data before cross-agent reads.
func (sg *SessionGovernor) SanitizeForRead(value string) string {
	sanitized := value
	for _, pattern := range sg.piiPatterns {
		sanitized = pattern.ReplaceAllString(sanitized, "[REDACTED]")
	}
	sanitized = sg.secretPattern.ReplaceAllString(sanitized, "[SECRET_REDACTED]")
	return sanitized
}

func (sg *SessionGovernor) scanValue(value string, result *WriteScanResult) {
	// Check for injection patterns.
	injectionPatterns := []string{
		"<script", "javascript:", "onerror=", "onload=",
		"'; DROP", "\" OR 1=1", "UNION SELECT",
	}
	lower := strings.ToLower(value)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			result.InjectionRisk = true
			result.Violations = append(result.Violations, "injection pattern detected")
			break
		}
	}

	// Check for PII.
	for _, pattern := range sg.piiPatterns {
		if matches := pattern.FindStringSubmatch(value); len(matches) > 0 {
			result.PIIDetected = append(result.PIIDetected, "pattern_match")
		}
	}

	// Check for secrets.
	if sg.secretPattern.MatchString(value) {
		result.SecretsFound = true
		result.Violations = append(result.Violations, "secrets detected in value")
	}
}
