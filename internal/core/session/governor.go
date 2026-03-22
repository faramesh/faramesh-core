package session

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

var (
	sessionWriteInjectionRe = regexp.MustCompile(`(?i)(\.\./|%2e%2e|<script|or\s+1\s*=\s*1|drop\s+table|\beval\s*\(|\bexec\s*\(|__import__)`)
	sessionWriteSecretRe    = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|password\s*=|api[_-]?key\s*=|bearer\s+[A-Za-z0-9\._\-]+|-----BEGIN [A-Z ]+ PRIVATE KEY-----)`)
)

// Governor enforces session-state write boundaries by agent namespace and
// blocks suspicious key/value payloads before state mutation.
type Governor struct {
	mu              sync.RWMutex
	agentNamespaces map[string]string
}

// NewGovernor creates a session state governor.
func NewGovernor() *Governor {
	return &Governor{
		agentNamespaces: make(map[string]string),
	}
}

// RegisterAgentNamespace ensures an agent has a write namespace.
// Namespace format is "<agentID>/".
func (g *Governor) RegisterAgentNamespace(agentID string) string {
	trimmed := strings.TrimSpace(agentID)
	if trimmed == "" {
		return ""
	}
	ns := trimmed + "/"
	g.mu.Lock()
	g.agentNamespaces[trimmed] = ns
	g.mu.Unlock()
	return ns
}

// CanWrite checks whether key/value are acceptable for this agent namespace.
// Returns allowed, reasonCode, reason.
func (g *Governor) CanWrite(agentID, key string, value any) (bool, string, string) {
	trimmedAgent := strings.TrimSpace(agentID)
	trimmedKey := strings.TrimSpace(key)
	if trimmedAgent == "" || trimmedKey == "" {
		return false, reasons.SessionStateWriteBlocked, "session state write requires non-empty agent_id and key"
	}

	g.mu.RLock()
	ns, ok := g.agentNamespaces[trimmedAgent]
	g.mu.RUnlock()
	if !ok {
		ns = g.RegisterAgentNamespace(trimmedAgent)
	}
	if !strings.HasPrefix(trimmedKey, ns) {
		return false, reasons.SessionStateNamespaceViolation,
			fmt.Sprintf("key %q must stay within namespace %q", trimmedKey, ns)
	}

	payload := fmt.Sprintf("%s=%v", trimmedKey, value)
	if sessionWriteInjectionRe.MatchString(payload) {
		return false, reasons.CodeExecutionInArgs, "session state write blocked: injection-like content detected"
	}
	if sessionWriteSecretRe.MatchString(payload) {
		return false, reasons.HighEntropySecret, "session state write blocked: secret-like content detected"
	}
	return true, "", ""
}
