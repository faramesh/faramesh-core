// Package observe — structured log schema with PII protection.
//
// Defines a mandatory field classification for governance logs.
// PII-classified fields are auto-redacted before emission.
package observe

import (
	"regexp"
	"time"
)

// FieldClass classifies a log field's sensitivity.
type FieldClass int

const (
	FieldPublic      FieldClass = iota // safe for any log destination
	FieldInternal                      // internal use, not for external
	FieldSensitive                     // requires access control on log storage
	FieldPII                           // auto-redacted in all log output
	FieldSecret                        // never logged under any circumstances
)

// LogField defines a field in the structured log schema.
type LogField struct {
	Name  string     `json:"name"`
	Class FieldClass `json:"class"`
}

// LogSchema defines the mandatory field classification for governance logs.
var LogSchema = []LogField{
	// Public fields — safe in all contexts.
	{Name: "timestamp", Class: FieldPublic},
	{Name: "level", Class: FieldPublic},
	{Name: "effect", Class: FieldPublic},
	{Name: "reason_code", Class: FieldPublic},
	{Name: "tool_id", Class: FieldPublic},
	{Name: "agent_id", Class: FieldPublic},
	{Name: "session_id", Class: FieldPublic},
	{Name: "dpr_record_id", Class: FieldPublic},
	{Name: "policy_version", Class: FieldPublic},
	{Name: "latency_us", Class: FieldPublic},

	// Internal fields — not exposed externally.
	{Name: "rule_id", Class: FieldInternal},
	{Name: "denial_token", Class: FieldInternal},
	{Name: "intercept_adapter", Class: FieldInternal},

	// Sensitive fields — access-controlled.
	{Name: "principal_id", Class: FieldSensitive},
	{Name: "delegation_chain", Class: FieldSensitive},

	// PII fields — auto-redacted.
	{Name: "principal_email", Class: FieldPII},
	{Name: "principal_name", Class: FieldPII},
	{Name: "args", Class: FieldPII},
	{Name: "message_history", Class: FieldPII},

	// Secret fields — never logged.
	{Name: "credential_value", Class: FieldSecret},
	{Name: "api_key", Class: FieldSecret},
	{Name: "session_token", Class: FieldSecret},
}

// schemaMap is pre-built for fast lookups.
var schemaMap = buildSchemaMap()

func buildSchemaMap() map[string]FieldClass {
	m := make(map[string]FieldClass, len(LogSchema))
	for _, f := range LogSchema {
		m[f.Name] = f.Class
	}
	return m
}

// ClassifyField returns the sensitivity class of a log field.
func ClassifyField(name string) FieldClass {
	if class, ok := schemaMap[name]; ok {
		return class
	}
	// Unknown fields default to Sensitive (safe default).
	return FieldSensitive
}

// LogEntry is a structured governance log entry.
type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Level     string            `json:"level"`
	Fields    map[string]string `json:"fields"`
}

// Sanitize produces a log entry with PII/Secret fields redacted.
func (e LogEntry) Sanitize() LogEntry {
	sanitized := LogEntry{
		Timestamp: e.Timestamp,
		Level:     e.Level,
		Fields:    make(map[string]string, len(e.Fields)),
	}
	for k, v := range e.Fields {
		class := ClassifyField(k)
		switch class {
		case FieldSecret:
			// Never include.
			continue
		case FieldPII:
			sanitized.Fields[k] = "[REDACTED]"
		default:
			sanitized.Fields[k] = v
		}
	}
	return sanitized
}

// SanitizeForExternalExport produces a log entry safe for external systems.
func (e LogEntry) SanitizeForExternalExport() LogEntry {
	sanitized := LogEntry{
		Timestamp: e.Timestamp,
		Level:     e.Level,
		Fields:    make(map[string]string, len(e.Fields)),
	}
	for k, v := range e.Fields {
		class := ClassifyField(k)
		switch class {
		case FieldSecret, FieldPII:
			continue
		case FieldSensitive, FieldInternal:
			sanitized.Fields[k] = "[REDACTED]"
		default:
			sanitized.Fields[k] = v
		}
	}
	return sanitized
}

// ValidateLogEntry checks that no Secret-class fields leak into a log output.
func ValidateLogEntry(fields map[string]string) []string {
	var violations []string
	for k := range fields {
		class := ClassifyField(k)
		if class == FieldSecret {
			violations = append(violations, "SECRET field in log output: "+k)
		}
	}
	return violations
}

// RedactString replaces PII patterns in a string.
func RedactString(s string) string {
	redacted := s
	for _, re := range piiPatterns {
		redacted = re.ReplaceAllString(redacted, "[REDACTED]")
	}
	for _, re := range secretPatterns {
		redacted = re.ReplaceAllString(redacted, "[SECRET_REDACTED]")
	}
	return redacted
}

var piiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b`),
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	regexp.MustCompile(`\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b`),
	regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`),
}
