// Package dpr implements the Decision Provenance Record chain.
// Each record is cryptographically linked to the previous one, forming
// a tamper-evident audit log per agent. The WAL-first invariant means
// a durable record exists on disk before the decision is returned.
package dpr

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the DPR schema version embedded in every record.
const SchemaVersion = "dpr/1.0"

// Record is a single entry in the Decision Provenance Record chain.
// All fields are intentionally flat for efficient SQLite storage and
// simple JSON serialization into the WAL.
type Record struct {
	SchemaVersion string `json:"schema_version"`
	RecordID      string `json:"record_id"`

	// Chain integrity
	PrevRecordHash string `json:"prev_record_hash"`
	RecordHash     string `json:"record_hash"`

	// Identity and request
	AgentID          string `json:"agent_id"`
	SessionID        string `json:"session_id"`
	ToolID           string `json:"tool_id"`
	InterceptAdapter string `json:"intercept_adapter"`

	// Decision
	Effect        string `json:"effect"`
	MatchedRuleID string `json:"matched_rule_id"`
	ReasonCode    string `json:"reason_code"`
	Reason        string `json:"reason"`

	// Policy context
	PolicyVersion string `json:"policy_version"`

	// Privacy-safe argument fingerprint: shape hash, never raw values.
	ArgsStructuralSig string `json:"args_structural_sig"`

	CreatedAt time.Time `json:"created_at"`
}

// CanonicalBytes returns the deterministic byte representation of this record
// used to compute record_hash. The previous record's hash is included so the
// chain forms a linked list of SHA256 hashes.
func (r *Record) CanonicalBytes() []byte {
	// Exclude record_hash itself from the canonical form.
	type canon struct {
		SchemaVersion    string    `json:"schema_version"`
		RecordID         string    `json:"record_id"`
		PrevRecordHash   string    `json:"prev_record_hash"`
		AgentID          string    `json:"agent_id"`
		SessionID        string    `json:"session_id"`
		ToolID           string    `json:"tool_id"`
		InterceptAdapter string    `json:"intercept_adapter"`
		Effect           string    `json:"effect"`
		MatchedRuleID    string    `json:"matched_rule_id"`
		ReasonCode       string    `json:"reason_code"`
		PolicyVersion    string    `json:"policy_version"`
		ArgsStructuralSig string   `json:"args_structural_sig"`
		CreatedAt        time.Time `json:"created_at"`
	}
	b, _ := json.Marshal(canon{
		SchemaVersion:     r.SchemaVersion,
		RecordID:          r.RecordID,
		PrevRecordHash:    r.PrevRecordHash,
		AgentID:           r.AgentID,
		SessionID:         r.SessionID,
		ToolID:            r.ToolID,
		InterceptAdapter:  r.InterceptAdapter,
		Effect:            r.Effect,
		MatchedRuleID:     r.MatchedRuleID,
		ReasonCode:        r.ReasonCode,
		PolicyVersion:     r.PolicyVersion,
		ArgsStructuralSig: r.ArgsStructuralSig,
		CreatedAt:         r.CreatedAt,
	})
	return b
}

// ComputeHash computes and sets RecordHash from CanonicalBytes.
func (r *Record) ComputeHash() {
	r.RecordHash = fmt.Sprintf("%x", sha256.Sum256(r.CanonicalBytes()))
}

// ArgsSignature computes a structural signature of the args map.
// Only the shape (key names and value types) is captured, never values.
func ArgsSignature(args map[string]any) string {
	if len(args) == 0 {
		return "{}"
	}
	sig := structuralSig(args, 0)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(sig)))[:16]
}

func structuralSig(v any, depth int) string {
	if depth > 5 {
		return "deep_object"
	}
	switch val := v.(type) {
	case map[string]any:
		parts := make([]string, 0, len(val))
		for k, child := range val {
			parts = append(parts, k+":"+structuralSig(child, depth+1))
		}
		return "{" + join(parts) + "}"
	case []any:
		if len(val) == 0 {
			return "[]"
		}
		return "[" + structuralSig(val[0], depth+1) + "]"
	case string:
		return "string"
	case float64, int, int64:
		return "number"
	case bool:
		return "bool"
	case nil:
		return "null"
	default:
		return "unknown"
	}
}

func join(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ","
		}
		result += p
	}
	return result
}
