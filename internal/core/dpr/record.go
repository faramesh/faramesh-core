// Package dpr implements the Decision Provenance Record chain.
// Each record is cryptographically linked to the previous one, forming
// a tamper-evident audit log per agent. The WAL-first invariant means
// a durable record exists on disk before the decision is returned.
package dpr

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// SchemaVersion is the DPR schema version embedded in every record.
const SchemaVersion = "dpr/1.0"

const genesisDomainSeparator = "faramesh/dpr/genesis/v1"

// Record is a single entry in the Decision Provenance Record chain.
// DPR v1.0 — all fields are intentionally flat for efficient storage
// and simple JSON serialization into the WAL.
type Record struct {
	// ── Schema & Chain Integrity ──
	SchemaVersion  string `json:"schema_version"`
	FPLVersion     string `json:"fpl_version,omitempty"` // Faramesh Policy Language version
	CARVersion     string `json:"car_version,omitempty"` // Canonical Action Request version
	RecordID       string `json:"record_id"`
	PrevRecordHash string `json:"prev_record_hash"`
	RecordHash     string `json:"record_hash"`
	HMACSig        string `json:"hmac_signature,omitempty"` // HMAC-SHA256 for non-repudiation

	// ── Identity & Request ──
	AgentID            string `json:"agent_id"`
	SessionID          string `json:"session_id"`
	ToolID             string `json:"tool_id"`
	InterceptAdapter   string `json:"intercept_adapter"`
	ExecutionTimeoutMS int    `json:"execution_timeout_ms,omitempty"`
	PrincipalIDHash    string `json:"principal_id_hash,omitempty"` // HMAC pseudonymized (GDPR)

	// ── Decision ──
	Effect        string `json:"effect"`
	MatchedRuleID string `json:"matched_rule_id"`
	ReasonCode    string `json:"reason_code"`
	Reason        string `json:"reason"`
	DenialToken   string `json:"denial_token,omitempty"` // opaque token for operator lookup

	// ── Incident Classification ──
	IncidentCategory string `json:"incident_category,omitempty"` // e.g. "destructive_command", "data_exfiltration"
	IncidentSeverity string `json:"incident_severity,omitempty"` // "critical", "high", "medium", "low"

	// ── Policy Context ──
	PolicyVersion    string `json:"policy_version"`
	PolicySourceType string `json:"policy_source_type,omitempty"` // "file"|"string"|"url"|"database"|"push"
	PolicySourceID   string `json:"policy_source_id,omitempty"`   // URL, db key, or push message ID

	// ── Arguments ──
	ArgsStructuralSig string            `json:"args_structural_sig"`
	ArgProvenance     map[string]string `json:"arg_provenance,omitempty"`    // arg_path -> source_dpr_record_id
	SelectorSnapshot  map[string]any    `json:"selector_snapshot,omitempty"` // selector values that drove decision

	// ── Custom Operators ──
	CustomOperatorsEvaluated []string       `json:"custom_operators_evaluated,omitempty"`
	OperatorResults          map[string]any `json:"operator_results,omitempty"`
	OperatorRegistryHash     string         `json:"operator_registry_hash,omitempty"`

	// ── Workflow Phase ──
	WorkflowPhase         string `json:"workflow_phase,omitempty"`
	PhaseTransitionRecord bool   `json:"phase_transition_record,omitempty"`

	// ── Credential Broker ──
	CredentialBrokered bool   `json:"credential_brokered,omitempty"`
	CredentialSource   string `json:"credential_source,omitempty"`
	CredentialScope    string `json:"credential_scope,omitempty"`

	// ── Execution Environment ──
	ExecutionEnvironment string `json:"execution_environment,omitempty"` // "firecracker"|"gvisor"|"docker_sandbox"|"host"

	// ── Multi-Agent Linkage ──
	InvokedByAgentID     string `json:"invoked_by_agent_id,omitempty"`
	InvokedByDPRID       string `json:"invoked_by_dpr_record_id,omitempty"`
	InnerGovernanceDPRID string `json:"inner_governance_dpr_record_id,omitempty"`

	// ── Callbacks ──
	CallbacksFired []string `json:"callbacks_fired,omitempty"`
	CallbackErrors []string `json:"callback_errors,omitempty"`

	// ── Degraded Mode ──
	DegradedMode string `json:"degraded_mode,omitempty"` // "FULL"|"STATELESS"|"MINIMAL"|"EMERGENCY"

	// ── Batch Approval ──
	BatchApproval   bool     `json:"batch_approval,omitempty"`
	BatchSize       int      `json:"batch_size,omitempty"`
	BatchDPRIDs     []string `json:"batch_dpr_ids,omitempty"`
	ResolvedByBatch bool     `json:"resolved_by_batch,omitempty"`
	BatchApprovalID string   `json:"batch_approval_id,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// CanonicalBytes returns the deterministic byte representation of this record
// used to compute record_hash. The previous record's hash is included so the
// chain forms a linked list of SHA256 hashes.
func (r *Record) CanonicalBytes() []byte {
	// Exclude record_hash and hmac_signature from the canonical form.
	type canon struct {
		SchemaVersion      string    `json:"schema_version"`
		FPLVersion         string    `json:"fpl_version,omitempty"`
		CARVersion         string    `json:"car_version,omitempty"`
		RecordID           string    `json:"record_id"`
		PrevRecordHash     string    `json:"prev_record_hash"`
		AgentID            string    `json:"agent_id"`
		SessionID          string    `json:"session_id"`
		ToolID             string    `json:"tool_id"`
		InterceptAdapter   string    `json:"intercept_adapter"`
		ExecutionTimeoutMS int       `json:"execution_timeout_ms,omitempty"`
		PrincipalIDHash    string    `json:"principal_id_hash,omitempty"`
		Effect             string    `json:"effect"`
		MatchedRuleID      string    `json:"matched_rule_id"`
		ReasonCode         string    `json:"reason_code"`
		DenialToken        string    `json:"denial_token,omitempty"`
		IncidentCategory   string    `json:"incident_category,omitempty"`
		IncidentSeverity   string    `json:"incident_severity,omitempty"`
		PolicyVersion      string    `json:"policy_version"`
		ArgsStructuralSig  string    `json:"args_structural_sig"`
		WorkflowPhase      string    `json:"workflow_phase,omitempty"`
		CredentialBrokered bool      `json:"credential_brokered,omitempty"`
		DegradedMode       string    `json:"degraded_mode,omitempty"`
		CreatedAt          time.Time `json:"created_at"`
	}
	b, _ := json.Marshal(canon{
		SchemaVersion:      r.SchemaVersion,
		FPLVersion:         r.FPLVersion,
		CARVersion:         r.CARVersion,
		RecordID:           r.RecordID,
		PrevRecordHash:     r.PrevRecordHash,
		AgentID:            r.AgentID,
		SessionID:          r.SessionID,
		ToolID:             r.ToolID,
		InterceptAdapter:   r.InterceptAdapter,
		ExecutionTimeoutMS: r.ExecutionTimeoutMS,
		PrincipalIDHash:    r.PrincipalIDHash,
		Effect:             r.Effect,
		MatchedRuleID:      r.MatchedRuleID,
		ReasonCode:         r.ReasonCode,
		DenialToken:        r.DenialToken,
		IncidentCategory:   r.IncidentCategory,
		IncidentSeverity:   r.IncidentSeverity,
		PolicyVersion:      r.PolicyVersion,
		ArgsStructuralSig:  r.ArgsStructuralSig,
		WorkflowPhase:      r.WorkflowPhase,
		CredentialBrokered: r.CredentialBrokered,
		DegradedMode:       r.DegradedMode,
		CreatedAt:          r.CreatedAt,
	})
	return b
}

// ComputeHash computes and sets RecordHash from CanonicalBytes.
func (r *Record) ComputeHash() {
	r.RecordHash = fmt.Sprintf("%x", sha256.Sum256(r.CanonicalBytes()))
}

// GenesisPrevHash returns the deterministic chain-start marker hash for agentID.
// The first record in an agent chain must use this value as PrevRecordHash.
func GenesisPrevHash(agentID string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(genesisDomainSeparator+":"+agentID)))
}

// IsGenesisRecord reports whether rec starts an agent chain.
func IsGenesisRecord(rec *Record) bool {
	if rec == nil {
		return false
	}
	return rec.PrevRecordHash == GenesisPrevHash(rec.AgentID)
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
		sort.Strings(parts)
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
