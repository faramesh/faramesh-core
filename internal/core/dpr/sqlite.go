package dpr

import (
	"database/sql"
	"errors"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store persists DPR records to SQLite. Records are written asynchronously
// after the WAL fsync — the WAL is the durable store; SQLite is for queries.
type Store struct {
	db *sql.DB
}

// OpenStore opens (or creates) a SQLite DPR database at the given path.
func OpenStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create DPR store directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open DPR SQLite: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate DPR schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Save writes a DPR record to SQLite. Called asynchronously after WAL write.
func (s *Store) Save(rec *Record) error {
	// Serialize complex fields to JSON.
	argProv := jsonOrNull(rec.ArgProvenance)
	selSnap := jsonOrNull(rec.SelectorSnapshot)
	custOps := jsonOrNull(rec.CustomOperatorsEvaluated)
	opRes := jsonOrNull(rec.OperatorResults)
	cbFired := jsonOrNull(rec.CallbacksFired)
	cbErrs := jsonOrNull(rec.CallbackErrors)
	batchIDs := jsonOrNull(rec.BatchDPRIDs)

	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO dpr_records (
			schema_version, fpl_version, car_version,
			record_id, prev_record_hash, record_hash, hmac_signature,
			agent_id, session_id, tool_id, intercept_adapter, execution_timeout_ms, principal_id_hash,
			effect, matched_rule_id, reason_code, reason, denial_token,
			incident_category, incident_severity,
			policy_version, policy_source_type, policy_source_id,
			args_structural_sig, arg_provenance, selector_snapshot,
			custom_operators_evaluated, operator_results, operator_registry_hash,
			workflow_phase, phase_transition_record,
			credential_brokered, credential_source, credential_scope,
			execution_environment,
			invoked_by_agent_id, invoked_by_dpr_id, inner_governance_dpr_id,
			callbacks_fired, callback_errors,
			degraded_mode,
			batch_approval, batch_size, batch_dpr_ids, resolved_by_batch, batch_approval_id,
			created_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.SchemaVersion, rec.FPLVersion, rec.CARVersion,
		rec.RecordID, rec.PrevRecordHash, rec.RecordHash, rec.HMACSig,
		rec.AgentID, rec.SessionID, rec.ToolID, rec.InterceptAdapter, rec.ExecutionTimeoutMS, rec.PrincipalIDHash,
		rec.Effect, rec.MatchedRuleID, rec.ReasonCode, rec.Reason, rec.DenialToken,
		rec.IncidentCategory, rec.IncidentSeverity,
		rec.PolicyVersion, rec.PolicySourceType, rec.PolicySourceID,
		rec.ArgsStructuralSig, argProv, selSnap,
		custOps, opRes, rec.OperatorRegistryHash,
		rec.WorkflowPhase, rec.PhaseTransitionRecord,
		rec.CredentialBrokered, rec.CredentialSource, rec.CredentialScope,
		rec.ExecutionEnvironment,
		rec.InvokedByAgentID, rec.InvokedByDPRID, rec.InnerGovernanceDPRID,
		cbFired, cbErrs,
		rec.DegradedMode,
		rec.BatchApproval, rec.BatchSize, batchIDs, rec.ResolvedByBatch, rec.BatchApprovalID,
		rec.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

// ByID returns one DPR record by record_id.
func (s *Store) ByID(recordID string) (*Record, error) {
	rows, err := s.db.Query(
		`SELECT `+dprSelectCols+` FROM dpr_records WHERE record_id = ? LIMIT 1`, recordID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	recs, err := scanRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, errors.New("record not found")
	}
	return recs[0], nil
}

// dprSelectCols is the full column list for DPR v1.0 SELECTs.
const dprSelectCols = `schema_version, fpl_version, car_version,
	record_id, prev_record_hash, record_hash, hmac_signature,
	agent_id, session_id, tool_id, intercept_adapter, execution_timeout_ms, principal_id_hash,
	effect, matched_rule_id, reason_code, reason, denial_token,
	incident_category, incident_severity,
	policy_version, policy_source_type, policy_source_id,
	args_structural_sig, arg_provenance, selector_snapshot,
	custom_operators_evaluated, operator_results, operator_registry_hash,
	workflow_phase, phase_transition_record,
	credential_brokered, credential_source, credential_scope,
	execution_environment,
	invoked_by_agent_id, invoked_by_dpr_id, inner_governance_dpr_id,
	callbacks_fired, callback_errors,
	degraded_mode,
	batch_approval, batch_size, batch_dpr_ids, resolved_by_batch, batch_approval_id,
	created_at`

// RecentByAgent returns the most recent records for an agent, newest first.
func (s *Store) RecentByAgent(agentID string, limit int) ([]*Record, error) {
	rows, err := s.db.Query(
		`SELECT `+dprSelectCols+` FROM dpr_records WHERE agent_id = ?
		ORDER BY created_at DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// Recent returns the most recent records across all agents, newest first.
func (s *Store) Recent(limit int) ([]*Record, error) {
	rows, err := s.db.Query(
		`SELECT `+dprSelectCols+` FROM dpr_records ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// LastHash returns the most recent record_hash for an agent,
// used to seed the chain for the next record.
func (s *Store) LastHash(agentID string) (string, error) {
	var hash string
	err := s.db.QueryRow(
		`SELECT record_hash FROM dpr_records WHERE agent_id = ?
		 ORDER BY created_at DESC LIMIT 1`, agentID,
	).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

// KnownAgents returns all distinct agent IDs that have DPR records.
// Used to seed the in-memory chain hash cache on daemon restart.
func (s *Store) KnownAgents() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT agent_id FROM dpr_records`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		agents = append(agents, id)
	}
	return agents, rows.Err()
}

// Close closes the database connection.
func (s *Store) Close() error { return s.db.Close() }

// VerifyChain checks chain integrity for an agent's DPR records.
// Records are verified in chronological order (oldest first).
func (s *Store) VerifyChain(agentID string) (*ChainBreak, error) {
	rows, err := s.db.Query(
		`SELECT `+dprSelectCols+` FROM dpr_records WHERE agent_id = ?
		ORDER BY created_at ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records, err := scanRecords(rows)
	if err != nil {
		return nil, err
	}

	for i, rec := range records {
		// Recompute hash from canonical bytes.
		saved := rec.RecordHash
		rec.ComputeHash()
		if rec.RecordHash != saved {
			return &ChainBreak{
				RecordID:     rec.RecordID,
				ExpectedHash: rec.RecordHash,
				ActualHash:   saved,
				Position:     i,
			}, nil
		}
		// Verify chain link (skip genesis).
		if i > 0 && rec.PrevRecordHash != records[i-1].RecordHash {
			return &ChainBreak{
				RecordID:       rec.RecordID,
				PrevRecordHash: rec.PrevRecordHash,
				ExpectedHash:   records[i-1].RecordHash,
				Position:       i,
			}, nil
		}
	}
	return nil, nil
}

func migrate(db *sql.DB) error {
	// v1.0 full schema — used for new databases.
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS dpr_records (
		id                         INTEGER PRIMARY KEY AUTOINCREMENT,
		schema_version             TEXT NOT NULL DEFAULT 'dpr/1.0',
		fpl_version                TEXT DEFAULT '',
		car_version                TEXT DEFAULT '',
		record_id                  TEXT NOT NULL UNIQUE,
		prev_record_hash           TEXT NOT NULL,
		record_hash                TEXT NOT NULL,
		hmac_signature             TEXT DEFAULT '',
		agent_id                   TEXT NOT NULL,
		session_id                 TEXT,
		tool_id                    TEXT NOT NULL,
		intercept_adapter          TEXT,
		execution_timeout_ms       INTEGER DEFAULT 0,
		principal_id_hash          TEXT DEFAULT '',
		effect                     TEXT NOT NULL,
		matched_rule_id            TEXT,
		reason_code                TEXT,
		reason                     TEXT,
		denial_token               TEXT DEFAULT '',
		incident_category          TEXT DEFAULT '',
		incident_severity          TEXT DEFAULT '',
		policy_version             TEXT,
		policy_source_type         TEXT DEFAULT '',
		policy_source_id           TEXT DEFAULT '',
		args_structural_sig        TEXT,
		arg_provenance             TEXT DEFAULT '',
		selector_snapshot          TEXT DEFAULT '',
		custom_operators_evaluated TEXT DEFAULT '',
		operator_results           TEXT DEFAULT '',
		operator_registry_hash     TEXT DEFAULT '',
		workflow_phase             TEXT DEFAULT '',
		phase_transition_record    INTEGER DEFAULT 0,
		credential_brokered        INTEGER DEFAULT 0,
		credential_source          TEXT DEFAULT '',
		credential_scope           TEXT DEFAULT '',
		execution_environment      TEXT DEFAULT '',
		invoked_by_agent_id        TEXT DEFAULT '',
		invoked_by_dpr_id          TEXT DEFAULT '',
		inner_governance_dpr_id    TEXT DEFAULT '',
		callbacks_fired            TEXT DEFAULT '',
		callback_errors            TEXT DEFAULT '',
		degraded_mode              TEXT DEFAULT '',
		batch_approval             INTEGER DEFAULT 0,
		batch_size                 INTEGER DEFAULT 0,
		batch_dpr_ids              TEXT DEFAULT '',
		resolved_by_batch          INTEGER DEFAULT 0,
		batch_approval_id          TEXT DEFAULT '',
		created_at                 TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_dpr_agent_time ON dpr_records(agent_id, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_effect ON dpr_records(effect, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_session ON dpr_records(session_id, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_incident ON dpr_records(incident_category, incident_severity);
	`)
	if err != nil {
		return err
	}

	// Run incremental migrations for pre-v1.0 databases.
	_, _ = db.Exec(`ALTER TABLE dpr_records ADD COLUMN execution_timeout_ms INTEGER DEFAULT 0`)

	v1Cols := []string{
		"fpl_version", "car_version", "hmac_signature", "principal_id_hash",
		"denial_token", "incident_category", "incident_severity",
		"policy_source_type", "policy_source_id",
		"arg_provenance", "selector_snapshot",
		"custom_operators_evaluated", "operator_results", "operator_registry_hash",
		"workflow_phase", "phase_transition_record",
		"credential_brokered", "credential_source", "credential_scope",
		"execution_environment",
		"invoked_by_agent_id", "invoked_by_dpr_id", "inner_governance_dpr_id",
		"callbacks_fired", "callback_errors",
		"degraded_mode",
		"batch_approval", "batch_size", "batch_dpr_ids", "resolved_by_batch", "batch_approval_id",
	}
	for _, col := range v1Cols {
		defaultVal := "''"
		if col == "phase_transition_record" || col == "credential_brokered" ||
			col == "batch_approval" || col == "batch_size" || col == "resolved_by_batch" {
			defaultVal = "0"
		}
		// ALTER TABLE ADD COLUMN is a no-op if the column already exists in SQLite.
		_, _ = db.Exec(fmt.Sprintf(
			`ALTER TABLE dpr_records ADD COLUMN %s TEXT DEFAULT %s`, col, defaultVal))
	}
	return nil
}

func scanRecords(rows *sql.Rows) ([]*Record, error) {
	var records []*Record
	for rows.Next() {
		var r Record
		var createdAt string
		var argProv, selSnap, custOps, opRes, cbFired, cbErrs, batchIDs sql.NullString
		if err := rows.Scan(
			&r.SchemaVersion, &r.FPLVersion, &r.CARVersion,
			&r.RecordID, &r.PrevRecordHash, &r.RecordHash, &r.HMACSig,
			&r.AgentID, &r.SessionID, &r.ToolID, &r.InterceptAdapter, &r.ExecutionTimeoutMS, &r.PrincipalIDHash,
			&r.Effect, &r.MatchedRuleID, &r.ReasonCode, &r.Reason, &r.DenialToken,
			&r.IncidentCategory, &r.IncidentSeverity,
			&r.PolicyVersion, &r.PolicySourceType, &r.PolicySourceID,
			&r.ArgsStructuralSig, &argProv, &selSnap,
			&custOps, &opRes, &r.OperatorRegistryHash,
			&r.WorkflowPhase, &r.PhaseTransitionRecord,
			&r.CredentialBrokered, &r.CredentialSource, &r.CredentialScope,
			&r.ExecutionEnvironment,
			&r.InvokedByAgentID, &r.InvokedByDPRID, &r.InnerGovernanceDPRID,
			&cbFired, &cbErrs,
			&r.DegradedMode,
			&r.BatchApproval, &r.BatchSize, &batchIDs, &r.ResolvedByBatch, &r.BatchApprovalID,
			&createdAt,
		); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339Nano, createdAt)
		r.CreatedAt = t
		// Deserialize JSON columns.
		jsonUnmarshal(argProv, &r.ArgProvenance)
		jsonUnmarshal(selSnap, &r.SelectorSnapshot)
		jsonUnmarshal(custOps, &r.CustomOperatorsEvaluated)
		jsonUnmarshal(opRes, &r.OperatorResults)
		jsonUnmarshal(cbFired, &r.CallbacksFired)
		jsonUnmarshal(cbErrs, &r.CallbackErrors)
		jsonUnmarshal(batchIDs, &r.BatchDPRIDs)
		records = append(records, &r)
	}
	return records, rows.Err()
}

// jsonOrNull serializes v to JSON, returning "" for nil/empty values.
func jsonOrNull(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" || string(b) == "[]" || string(b) == "{}" {
		return ""
	}
	return string(b)
}

// jsonUnmarshal deserializes a NullString JSON value into dst.
func jsonUnmarshal(ns sql.NullString, dst any) {
	if !ns.Valid || ns.String == "" {
		return
	}
	_ = json.Unmarshal([]byte(ns.String), dst)
}
