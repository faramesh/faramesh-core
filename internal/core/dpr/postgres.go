package dpr

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// PGStore persists DPR records to PostgreSQL for production multi-node
// deployments. The PostgreSQL store provides:
//   - ACID transactions for record insertion
//   - Per-agent chain partitioning via agent_id index
//   - Rich querying (by time range, effect, incident category, etc.)
//   - Full-text search on reason fields
type PGStore struct {
	db *sql.DB
}

// OpenPGStore connects to PostgreSQL and runs migrations.
func OpenPGStore(dsn string) (*PGStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open PG DPR store: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := pgMigrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate PG DPR schema: %w", err)
	}
	return &PGStore{db: db}, nil
}

// Save writes a DPR record to PostgreSQL.
func (s *PGStore) Save(rec *Record) error {
	argProv := pgJSONOrNull(rec.ArgProvenance)
	selSnap := pgJSONOrNull(rec.SelectorSnapshot)
	custOps := pgJSONOrNull(rec.CustomOperatorsEvaluated)
	opRes := pgJSONOrNull(rec.OperatorResults)
	cbFired := pgJSONOrNull(rec.CallbacksFired)
	cbErrs := pgJSONOrNull(rec.CallbackErrors)
	batchIDs := pgJSONOrNull(rec.BatchDPRIDs)

	_, err := s.db.Exec(`
		INSERT INTO dpr_records (
			schema_version, fpl_version, car_version,
			record_id, prev_record_hash, record_hash, hmac_signature,
			agent_id, session_id, tool_id, intercept_adapter, execution_timeout_ms, principal_id_hash,
			effect, matched_rule_id, reason_code, reason, denial_token,
			incident_category, incident_severity,
			policy_version, policy_source_type, policy_source_id,
			args_structural_sig, arg_provenance, selector_snapshot,
			hardening_mode, network_host_hash, network_port, network_resolved_ip_hash, network_audit_bypass, inference_model_rewrite_applied,
			custom_operators_evaluated, operator_results, operator_registry_hash,
			workflow_phase, phase_transition_record,
			credential_brokered, credential_source, credential_scope,
			execution_environment,
			invoked_by_agent_id, invoked_by_dpr_id, inner_governance_dpr_id,
			callbacks_fired, callback_errors,
			degraded_mode,
			batch_approval, batch_size, batch_dpr_ids, resolved_by_batch, batch_approval_id,
			created_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
			$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,
			$39,$40,$41,$42,$43,$44,$45,$46,$47,$48,$49,$50,$51,$52,$53
		) ON CONFLICT (record_id) DO NOTHING`,
		rec.SchemaVersion, rec.FPLVersion, rec.CARVersion,
		rec.RecordID, rec.PrevRecordHash, rec.RecordHash, rec.HMACSig,
		rec.AgentID, rec.SessionID, rec.ToolID, rec.InterceptAdapter, rec.ExecutionTimeoutMS, rec.PrincipalIDHash,
		rec.Effect, rec.MatchedRuleID, rec.ReasonCode, rec.Reason, rec.DenialToken,
		rec.IncidentCategory, rec.IncidentSeverity,
		rec.PolicyVersion, rec.PolicySourceType, rec.PolicySourceID,
		rec.ArgsStructuralSig, argProv, selSnap,
		rec.HardeningMode, rec.NetworkHostHash, rec.NetworkPort, rec.NetworkResolvedIPHash, rec.NetworkAuditBypass, rec.InferenceModelRewriteApplied,
		custOps, opRes, rec.OperatorRegistryHash,
		rec.WorkflowPhase, rec.PhaseTransitionRecord,
		rec.CredentialBrokered, rec.CredentialSource, rec.CredentialScope,
		rec.ExecutionEnvironment,
		rec.InvokedByAgentID, rec.InvokedByDPRID, rec.InnerGovernanceDPRID,
		cbFired, cbErrs,
		rec.DegradedMode,
		rec.BatchApproval, rec.BatchSize, batchIDs, rec.ResolvedByBatch, rec.BatchApprovalID,
		rec.CreatedAt.UTC(),
	)
	return err
}

// ByID returns one DPR record by record_id.
func (s *PGStore) ByID(recordID string) (*Record, error) {
	rows, err := s.db.Query(`
		SELECT `+pgSelectCols+`
		FROM dpr_records WHERE record_id = $1 LIMIT 1`, recordID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	recs, err := pgScanRecords(rows)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, errors.New("record not found")
	}
	return recs[0], nil
}

// RecentByAgent returns the most recent records for an agent, newest first.
func (s *PGStore) RecentByAgent(agentID string, limit int) ([]*Record, error) {
	rows, err := s.db.Query(`
		SELECT `+pgSelectCols+`
		FROM dpr_records WHERE agent_id = $1
		ORDER BY created_at DESC LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return pgScanRecords(rows)
}

// Recent returns the most recent records across all agents, newest first.
func (s *PGStore) Recent(limit int) ([]*Record, error) {
	rows, err := s.db.Query(`
		SELECT `+pgSelectCols+`
		FROM dpr_records ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return pgScanRecords(rows)
}

// LastHash returns the most recent record_hash for an agent.
func (s *PGStore) LastHash(agentID string) (string, error) {
	var hash string
	err := s.db.QueryRow(
		`SELECT record_hash FROM dpr_records WHERE agent_id = $1
		 ORDER BY created_at DESC LIMIT 1`, agentID,
	).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

// KnownAgents returns all distinct agent IDs.
func (s *PGStore) KnownAgents() ([]string, error) {
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

// VerifyChain checks chain integrity for an agent.
func (s *PGStore) VerifyChain(agentID string) (*ChainBreak, error) {
	rows, err := s.db.Query(`
		SELECT `+pgSelectCols+`
		FROM dpr_records WHERE agent_id = $1
		ORDER BY created_at ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records, err := pgScanRecords(rows)
	if err != nil {
		return nil, err
	}

	for i, rec := range records {
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

// Close closes the database connection.
func (s *PGStore) Close() error { return s.db.Close() }

// ── internals ──

const pgSelectCols = `schema_version, fpl_version, car_version,
	record_id, prev_record_hash, record_hash, hmac_signature,
	agent_id, session_id, tool_id, intercept_adapter, execution_timeout_ms, principal_id_hash,
	effect, matched_rule_id, reason_code, reason, denial_token,
	incident_category, incident_severity,
	policy_version, policy_source_type, policy_source_id,
	args_structural_sig, arg_provenance, selector_snapshot,
	hardening_mode, network_host_hash, network_port, network_resolved_ip_hash, network_audit_bypass, inference_model_rewrite_applied,
	custom_operators_evaluated, operator_results, operator_registry_hash,
	workflow_phase, phase_transition_record,
	credential_brokered, credential_source, credential_scope,
	execution_environment,
	invoked_by_agent_id, invoked_by_dpr_id, inner_governance_dpr_id,
	callbacks_fired, callback_errors,
	degraded_mode,
	batch_approval, batch_size, batch_dpr_ids, resolved_by_batch, batch_approval_id,
	created_at`

func pgMigrate(db *sql.DB) error {
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS dpr_records (
		id                         BIGSERIAL PRIMARY KEY,
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
		arg_provenance             JSONB DEFAULT '{}',
		selector_snapshot          JSONB DEFAULT '{}',
		hardening_mode             TEXT DEFAULT '',
		network_host_hash          TEXT DEFAULT '',
		network_port               INTEGER DEFAULT 0,
		network_resolved_ip_hash   TEXT DEFAULT '',
		network_audit_bypass       BOOLEAN DEFAULT FALSE,
		inference_model_rewrite_applied BOOLEAN DEFAULT FALSE,
		custom_operators_evaluated JSONB DEFAULT '[]',
		operator_results           JSONB DEFAULT '{}',
		operator_registry_hash     TEXT DEFAULT '',
		workflow_phase             TEXT DEFAULT '',
		phase_transition_record    BOOLEAN DEFAULT FALSE,
		credential_brokered        BOOLEAN DEFAULT FALSE,
		credential_source          TEXT DEFAULT '',
		credential_scope           TEXT DEFAULT '',
		execution_environment      TEXT DEFAULT '',
		invoked_by_agent_id        TEXT DEFAULT '',
		invoked_by_dpr_id          TEXT DEFAULT '',
		inner_governance_dpr_id    TEXT DEFAULT '',
		callbacks_fired            JSONB DEFAULT '[]',
		callback_errors            JSONB DEFAULT '[]',
		degraded_mode              TEXT DEFAULT '',
		batch_approval             BOOLEAN DEFAULT FALSE,
		batch_size                 INTEGER DEFAULT 0,
		batch_dpr_ids              JSONB DEFAULT '[]',
		resolved_by_batch          BOOLEAN DEFAULT FALSE,
		batch_approval_id          TEXT DEFAULT '',
		created_at                 TIMESTAMPTZ NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_dpr_agent_time ON dpr_records(agent_id, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_effect ON dpr_records(effect, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_session ON dpr_records(session_id, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_incident ON dpr_records(incident_category, incident_severity);
	CREATE INDEX IF NOT EXISTS idx_dpr_record_hash ON dpr_records(record_hash);
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS execution_timeout_ms INTEGER DEFAULT 0;
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS hardening_mode TEXT DEFAULT '';
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS network_host_hash TEXT DEFAULT '';
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS network_port INTEGER DEFAULT 0;
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS network_resolved_ip_hash TEXT DEFAULT '';
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS network_audit_bypass BOOLEAN DEFAULT FALSE;
	ALTER TABLE dpr_records ADD COLUMN IF NOT EXISTS inference_model_rewrite_applied BOOLEAN DEFAULT FALSE;
	`)
	return err
}

func pgScanRecords(rows *sql.Rows) ([]*Record, error) {
	var records []*Record
	for rows.Next() {
		var r Record
		var createdAt time.Time
		var argProv, selSnap, custOps, opRes, cbFired, cbErrs, batchIDs sql.NullString
		if err := rows.Scan(
			&r.SchemaVersion, &r.FPLVersion, &r.CARVersion,
			&r.RecordID, &r.PrevRecordHash, &r.RecordHash, &r.HMACSig,
			&r.AgentID, &r.SessionID, &r.ToolID, &r.InterceptAdapter, &r.ExecutionTimeoutMS, &r.PrincipalIDHash,
			&r.Effect, &r.MatchedRuleID, &r.ReasonCode, &r.Reason, &r.DenialToken,
			&r.IncidentCategory, &r.IncidentSeverity,
			&r.PolicyVersion, &r.PolicySourceType, &r.PolicySourceID,
			&r.ArgsStructuralSig, &argProv, &selSnap,
			&r.HardeningMode, &r.NetworkHostHash, &r.NetworkPort, &r.NetworkResolvedIPHash, &r.NetworkAuditBypass, &r.InferenceModelRewriteApplied,
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
		r.CreatedAt = createdAt
		pgJSONUnmarshal(argProv, &r.ArgProvenance)
		pgJSONUnmarshal(selSnap, &r.SelectorSnapshot)
		pgJSONUnmarshal(custOps, &r.CustomOperatorsEvaluated)
		pgJSONUnmarshal(opRes, &r.OperatorResults)
		pgJSONUnmarshal(cbFired, &r.CallbacksFired)
		pgJSONUnmarshal(cbErrs, &r.CallbackErrors)
		pgJSONUnmarshal(batchIDs, &r.BatchDPRIDs)
		records = append(records, &r)
	}
	return records, rows.Err()
}

func pgJSONOrNull(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) == "null" || string(b) == "[]" || string(b) == "{}" {
		return nil
	}
	return string(b)
}

func pgJSONUnmarshal(ns sql.NullString, dst any) {
	if !ns.Valid || ns.String == "" {
		return
	}
	_ = json.Unmarshal([]byte(ns.String), dst)
}
