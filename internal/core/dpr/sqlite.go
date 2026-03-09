package dpr

import (
	"database/sql"
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
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO dpr_records (
			schema_version, record_id, prev_record_hash, record_hash,
			agent_id, session_id, tool_id, intercept_adapter,
			effect, matched_rule_id, reason_code, reason,
			policy_version, args_structural_sig, created_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.SchemaVersion, rec.RecordID, rec.PrevRecordHash, rec.RecordHash,
		rec.AgentID, rec.SessionID, rec.ToolID, rec.InterceptAdapter,
		rec.Effect, rec.MatchedRuleID, rec.ReasonCode, rec.Reason,
		rec.PolicyVersion, rec.ArgsStructuralSig, rec.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

// RecentByAgent returns the most recent records for an agent, newest first.
func (s *Store) RecentByAgent(agentID string, limit int) ([]*Record, error) {
	rows, err := s.db.Query(`
		SELECT schema_version, record_id, prev_record_hash, record_hash,
		       agent_id, session_id, tool_id, intercept_adapter,
		       effect, matched_rule_id, reason_code, reason,
		       policy_version, args_structural_sig, created_at
		FROM dpr_records WHERE agent_id = ?
		ORDER BY created_at DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRecords(rows)
}

// Recent returns the most recent records across all agents, newest first.
func (s *Store) Recent(limit int) ([]*Record, error) {
	rows, err := s.db.Query(`
		SELECT schema_version, record_id, prev_record_hash, record_hash,
		       agent_id, session_id, tool_id, intercept_adapter,
		       effect, matched_rule_id, reason_code, reason,
		       policy_version, args_structural_sig, created_at
		FROM dpr_records ORDER BY created_at DESC LIMIT ?`, limit)
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

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS dpr_records (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		schema_version  TEXT NOT NULL DEFAULT 'dpr/1.0',
		record_id       TEXT NOT NULL UNIQUE,
		prev_record_hash TEXT NOT NULL,
		record_hash     TEXT NOT NULL,
		agent_id        TEXT NOT NULL,
		session_id      TEXT,
		tool_id         TEXT NOT NULL,
		intercept_adapter TEXT,
		effect          TEXT NOT NULL,
		matched_rule_id TEXT,
		reason_code     TEXT,
		reason          TEXT,
		policy_version  TEXT,
		args_structural_sig TEXT,
		created_at      TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_dpr_agent_time ON dpr_records(agent_id, created_at);
	CREATE INDEX IF NOT EXISTS idx_dpr_effect ON dpr_records(effect, created_at);
	`)
	return err
}

func scanRecords(rows *sql.Rows) ([]*Record, error) {
	var records []*Record
	for rows.Next() {
		var r Record
		var createdAt string
		if err := rows.Scan(
			&r.SchemaVersion, &r.RecordID, &r.PrevRecordHash, &r.RecordHash,
			&r.AgentID, &r.SessionID, &r.ToolID, &r.InterceptAdapter,
			&r.Effect, &r.MatchedRuleID, &r.ReasonCode, &r.Reason,
			&r.PolicyVersion, &r.ArgsStructuralSig, &createdAt,
		); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339Nano, createdAt)
		r.CreatedAt = t
		records = append(records, &r)
	}
	return records, rows.Err()
}
