package standing

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// OpenRegistryStore opens (or creates) the standing-grants SQLite database at
// dbPath, migrates schema, loads active rows into memory, and returns a
// registry that persists Add / Revoke / TryConsume.
func OpenRegistryStore(dbPath string) (*Registry, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("standing store directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open standing SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := configureStandingSQLite(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure standing SQLite: %w", err)
	}
	if err := migrateStanding(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate standing schema: %w", err)
	}
	r := &Registry{db: db}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reloadFromDBLocked(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return r, nil
}

func configureStandingSQLite(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return err
		}
	}
	return nil
}

func migrateStanding(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS standing_grants (
	id TEXT PRIMARY KEY NOT NULL,
	agent_id TEXT NOT NULL,
	session_id TEXT NOT NULL DEFAULT '',
	tool_pattern TEXT NOT NULL,
	policy_version TEXT NOT NULL DEFAULT '',
	rule_id TEXT NOT NULL DEFAULT '',
	expires_at INTEGER NOT NULL,
	max_uses INTEGER NOT NULL,
	uses INTEGER NOT NULL,
	issued_by TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_standing_grants_expires ON standing_grants(expires_at);
`)
	return err
}

func (r *Registry) reloadFromDBLocked() error {
	if r.db == nil {
		return nil
	}
	now := time.Now().UTC().Unix()
	if _, err := r.db.Exec(`DELETE FROM standing_grants WHERE expires_at < ?`, now); err != nil {
		return fmt.Errorf("standing purge expired: %w", err)
	}
	rows, err := r.db.Query(`
SELECT id, agent_id, session_id, tool_pattern, policy_version, rule_id,
	expires_at, max_uses, uses, issued_by, created_at
FROM standing_grants`)
	if err != nil {
		return fmt.Errorf("standing load: %w", err)
	}
	defer rows.Close()

	var loaded []*Grant
	for rows.Next() {
		var (
			id, agentID, sessionID, toolPat, polVer, ruleID, issuedBy string
			expiresAt, createdAt, maxUses, uses                     int64
		)
		if err := rows.Scan(&id, &agentID, &sessionID, &toolPat, &polVer, &ruleID,
			&expiresAt, &maxUses, &uses, &issuedBy, &createdAt); err != nil {
			return fmt.Errorf("standing scan: %w", err)
		}
		g := &Grant{
			ID:            id,
			AgentID:       agentID,
			SessionID:     sessionID,
			ToolPattern:   toolPat,
			PolicyVersion: polVer,
			RuleID:        ruleID,
			ExpiresAt:     time.Unix(expiresAt, 0).UTC(),
			MaxUses:       int(maxUses),
			Uses:          int(uses),
			IssuedBy:      issuedBy,
			CreatedAt:     time.Unix(createdAt, 0).UTC(),
		}
		loaded = append(loaded, g)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("standing rows: %w", err)
	}
	r.grants = loaded
	return nil
}

func (r *Registry) persistInsertGrant(g *Grant) error {
	if r.db == nil || g == nil {
		return nil
	}
	_, err := r.db.Exec(`
INSERT INTO standing_grants (
	id, agent_id, session_id, tool_pattern, policy_version, rule_id,
	expires_at, max_uses, uses, issued_by, created_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		g.ID, g.AgentID, g.SessionID, g.ToolPattern, g.PolicyVersion, g.RuleID,
		g.ExpiresAt.Unix(), g.MaxUses, g.Uses, g.IssuedBy, g.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("standing insert: %w", err)
	}
	return nil
}

func (r *Registry) persistUpdateUses(id string, uses int) error {
	if r.db == nil {
		return nil
	}
	res, err := r.db.Exec(`UPDATE standing_grants SET uses = ? WHERE id = ?`, uses, id)
	if err != nil {
		return fmt.Errorf("standing update uses: %w", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return fmt.Errorf("standing update uses: expected 1 row, got %d", n)
	}
	return nil
}

func (r *Registry) persistDeleteGrant(id string, requireRow bool) error {
	if r.db == nil {
		return nil
	}
	res, err := r.db.Exec(`DELETE FROM standing_grants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("standing delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if requireRow && n != 1 {
		return fmt.Errorf("standing delete: expected 1 row, got %d", n)
	}
	if !requireRow && n > 1 {
		return fmt.Errorf("standing delete: unexpected row count %d", n)
	}
	return nil
}

// Close closes the SQLite handle. The registry must not be used afterward.
func (r *Registry) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.db.Close()
	r.db = nil
	return err
}
