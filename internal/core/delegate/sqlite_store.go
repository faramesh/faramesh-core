package delegate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore persists delegation grants in a SQLite database. Schema and
// pragmas follow the project's existing pattern (see internal/core/dpr).
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens (or creates) a SQLite-backed delegation store at
// dbPath. Parent directories are created if missing.
func OpenSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		return nil, errors.New("delegate: SQLite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("delegate: create store directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("delegate: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := configureDelegateSQLite(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("delegate: configure sqlite: %w", err)
	}
	if err := migrateDelegate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("delegate: migrate schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

// Close releases the underlying database handle.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func configureDelegateSQLite(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA foreign_keys = ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("apply %q: %w", p, err)
		}
	}
	return nil
}

// migrateDelegate creates the v1 schema if missing. The schema_version
// column is reserved for forward-compatible additive migrations; older
// rows default to 'delegate/1.0'.
func migrateDelegate(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS delegate_grants (
		token           TEXT PRIMARY KEY,
		schema_version  TEXT NOT NULL DEFAULT 'delegate/1.0',
		from_agent      TEXT NOT NULL,
		to_agent        TEXT NOT NULL,
		scope           TEXT NOT NULL DEFAULT '*',
		ceiling         TEXT NOT NULL DEFAULT '',
		issued_at       INTEGER NOT NULL,
		expires_at      INTEGER NOT NULL,
		chain_depth     INTEGER NOT NULL DEFAULT 1,
		active          INTEGER NOT NULL DEFAULT 1
	);

	CREATE INDEX IF NOT EXISTS idx_delegate_grants_from ON delegate_grants(from_agent);
	CREATE INDEX IF NOT EXISTS idx_delegate_grants_to   ON delegate_grants(to_agent);
	CREATE INDEX IF NOT EXISTS idx_delegate_grants_active_to ON delegate_grants(active, to_agent);
	`)
	return err
}

// Insert persists a new grant. Duplicate tokens are rejected.
func (s *SQLiteStore) Insert(g Grant) error {
	if g.Token == "" {
		return fmt.Errorf("delegate: insert requires non-empty token")
	}
	_, err := s.db.ExecContext(context.Background(), `
	INSERT INTO delegate_grants
		(token, from_agent, to_agent, scope, ceiling, issued_at, expires_at, chain_depth, active)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.Token, g.FromAgent, g.ToAgent, g.Scope, g.Ceiling,
		g.IssuedAt.UTC().Unix(), g.ExpiresAt.UTC().Unix(),
		g.ChainDepth, boolToInt(g.Active),
	)
	if err != nil && isUniqueViolation(err) {
		return ErrDuplicateToken
	}
	if err != nil {
		return fmt.Errorf("delegate: insert: %w", err)
	}
	return nil
}

// GetByToken loads a grant by its token, if present.
func (s *SQLiteStore) GetByToken(token string) (Grant, bool) {
	row := s.db.QueryRowContext(context.Background(), `
	SELECT token, from_agent, to_agent, scope, ceiling, issued_at, expires_at, chain_depth, active
	FROM delegate_grants WHERE token = ?`, token)
	g, err := scanGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, false
	}
	if err != nil {
		return Grant{}, false
	}
	return g, true
}

// ListByAgent returns grants where agentID is on either side, newest-first.
func (s *SQLiteStore) ListByAgent(agentID string) []Grant {
	rows, err := s.db.QueryContext(context.Background(), `
	SELECT token, from_agent, to_agent, scope, ceiling, issued_at, expires_at, chain_depth, active
	FROM delegate_grants
	WHERE from_agent = ? OR to_agent = ?
	ORDER BY issued_at DESC`, agentID, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return collectGrants(rows)
}

// ListInbound returns active grants where agentID is the to-agent.
func (s *SQLiteStore) ListInbound(agentID string) []Grant {
	rows, err := s.db.QueryContext(context.Background(), `
	SELECT token, from_agent, to_agent, scope, ceiling, issued_at, expires_at, chain_depth, active
	FROM delegate_grants
	WHERE to_agent = ? AND active = 1
	ORDER BY issued_at DESC`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return collectGrants(rows)
}

// Revoke deactivates all active grants from→to and returns the row count.
func (s *SQLiteStore) Revoke(from, to string) (int, error) {
	res, err := s.db.ExecContext(context.Background(), `
	UPDATE delegate_grants SET active = 0
	WHERE from_agent = ? AND to_agent = ? AND active = 1`, from, to)
	if err != nil {
		return 0, fmt.Errorf("delegate: revoke: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("delegate: revoke rows affected: %w", err)
	}
	return int(n), nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanGrant(r rowScanner) (Grant, error) {
	var (
		g                   Grant
		issuedUnix, expUnix int64
		activeI             int
	)
	err := r.Scan(&g.Token, &g.FromAgent, &g.ToAgent, &g.Scope, &g.Ceiling,
		&issuedUnix, &expUnix, &g.ChainDepth, &activeI)
	if err != nil {
		return Grant{}, err
	}
	g.IssuedAt = time.Unix(issuedUnix, 0).UTC()
	g.ExpiresAt = time.Unix(expUnix, 0).UTC()
	g.Active = activeI != 0
	return g, nil
}

func collectGrants(rows *sql.Rows) []Grant {
	var out []Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			continue
		}
		out = append(out, g)
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint
// violation. modernc.org/sqlite returns errors whose Error() string
// contains "UNIQUE constraint failed".
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{"UNIQUE constraint failed", "constraint failed: UNIQUE"} {
		if containsFold(msg, marker) {
			return true
		}
	}
	return false
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a := haystack[i+j]
			b := needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
