package schedule

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

// SQLiteStore persists ScheduledExecutions in SQLite. Pragmas and migration
// pattern follow internal/core/dpr.
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLiteStore opens (or creates) the on-disk store at dbPath.
func OpenSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		return nil, errors.New("schedule: SQLite path is required")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("schedule: create store directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("schedule: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := configureScheduleSQLite(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schedule: configure sqlite: %w", err)
	}
	if err := migrateSchedule(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("schedule: migrate schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func configureScheduleSQLite(db *sql.DB) error {
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

func migrateSchedule(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS scheduled_executions (
		id              TEXT PRIMARY KEY,
		schema_version  TEXT NOT NULL DEFAULT 'schedule/1.0',
		agent_id        TEXT NOT NULL,
		tool            TEXT NOT NULL,
		args            TEXT NOT NULL DEFAULT '',
		policy          TEXT NOT NULL DEFAULT '',
		reeval          INTEGER NOT NULL DEFAULT 0,
		scheduled_at    INTEGER NOT NULL,
		created_at      INTEGER NOT NULL,
		status          TEXT NOT NULL,
		status_message  TEXT NOT NULL DEFAULT '',
		executed_at     INTEGER NOT NULL DEFAULT 0,
		approved_at     INTEGER NOT NULL DEFAULT 0,
		approved_by     TEXT NOT NULL DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_scheduled_agent     ON scheduled_executions(agent_id);
	CREATE INDEX IF NOT EXISTS idx_scheduled_status    ON scheduled_executions(status);
	CREATE INDEX IF NOT EXISTS idx_scheduled_scheduled_at ON scheduled_executions(scheduled_at);
	CREATE INDEX IF NOT EXISTS idx_scheduled_executed_at  ON scheduled_executions(executed_at);
	`)
	return err
}

func (s *SQLiteStore) Insert(e ScheduledExecution) error {
	if e.ID == "" {
		return fmt.Errorf("schedule: insert requires non-empty id")
	}
	_, err := s.db.ExecContext(context.Background(), `
	INSERT INTO scheduled_executions
		(id, agent_id, tool, args, policy, reeval, scheduled_at, created_at, status,
		 status_message, executed_at, approved_at, approved_by)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.AgentID, e.Tool, e.Args, e.Policy, boolToInt(e.Reeval),
		e.ScheduledAt.UTC().Unix(), e.CreatedAt.UTC().Unix(), string(e.Status),
		e.StatusMessage, unixOrZero(e.ExecutedAt), unixOrZero(e.ApprovedAt), e.ApprovedBy,
	)
	if err != nil && isUniqueViolation(err) {
		return ErrDuplicateID
	}
	if err != nil {
		return fmt.Errorf("schedule: insert: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetByID(id string) (ScheduledExecution, bool) {
	row := s.db.QueryRowContext(context.Background(), selectColsAndFrom+` WHERE id = ?`, id)
	e, err := scanExecution(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ScheduledExecution{}, false
	}
	if err != nil {
		return ScheduledExecution{}, false
	}
	return e, true
}

func (s *SQLiteStore) ListByAgent(agentID string) []ScheduledExecution {
	rows, err := s.db.QueryContext(context.Background(),
		selectColsAndFrom+` WHERE agent_id = ? ORDER BY scheduled_at ASC`, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	return collectExecutions(rows)
}

func (s *SQLiteStore) ListByStatus(status Status) []ScheduledExecution {
	rows, err := s.db.QueryContext(context.Background(),
		selectColsAndFrom+` WHERE status = ? ORDER BY scheduled_at ASC`, string(status))
	if err != nil {
		return nil
	}
	defer rows.Close()
	return collectExecutions(rows)
}

func (s *SQLiteStore) ListExecutedSince(since time.Time) []ScheduledExecution {
	rows, err := s.db.QueryContext(context.Background(),
		selectColsAndFrom+` WHERE executed_at > 0 AND executed_at >= ? ORDER BY executed_at DESC`,
		since.UTC().Unix())
	if err != nil {
		return nil
	}
	defer rows.Close()
	return collectExecutions(rows)
}

func (s *SQLiteStore) Update(e ScheduledExecution) error {
	if e.ID == "" {
		return fmt.Errorf("schedule: update requires non-empty id")
	}
	res, err := s.db.ExecContext(context.Background(), `
	UPDATE scheduled_executions SET
		agent_id=?, tool=?, args=?, policy=?, reeval=?,
		scheduled_at=?, status=?, status_message=?,
		executed_at=?, approved_at=?, approved_by=?
	WHERE id = ?`,
		e.AgentID, e.Tool, e.Args, e.Policy, boolToInt(e.Reeval),
		e.ScheduledAt.UTC().Unix(), string(e.Status), e.StatusMessage,
		unixOrZero(e.ExecutedAt), unixOrZero(e.ApprovedAt), e.ApprovedBy,
		e.ID,
	)
	if err != nil {
		return fmt.Errorf("schedule: update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("schedule: update rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const selectColsAndFrom = `SELECT id, agent_id, tool, args, policy, reeval,
	scheduled_at, created_at, status, status_message,
	executed_at, approved_at, approved_by
	FROM scheduled_executions`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanExecution(r rowScanner) (ScheduledExecution, error) {
	var (
		e                                         ScheduledExecution
		reevalI                                   int
		schedAt, createdAt, executedAt, approveAt int64
		status                                    string
	)
	err := r.Scan(
		&e.ID, &e.AgentID, &e.Tool, &e.Args, &e.Policy, &reevalI,
		&schedAt, &createdAt, &status, &e.StatusMessage,
		&executedAt, &approveAt, &e.ApprovedBy,
	)
	if err != nil {
		return ScheduledExecution{}, err
	}
	e.Reeval = reevalI != 0
	e.ScheduledAt = time.Unix(schedAt, 0).UTC()
	e.CreatedAt = time.Unix(createdAt, 0).UTC()
	e.Status = Status(status)
	if executedAt > 0 {
		e.ExecutedAt = time.Unix(executedAt, 0).UTC()
	}
	if approveAt > 0 {
		e.ApprovedAt = time.Unix(approveAt, 0).UTC()
	}
	return e, nil
}

func collectExecutions(rows *sql.Rows) []ScheduledExecution {
	var out []ScheduledExecution
	for rows.Next() {
		e, err := scanExecution(rows)
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().Unix()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return containsCI(msg, "UNIQUE constraint failed") || containsCI(msg, "constraint failed: UNIQUE")
}

func containsCI(haystack, needle string) bool {
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
