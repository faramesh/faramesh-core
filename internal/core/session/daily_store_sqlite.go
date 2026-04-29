package session

import (
	"context"
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DailyCostStore persists per-agent daily USD totals.
type DailyCostStore interface {
	AddDailyCost(ctx context.Context, agentID, day string, amount float64) error
	GetDailyCost(ctx context.Context, agentID, day string) (float64, error)
	Close() error
}

// SQLiteDailyCostStore persists daily cost totals in SQLite.
type SQLiteDailyCostStore struct {
	db *sql.DB
}

// NewSQLiteDailyCostStore opens/creates a SQLite file store for daily costs.
func NewSQLiteDailyCostStore(dbPath string) (*SQLiteDailyCostStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite daily cost store: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS session_daily_costs (
		agent_id TEXT NOT NULL,
		day TEXT NOT NULL,
		cost_usd REAL NOT NULL DEFAULT 0,
		PRIMARY KEY (agent_id, day)
	)`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create session_daily_costs table: %w", err)
	}
	return &SQLiteDailyCostStore{db: db}, nil
}

func (s *SQLiteDailyCostStore) AddDailyCost(ctx context.Context, agentID, day string, amount float64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO session_daily_costs(agent_id, day, cost_usd)
VALUES (?, ?, ?)
ON CONFLICT(agent_id, day) DO UPDATE SET cost_usd = cost_usd + excluded.cost_usd`, agentID, day, amount)
	if err != nil {
		return fmt.Errorf("add daily cost: %w", err)
	}
	return nil
}

func (s *SQLiteDailyCostStore) GetDailyCost(ctx context.Context, agentID, day string) (float64, error) {
	var cost float64
	err := s.db.QueryRowContext(ctx, `SELECT cost_usd FROM session_daily_costs WHERE agent_id = ? AND day = ?`, agentID, day).Scan(&cost)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get daily cost: %w", err)
	}
	return cost, nil
}

func (s *SQLiteDailyCostStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
