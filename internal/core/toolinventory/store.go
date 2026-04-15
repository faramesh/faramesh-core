package toolinventory

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	_ "modernc.org/sqlite"
)

// Entry is a persisted observation summary for a governed tool.
type Entry struct {
	ToolID            string         `json:"tool_id"`
	FirstSeen         time.Time      `json:"first_seen"`
	LastSeen          time.Time      `json:"last_seen"`
	TotalInvocations  int64          `json:"total_invocations"`
	Effects           map[string]int `json:"effects,omitempty"`
	InterceptAdapters []string       `json:"intercept_adapters,omitempty"`
	CoverageTier      string         `json:"coverage_tier,omitempty"`
	PolicyRuleIDs     []string       `json:"policy_rule_ids,omitempty"`
}

// Observation is one incremental runtime event for a tool.
type Observation struct {
	ToolID           string
	Effect           string
	InterceptAdapter string
	PolicyRuleID     string
	CoverageTier     string
	Timestamp        time.Time
}

// Store persists observed tool inventory into SQLite.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// OpenStore opens or creates a tool inventory store at dbPath.
func OpenStore(dbPath string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("create tool inventory directory: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open tool inventory sqlite: %w", err)
	}
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate tool inventory schema: %w", err)
	}
	return &Store{db: db}, nil
}

// RecordObservation updates the observed state for one tool invocation.
func (s *Store) RecordObservation(obs Observation) error {
	if s == nil || stringsTrim(obs.ToolID) == "" {
		return nil
	}
	if obs.Timestamp.IsZero() {
		obs.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.byToolLocked(obs.ToolID)
	if err != nil {
		return err
	}
	if entry == nil {
		entry = &Entry{
			ToolID:            obs.ToolID,
			FirstSeen:         obs.Timestamp.UTC(),
			LastSeen:          obs.Timestamp.UTC(),
			Effects:           map[string]int{},
			InterceptAdapters: []string{},
			PolicyRuleIDs:     []string{},
		}
	}
	if entry.FirstSeen.IsZero() || obs.Timestamp.Before(entry.FirstSeen) {
		entry.FirstSeen = obs.Timestamp.UTC()
	}
	if entry.LastSeen.IsZero() || obs.Timestamp.After(entry.LastSeen) {
		entry.LastSeen = obs.Timestamp.UTC()
	}
	entry.TotalInvocations++
	if stringsTrim(obs.Effect) != "" {
		entry.Effects[obs.Effect]++
	}
	if adapter := stringsTrim(obs.InterceptAdapter); adapter != "" && !slices.Contains(entry.InterceptAdapters, adapter) {
		entry.InterceptAdapters = append(entry.InterceptAdapters, adapter)
		slices.Sort(entry.InterceptAdapters)
	}
	if ruleID := stringsTrim(obs.PolicyRuleID); ruleID != "" && !slices.Contains(entry.PolicyRuleIDs, ruleID) {
		entry.PolicyRuleIDs = append(entry.PolicyRuleIDs, ruleID)
		slices.Sort(entry.PolicyRuleIDs)
	}
	if tier := stringsTrim(obs.CoverageTier); tier != "" {
		entry.CoverageTier = tier
	}

	effectsJSON, _ := json.Marshal(entry.Effects)
	adaptersJSON, _ := json.Marshal(entry.InterceptAdapters)
	ruleIDsJSON, _ := json.Marshal(entry.PolicyRuleIDs)

	_, err = s.db.Exec(`
		INSERT INTO tool_inventory (
			tool_id, first_seen, last_seen, total_invocations, effects, intercept_adapters, coverage_tier, policy_rule_ids
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tool_id) DO UPDATE SET
			first_seen = excluded.first_seen,
			last_seen = excluded.last_seen,
			total_invocations = excluded.total_invocations,
			effects = excluded.effects,
			intercept_adapters = excluded.intercept_adapters,
			coverage_tier = excluded.coverage_tier,
			policy_rule_ids = excluded.policy_rule_ids
	`,
		entry.ToolID,
		entry.FirstSeen.UTC().Format(time.RFC3339Nano),
		entry.LastSeen.UTC().Format(time.RFC3339Nano),
		entry.TotalInvocations,
		string(effectsJSON),
		string(adaptersJSON),
		entry.CoverageTier,
		string(ruleIDsJSON),
	)
	return err
}

// SeedFromDPRRecords builds inventory state from historical DPR records.
func (s *Store) SeedFromDPRRecords(records []*dpr.Record) error {
	for _, rec := range records {
		if rec == nil || stringsTrim(rec.ToolID) == "" {
			continue
		}
		if err := s.RecordObservation(Observation{
			ToolID:           rec.ToolID,
			Effect:           rec.Effect,
			InterceptAdapter: rec.InterceptAdapter,
			PolicyRuleID:     rec.MatchedRuleID,
			Timestamp:        rec.CreatedAt,
		}); err != nil {
			return err
		}
	}
	return nil
}

// All returns all inventory entries ordered by last seen descending.
func (s *Store) All() ([]Entry, error) {
	rows, err := s.db.Query(`
		SELECT tool_id, first_seen, last_seen, total_invocations, effects, intercept_adapters, coverage_tier, policy_rule_ids
		FROM tool_inventory
		ORDER BY last_seen DESC, tool_id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *entry)
	}
	return entries, rows.Err()
}

func (s *Store) byToolLocked(toolID string) (*Entry, error) {
	row := s.db.QueryRow(`
		SELECT tool_id, first_seen, last_seen, total_invocations, effects, intercept_adapters, coverage_tier, policy_rule_ids
		FROM tool_inventory
		WHERE tool_id = ?
		LIMIT 1
	`, toolID)
	return scanEntry(row)
}

func scanEntry(scanner interface{ Scan(dest ...any) error }) (*Entry, error) {
	var entry Entry
	var firstSeen, lastSeen string
	var effectsJSON, adaptersJSON, ruleIDsJSON string
	err := scanner.Scan(
		&entry.ToolID,
		&firstSeen,
		&lastSeen,
		&entry.TotalInvocations,
		&effectsJSON,
		&adaptersJSON,
		&entry.CoverageTier,
		&ruleIDsJSON,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	entry.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
	entry.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
	if entry.Effects == nil {
		entry.Effects = map[string]int{}
	}
	_ = json.Unmarshal([]byte(effectsJSON), &entry.Effects)
	_ = json.Unmarshal([]byte(adaptersJSON), &entry.InterceptAdapters)
	_ = json.Unmarshal([]byte(ruleIDsJSON), &entry.PolicyRuleIDs)
	return &entry, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tool_inventory (
			tool_id TEXT PRIMARY KEY,
			first_seen TEXT NOT NULL,
			last_seen TEXT NOT NULL,
			total_invocations INTEGER NOT NULL DEFAULT 0,
			effects TEXT DEFAULT '{}',
			intercept_adapters TEXT DEFAULT '[]',
			coverage_tier TEXT DEFAULT '',
			policy_rule_ids TEXT DEFAULT '[]'
		);
		CREATE INDEX IF NOT EXISTS idx_tool_inventory_last_seen ON tool_inventory(last_seen DESC);
	`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func stringsTrim(v string) string {
	return strings.TrimSpace(v)
}
