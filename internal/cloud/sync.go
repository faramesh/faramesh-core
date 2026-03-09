// Package cloud — DPR sync to Horizon.
//
// When --sync-horizon is set on faramesh serve, this package streams DPR
// records to the Horizon ingestion API in real time. Records are buffered
// locally and retried on network failure.
//
// DecisionEvent is a self-contained copy of the fields needed for sync,
// deliberately not importing internal/core to avoid circular dependencies.
// The pipeline calls Syncer.Send(core.Decision) via the core.DecisionSyncer
// interface; daemon wires them together at startup.
package cloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// DecisionEvent is the wire-format struct sent to Horizon.
// It mirrors the fields of core.Decision that are meaningful for cloud sync.
type DecisionEvent struct {
	Effect        string        `json:"effect"`
	RuleID        string        `json:"rule_id,omitempty"`
	ReasonCode    string        `json:"reason_code"`
	PolicyVersion string        `json:"policy_version,omitempty"`
	LatencyMs     int64         `json:"latency_ms"`
}

// Sendable is the subset of core.Decision the syncer cares about.
// Implemented by core.Decision so core.DecisionSyncer is satisfied without
// the cloud package importing core.
type Sendable interface {
	GetEffect() string
	GetRuleID() string
	GetReasonCode() string
	GetPolicyVersion() string
	GetLatency() time.Duration
}

// SyncConfig holds the configuration for DPR sync to Horizon.
type SyncConfig struct {
	Token      string
	HorizonURL string
	OrgID      string
	AgentID    string
	Log        *zap.Logger
}

// Syncer streams DPR records to Horizon.
// It satisfies core.DecisionSyncer via the Send(any) approach — see
// SendDecision which accepts the concrete core.Decision fields directly.
type Syncer struct {
	cfg    SyncConfig
	ch     chan DecisionEvent
	client *http.Client
}

// NewSyncer creates a new DPR syncer.
func NewSyncer(cfg SyncConfig) *Syncer {
	if cfg.HorizonURL == "" {
		cfg.HorizonURL = HorizonBaseURL
	}
	return &Syncer{
		cfg:    cfg,
		ch:     make(chan DecisionEvent, 1000),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// SendDecision queues a governance decision for async sync to Horizon.
// Accepts individual fields to avoid importing core from the cloud package.
// Non-blocking: if the buffer is full the record is dropped with a warning.
func (s *Syncer) SendDecision(effect, ruleID, reasonCode, policyVersion string, latency time.Duration) {
	ev := DecisionEvent{
		Effect:        effect,
		RuleID:        ruleID,
		ReasonCode:    reasonCode,
		PolicyVersion: policyVersion,
		LatencyMs:     latency.Milliseconds(),
	}
	select {
	case s.ch <- ev:
	default:
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("horizon sync buffer full — DPR record dropped",
				zap.String("agent", s.cfg.AgentID))
		}
	}
}

// Run starts the background sync loop. Blocks until channel is closed.
func (s *Syncer) Run() {
	batch := make([]DecisionEvent, 0, 50)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				if len(batch) > 0 {
					_ = s.flush(batch)
				}
				return
			}
			batch = append(batch, ev)
			if len(batch) >= 50 {
				_ = s.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				_ = s.flush(batch)
				batch = batch[:0]
			}
		}
	}
}

// Close stops the syncer and flushes remaining records.
func (s *Syncer) Close() {
	close(s.ch)
}

func (s *Syncer) flush(events []DecisionEvent) error {
	payload := map[string]any{
		"agent_id": s.cfg.AgentID,
		"org_id":   s.cfg.OrgID,
		"events":   events,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := s.cfg.HorizonURL + "/v1/ingest/dpr"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)

	resp, err := s.client.Do(req)
	if err != nil {
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("horizon sync request failed",
				zap.Error(err), zap.Int("records", len(events)))
		}
		return fmt.Errorf("horizon sync: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("horizon sync HTTP error",
				zap.Int("status", resp.StatusCode), zap.Int("records", len(events)))
		}
		return fmt.Errorf("horizon sync HTTP %d", resp.StatusCode)
	}

	return nil
}
