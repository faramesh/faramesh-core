// Package degraded implements the four formal degraded modes for the
// governance engine. Modes transition automatically based on backend
// availability (Redis, PostgreSQL) and are recorded in DPR records.
//
// Mode 0 — FULL: Normal operation, all features active.
// Mode 1 — STATELESS: Redis unavailable, session state disabled.
// Mode 2 — MINIMAL: PostgreSQL unavailable, DPR writes buffered.
// Mode 3 — EMERGENCY: Both unavailable, in-memory only.
package degraded

import (
	"sync"
	"sync/atomic"
	"time"
)

// Mode represents the current degradation level of the governance engine.
type Mode int32

const (
	ModeFull      Mode = 0 // All backends available
	ModeStateless Mode = 1 // Redis unavailable — no session state
	ModeMinimal   Mode = 2 // PostgreSQL unavailable — DPR buffered
	ModeEmergency Mode = 3 // Both unavailable — in-memory only
)

// String returns the DPR-compatible mode string.
func (m Mode) String() string {
	switch m {
	case ModeFull:
		return "FULL"
	case ModeStateless:
		return "STATELESS"
	case ModeMinimal:
		return "MINIMAL"
	case ModeEmergency:
		return "EMERGENCY"
	default:
		return "UNKNOWN"
	}
}

// TransitionAlert is emitted when the governance engine changes mode.
type TransitionAlert struct {
	From      Mode      `json:"from"`
	To        Mode      `json:"to"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// BufferedRecord holds a DPR record that could not be persisted.
type BufferedRecord struct {
	Data      []byte
	CreatedAt time.Time
}

// Manager tracks the current degraded mode and manages the in-memory
// DPR buffer used when PostgreSQL is unavailable.
type Manager struct {
	mode atomic.Int32

	// In-memory DPR buffer for Mode 2/3 — bounded to MaxBufferSize records.
	bufMu         sync.Mutex
	buffer        []BufferedRecord
	MaxBufferSize int

	// Emergency timeout: if backends don't recover within this duration
	// in Mode 3, trigger GOVERNANCE_SHUTDOWN and block all tool calls.
	EmergencyTimeout time.Duration
	emergencyStart   time.Time
	shutdown         atomic.Bool

	// Alert callback — called on every mode transition.
	OnTransition func(TransitionAlert)
}

// NewManager creates a degraded mode manager with default settings.
func NewManager() *Manager {
	return &Manager{
		MaxBufferSize:    10000,
		EmergencyTimeout: 5 * time.Minute,
	}
}

// Current returns the current degraded mode.
func (m *Manager) Current() Mode {
	return Mode(m.mode.Load())
}

// IsShutdown returns true if the emergency timeout has expired and
// the engine should block all tool calls.
func (m *Manager) IsShutdown() bool {
	return m.shutdown.Load()
}

// SetBackendStatus updates the degraded mode based on backend availability.
// This should be called periodically by health checks.
func (m *Manager) SetBackendStatus(redisAvailable, postgresAvailable bool) {
	var newMode Mode
	switch {
	case redisAvailable && postgresAvailable:
		newMode = ModeFull
	case !redisAvailable && postgresAvailable:
		newMode = ModeStateless
	case redisAvailable && !postgresAvailable:
		newMode = ModeMinimal
	default:
		newMode = ModeEmergency
	}

	old := Mode(m.mode.Swap(int32(newMode)))
	if old == newMode {
		// Check emergency timeout in Mode 3.
		if newMode == ModeEmergency && !m.emergencyStart.IsZero() {
			if time.Since(m.emergencyStart) > m.EmergencyTimeout {
				m.shutdown.Store(true)
				m.emitTransition(ModeEmergency, ModeEmergency, "emergency timeout expired — GOVERNANCE_SHUTDOWN")
			}
		}
		return
	}

	// Mode transition occurred.
	reason := "backend status changed"
	switch newMode {
	case ModeFull:
		reason = "all backends recovered"
		m.shutdown.Store(false)
		m.emergencyStart = time.Time{}
		m.flushBuffer()
	case ModeStateless:
		reason = "Redis unavailable — session state disabled, fail-closed for DEFER"
	case ModeMinimal:
		reason = "PostgreSQL unavailable — DPR writes buffered in-memory"
	case ModeEmergency:
		reason = "Redis and PostgreSQL unavailable — in-memory only"
		m.emergencyStart = time.Now()
	}

	m.emitTransition(old, newMode, reason)
}

// BufferDPR adds a DPR record to the in-memory buffer when PostgreSQL
// is unavailable. Returns false if the buffer is full (oldest dropped).
func (m *Manager) BufferDPR(data []byte) bool {
	m.bufMu.Lock()
	defer m.bufMu.Unlock()

	rec := BufferedRecord{
		Data:      make([]byte, len(data)),
		CreatedAt: time.Now(),
	}
	copy(rec.Data, data)

	if len(m.buffer) >= m.MaxBufferSize {
		// Drop oldest record, emit DPR_BUFFER_OVERFLOW alert.
		m.buffer = m.buffer[1:]
		m.buffer = append(m.buffer, rec)
		return false // indicates overflow
	}
	m.buffer = append(m.buffer, rec)
	return true
}

// DrainBuffer returns all buffered records and clears the buffer.
// Called when PostgreSQL recovers to flush pending records.
func (m *Manager) DrainBuffer() []BufferedRecord {
	m.bufMu.Lock()
	defer m.bufMu.Unlock()

	if len(m.buffer) == 0 {
		return nil
	}
	result := m.buffer
	m.buffer = nil
	return result
}

// BufferSize returns the current number of buffered DPR records.
func (m *Manager) BufferSize() int {
	m.bufMu.Lock()
	defer m.bufMu.Unlock()
	return len(m.buffer)
}

// SessionStateAvailable returns true if session state operations should
// proceed. Returns false in STATELESS and EMERGENCY modes.
func (m *Manager) SessionStateAvailable() bool {
	mode := m.Current()
	return mode == ModeFull || mode == ModeMinimal
}

// DPRPersistenceAvailable returns true if DPR records can be written
// to the durable store. Returns false in MINIMAL and EMERGENCY modes.
func (m *Manager) DPRPersistenceAvailable() bool {
	mode := m.Current()
	return mode == ModeFull || mode == ModeStateless
}

// DEFERAvailable returns true if DEFER workflow operations are available.
// DEFER requires both session state (Redis) and DPR persistence (PostgreSQL).
// When unavailable, DEFER rules convert to DENY.
func (m *Manager) DEFERAvailable() bool {
	return m.Current() == ModeFull
}

func (m *Manager) flushBuffer() {
	// Buffer flush is handled by the caller (pipeline or daemon) by calling
	// DrainBuffer() and persisting the records to PostgreSQL.
}

func (m *Manager) emitTransition(from, to Mode, reason string) {
	if m.OnTransition != nil {
		m.OnTransition(TransitionAlert{
			From:      from,
			To:        to,
			Reason:    reason,
			Timestamp: time.Now(),
		})
	}
}
