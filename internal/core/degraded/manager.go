package degraded

import (
	"sync"
	"sync/atomic"
	"time"
)

type Mode int32

const (
	ModeFull      Mode = 0
	ModeStateless Mode = 1
	ModeMinimal   Mode = 2
	ModeEmergency Mode = 3
)

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

type TransitionAlert struct {
	From      Mode      `json:"from"`
	To        Mode      `json:"to"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

type BufferedRecord struct {
	Data      []byte
	CreatedAt time.Time
}

type Manager struct {
	mode atomic.Int32

	bufMu         sync.Mutex
	buffer        []BufferedRecord
	MaxBufferSize int

	EmergencyTimeout time.Duration
	emergencyStart   time.Time
	shutdown         atomic.Bool
	OnTransition     func(TransitionAlert)

	forcedDegraded atomic.Bool
	faultInjected  atomic.Bool
}

func NewManager() *Manager {
	return &Manager{
		MaxBufferSize:    10000,
		EmergencyTimeout: 5 * time.Minute,
	}
}

func (m *Manager) Current() Mode {
	if m.faultInjected.Load() {
		return ModeEmergency
	}
	if m.forcedDegraded.Load() {
		return ModeStateless
	}
	return Mode(m.mode.Load())
}

func (m *Manager) IsShutdown() bool {
	return m.shutdown.Load()
}

func (m *Manager) SetDegraded(enabled bool) {
	m.forcedDegraded.Store(enabled)
}

func (m *Manager) ToggleDegraded() bool {
	next := !m.forcedDegraded.Load()
	m.forcedDegraded.Store(next)
	return next
}

func (m *Manager) SetFault(enabled bool) {
	m.faultInjected.Store(enabled)
}

func (m *Manager) ToggleFault() bool {
	next := !m.faultInjected.Load()
	m.faultInjected.Store(next)
	return next
}

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
		if newMode == ModeEmergency && !m.emergencyStart.IsZero() {
			if time.Since(m.emergencyStart) > m.EmergencyTimeout {
				m.shutdown.Store(true)
				m.emitTransition(ModeEmergency, ModeEmergency, "emergency timeout expired — GOVERNANCE_SHUTDOWN")
			}
		}
		return
	}

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

func (m *Manager) BufferDPR(data []byte) bool {
	m.bufMu.Lock()
	defer m.bufMu.Unlock()

	rec := BufferedRecord{Data: make([]byte, len(data)), CreatedAt: time.Now()}
	copy(rec.Data, data)
	if len(m.buffer) >= m.MaxBufferSize {
		m.buffer = m.buffer[1:]
		m.buffer = append(m.buffer, rec)
		return false
	}
	m.buffer = append(m.buffer, rec)
	return true
}

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

func (m *Manager) BufferSize() int {
	m.bufMu.Lock()
	defer m.bufMu.Unlock()
	return len(m.buffer)
}

func (m *Manager) SessionStateAvailable() bool {
	mode := m.Current()
	return mode == ModeFull || mode == ModeMinimal
}

func (m *Manager) DPRPersistenceAvailable() bool {
	mode := m.Current()
	return mode == ModeFull || mode == ModeStateless
}

func (m *Manager) DEFERAvailable() bool { return m.Current() == ModeFull }

func (m *Manager) flushBuffer() {}

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
