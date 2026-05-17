package daemon

import (
	"sync"
	"time"
)

// LifecycleState is the daemon governance readiness state (FARAMESH.md §8).
type LifecycleState string

const (
	StateStarting      LifecycleState = "STARTING"
	StateInitializing  LifecycleState = "INITIALIZING"
	StateReady         LifecycleState = "READY"
	StateDraining      LifecycleState = "DRAINING"
	StateHalt          LifecycleState = "HALT"
)

// Lifecycle tracks daemon readiness and cold-start enforcement.
type Lifecycle struct {
	mu sync.RWMutex

	state            LifecycleState
	startedAt        time.Time
	readyAt          time.Time
	coldStartWindow  time.Duration
}

func NewLifecycle(coldStartWindow time.Duration) *Lifecycle {
	return &Lifecycle{
		state:           StateStarting,
		startedAt:       time.Now().UTC(),
		coldStartWindow: coldStartWindow,
	}
}

// MarkInitializing transitions STARTING → INITIALIZING.
func (l *Lifecycle) MarkInitializing() {
	l.SetState(StateInitializing)
}

func (l *Lifecycle) State() LifecycleState {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state
}

func (l *Lifecycle) SetState(s LifecycleState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state = s
	if s == StateReady {
		l.readyAt = time.Now().UTC()
	}
}

func (l *Lifecycle) AcceptsGovernance() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state == StateReady
}

func (l *Lifecycle) ColdStartExceeded() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.coldStartWindow <= 0 {
		return false
	}
	if l.state == StateReady || l.state == StateHalt {
		return false
	}
	return time.Since(l.startedAt) > l.coldStartWindow
}
