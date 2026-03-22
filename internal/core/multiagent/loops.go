// Package multiagent — critique loop governance.
//
// Governs iterative refinement loops between agents (e.g., generator +
// critic patterns). Tracks convergence trajectory, detects lack of
// improvement, and enforces max iterations/cost/duration caps.
package multiagent

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// LoopConfig defines governance constraints for a critique loop.
type LoopConfig struct {
	LoopID            string        `json:"loop_id"`
	MaxIterations     int           `json:"max_iterations"`
	MaxTotalCostUSD   float64       `json:"max_total_cost_usd"`
	MaxDuration       time.Duration `json:"max_duration"`
	MinImprovementPct float64       `json:"min_improvement_pct"` // stop if improvement < this %
	OnMaxReached      string        `json:"on_max_reached"`      // "deny" or "defer"
}

// LoopIteration records a single iteration in the loop.
type LoopIteration struct {
	Index       int       `json:"index"`
	AgentID     string    `json:"agent_id"` // which agent produced this iteration
	Score       float64   `json:"score"`    // quality metric (higher = better)
	CostUSD     float64   `json:"cost_usd"`
	Timestamp   time.Time `json:"timestamp"`
	Improvement float64   `json:"improvement_pct"` // vs previous iteration
}

// LoopState holds the full state of a critique loop.
type LoopState struct {
	Config     LoopConfig      `json:"config"`
	Iterations []LoopIteration `json:"iterations"`
	TotalCost  float64         `json:"total_cost_usd"`
	StartedAt  time.Time       `json:"started_at"`
	StoppedAt  *time.Time      `json:"stopped_at,omitempty"`
	StopReason string          `json:"stop_reason,omitempty"`
}

// LoopGovernor manages critique loop governance.
type LoopGovernor struct {
	mu         sync.Mutex
	loops      map[string]*LoopState
	runtimeCfg LoopRuntimeConfig
	runtime    map[string][]loopRuntimeCall
}

type LoopRuntimeConfig struct {
	Enabled     bool
	Window      time.Duration
	MaxRepeats  int
	MaxCalls    int
	MaxArgBytes int
}

type loopRuntimeCall struct {
	ts        time.Time
	signature string
}

// NewLoopGovernor creates a loop governor.
func NewLoopGovernor() *LoopGovernor {
	return &LoopGovernor{
		loops:   make(map[string]*LoopState),
		runtime: make(map[string][]loopRuntimeCall),
	}
}

func (lg *LoopGovernor) ConfigureRuntime(cfg LoopRuntimeConfig) {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	lg.runtimeCfg = cfg
}

func (lg *LoopGovernor) CheckAndTrack(agentID, sessionID, toolID string, args map[string]any, now time.Time) (bool, string, string) {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	cfg := lg.runtimeCfg
	if !cfg.Enabled || cfg.Window <= 0 {
		return true, "", ""
	}
	if cfg.MaxCalls <= 0 && cfg.MaxRepeats <= 0 {
		return true, "", ""
	}
	key := agentID + "|" + sessionID
	calls := lg.runtime[key]
	cutoff := now.Add(-cfg.Window)
	kept := calls[:0]
	for _, c := range calls {
		if c.ts.After(cutoff) || c.ts.Equal(cutoff) {
			kept = append(kept, c)
		}
	}
	sig := toolID + "|" + boundedArgsSignature(args, cfg.MaxArgBytes)
	repeats := 1
	for i := len(kept) - 1; i >= 0; i-- {
		if kept[i].signature == sig {
			repeats++
		}
	}
	if cfg.MaxCalls > 0 && len(kept)+1 > cfg.MaxCalls {
		lg.runtime[key] = append(kept, loopRuntimeCall{ts: now, signature: sig})
		return false, "AGENT_LOOP_DETECTED", fmt.Sprintf("loop governor blocked burst activity (%d calls/%s)", len(kept)+1, cfg.Window)
	}
	if cfg.MaxRepeats > 0 && repeats > cfg.MaxRepeats {
		lg.runtime[key] = append(kept, loopRuntimeCall{ts: now, signature: sig})
		return false, "LOOP_DETECTION", fmt.Sprintf("loop governor blocked repetitive pattern on %q (%d repeats/%s)", toolID, repeats, cfg.Window)
	}
	lg.runtime[key] = append(kept, loopRuntimeCall{ts: now, signature: sig})
	return true, "", ""
}

func boundedArgsSignature(args map[string]any, max int) string {
	s := fmt.Sprintf("%v", args)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

// StartLoop begins a governed critique loop.
func (lg *LoopGovernor) StartLoop(config LoopConfig) error {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	if _, exists := lg.loops[config.LoopID]; exists {
		return fmt.Errorf("loop %s already exists", config.LoopID)
	}
	lg.loops[config.LoopID] = &LoopState{
		Config:    config,
		StartedAt: time.Now(),
	}
	return nil
}

// RecordIteration records a loop iteration and checks governance constraints.
// Returns (canContinue, reason).
func (lg *LoopGovernor) RecordIteration(loopID, agentID string, score, costUSD float64) (bool, string) {
	lg.mu.Lock()
	defer lg.mu.Unlock()

	state, ok := lg.loops[loopID]
	if !ok {
		return false, "LOOP_NOT_FOUND"
	}
	if state.StoppedAt != nil {
		return false, fmt.Sprintf("LOOP_ALREADY_STOPPED: %s", state.StopReason)
	}

	// Calculate improvement.
	improvement := 0.0
	if len(state.Iterations) > 0 {
		prevScore := state.Iterations[len(state.Iterations)-1].Score
		if prevScore != 0 {
			improvement = ((score - prevScore) / math.Abs(prevScore)) * 100.0
		}
	}

	iter := LoopIteration{
		Index:       len(state.Iterations),
		AgentID:     agentID,
		Score:       score,
		CostUSD:     costUSD,
		Timestamp:   time.Now(),
		Improvement: improvement,
	}
	state.Iterations = append(state.Iterations, iter)
	state.TotalCost += costUSD

	// Check max iterations.
	if state.Config.MaxIterations > 0 && len(state.Iterations) >= state.Config.MaxIterations {
		return lg.stopLoop(state, "MAX_ITERATIONS_REACHED")
	}

	// Check max cost.
	if state.Config.MaxTotalCostUSD > 0 && state.TotalCost >= state.Config.MaxTotalCostUSD {
		return lg.stopLoop(state, "MAX_COST_REACHED")
	}

	// Check max duration.
	if state.Config.MaxDuration > 0 && time.Since(state.StartedAt) >= state.Config.MaxDuration {
		return lg.stopLoop(state, "MAX_DURATION_REACHED")
	}

	// Check convergence (only after at least 2 iterations).
	if state.Config.MinImprovementPct > 0 && len(state.Iterations) >= 2 {
		if improvement < state.Config.MinImprovementPct {
			return lg.stopLoop(state, fmt.Sprintf("CONVERGED: improvement %.1f%% < minimum %.1f%%",
				improvement, state.Config.MinImprovementPct))
		}
	}

	return true, ""
}

func (lg *LoopGovernor) stopLoop(state *LoopState, reason string) (bool, string) {
	now := time.Now()
	state.StoppedAt = &now
	state.StopReason = reason
	return false, reason
}

// LoopStatus returns the current state of a loop.
func (lg *LoopGovernor) LoopStatus(loopID string) (LoopState, bool) {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	state, ok := lg.loops[loopID]
	if !ok {
		return LoopState{}, false
	}
	return *state, true
}

// ConvergenceTrajectory returns the score trajectory for a loop.
func (lg *LoopGovernor) ConvergenceTrajectory(loopID string) []float64 {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	state, ok := lg.loops[loopID]
	if !ok {
		return nil
	}
	scores := make([]float64, len(state.Iterations))
	for i, iter := range state.Iterations {
		scores[i] = iter.Score
	}
	return scores
}

// IsConverging checks if the loop is making meaningful progress.
func (lg *LoopGovernor) IsConverging(loopID string, windowSize int) bool {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	state, ok := lg.loops[loopID]
	if !ok || len(state.Iterations) < windowSize {
		return true // not enough data, assume converging
	}
	recent := state.Iterations[len(state.Iterations)-windowSize:]
	improving := 0
	for _, iter := range recent {
		if iter.Improvement > 0 {
			improving++
		}
	}
	return improving > windowSize/2
}

// EndLoop explicitly ends a loop.
func (lg *LoopGovernor) EndLoop(loopID, reason string) {
	lg.mu.Lock()
	defer lg.mu.Unlock()
	state, ok := lg.loops[loopID]
	if !ok || state.StoppedAt != nil {
		return
	}
	now := time.Now()
	state.StoppedAt = &now
	state.StopReason = reason
}
