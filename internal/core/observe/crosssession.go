// Package observe — cross-session information flow tracking.
//
// Tracks unique records across sessions by principal. Detects potential
// read-then-exfil patterns by analyzing DPR lineage across sessions.
package observe

import (
	"sync"
	"time"
)

// FlowRecord represents a cross-session data access.
type FlowRecord struct {
	PrincipalID string    `json:"principal_id"`
	SessionID   string    `json:"session_id"`
	ToolID      string    `json:"tool_id"`
	Effect      string    `json:"effect"`
	Timestamp   time.Time `json:"timestamp"`
	DPRID       string    `json:"dpr_id"`
}

// ExfilPattern represents a detected read-then-exfil pattern.
type ExfilPattern struct {
	PrincipalID   string    `json:"principal_id"`
	ReadSession   string    `json:"read_session"`
	ExfilSession  string    `json:"exfil_session"`
	ReadTool      string    `json:"read_tool"`
	ExfilTool     string    `json:"exfil_tool"`
	TimeBetween   time.Duration `json:"time_between"`
	DetectedAt    time.Time `json:"detected_at"`
}

// FlowTracker tracks cross-session information flow for anomaly detection.
type FlowTracker struct {
	mu         sync.Mutex
	records    []FlowRecord
	byPrincipal map[string][]FlowRecord
	readTools  map[string]bool // tools that read data
	exfilTools map[string]bool // tools that could exfiltrate data
}

// NewFlowTracker creates a cross-session flow tracker.
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		byPrincipal: make(map[string][]FlowRecord),
		readTools: map[string]bool{
			"db/query": true, "db/read": true,
			"fs/read": true, "api/get": true,
			"search": true, "lookup": true,
		},
		exfilTools: map[string]bool{
			"email/send": true, "api/post": true,
			"fs/write": true, "upload": true,
			"webhook/call": true, "net/connect": true,
		},
	}
}

// SetReadTools configures which tools are classified as data reads.
func (ft *FlowTracker) SetReadTools(tools []string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.readTools = make(map[string]bool, len(tools))
	for _, t := range tools {
		ft.readTools[t] = true
	}
}

// SetExfilTools configures which tools could exfiltrate data.
func (ft *FlowTracker) SetExfilTools(tools []string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.exfilTools = make(map[string]bool, len(tools))
	for _, t := range tools {
		ft.exfilTools[t] = true
	}
}

// RecordAccess records a data access event.
func (ft *FlowTracker) RecordAccess(rec FlowRecord) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.records = append(ft.records, rec)
	ft.byPrincipal[rec.PrincipalID] = append(ft.byPrincipal[rec.PrincipalID], rec)
}

// DetectExfilPatterns scans for read-then-exfil patterns across sessions.
func (ft *FlowTracker) DetectExfilPatterns(maxTimeBetween time.Duration) []ExfilPattern {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	var patterns []ExfilPattern
	for principalID, records := range ft.byPrincipal {
		// Find reads in one session followed by exfils in another session.
		for i, r1 := range records {
			if !ft.readTools[r1.ToolID] || r1.Effect != "PERMIT" {
				continue
			}
			for j := i + 1; j < len(records); j++ {
				r2 := records[j]
				if r2.SessionID == r1.SessionID {
					continue // same session, not cross-session exfil
				}
				if !ft.exfilTools[r2.ToolID] || r2.Effect != "PERMIT" {
					continue
				}
				timeBetween := r2.Timestamp.Sub(r1.Timestamp)
				if timeBetween > maxTimeBetween {
					break // too far apart
				}
				patterns = append(patterns, ExfilPattern{
					PrincipalID:  principalID,
					ReadSession:  r1.SessionID,
					ExfilSession: r2.SessionID,
					ReadTool:     r1.ToolID,
					ExfilTool:    r2.ToolID,
					TimeBetween:  timeBetween,
					DetectedAt:   time.Now(),
				})
			}
		}
	}
	return patterns
}

// UniqueRecordsByPrincipal returns the count of unique DPR records per principal.
func (ft *FlowTracker) UniqueRecordsByPrincipal() map[string]int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	counts := make(map[string]int, len(ft.byPrincipal))
	for pid, records := range ft.byPrincipal {
		seen := make(map[string]bool)
		for _, r := range records {
			seen[r.DPRID] = true
		}
		counts[pid] = len(seen)
	}
	return counts
}

// SessionsForPrincipal returns all unique sessions for a principal.
func (ft *FlowTracker) SessionsForPrincipal(principalID string) []string {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	seen := make(map[string]bool)
	for _, r := range ft.byPrincipal[principalID] {
		seen[r.SessionID] = true
	}
	sessions := make([]string, 0, len(seen))
	for s := range seen {
		sessions = append(sessions, s)
	}
	return sessions
}
