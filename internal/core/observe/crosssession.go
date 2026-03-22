package observe

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// crossSessionAnalysisWindow bounds how far back we look for paired read→exfil flows.
const crossSessionAnalysisWindow = 24 * time.Hour

// maxEventsPerPrincipal caps memory for the in-process flow graph.
const maxEventsPerPrincipal = 64

type flowKind int

const (
	flowKindOther flowKind = iota
	flowKindRead
	flowKindExfil
)

// FlowTracker records PERMIT access events per principal and detects a coarse
// read-then-exfil pattern across different sessions (cross-session temporal accumulation).
type FlowTracker struct {
	mu sync.Mutex
	// key: principal id (including synthetic "_anonymous")
	byPrincipal map[string][]flowEntry

	suspicionCount atomic.Int64
}

type flowEntry struct {
	sessionID   string
	toolID      string
	kind        flowKind
	timestamp   time.Time
	principalID string
	dprID       string
}

// NewFlowTracker creates an empty flow tracker for cross-session analysis.
func NewFlowTracker() *FlowTracker {
	return &FlowTracker{
		byPrincipal: make(map[string][]flowEntry),
	}
}

// SuspicionCount returns how many read→exfil cross-session sequences were observed.
func (ft *FlowTracker) SuspicionCount() int64 {
	if ft == nil {
		return 0
	}
	return ft.suspicionCount.Load()
}

// RecordAccess appends an access event and runs cross-session pairing checks.
func (ft *FlowTracker) RecordAccess(evt AccessEvent) error {
	if ft == nil {
		return nil
	}
	pid := evt.PrincipalID
	if pid == "" {
		pid = "_anonymous"
	}
	now := evt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	kind := classifyToolKind(evt.ToolID)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	hist := ft.byPrincipal[pid]
	hist = pruneFlowHistory(hist, now)
	if kind == flowKindExfil {
		for _, prev := range hist {
			if prev.kind != flowKindRead {
				continue
			}
			if prev.sessionID == evt.SessionID {
				continue
			}
			if now.Sub(prev.timestamp) > crossSessionAnalysisWindow {
				continue
			}
			ft.suspicionCount.Add(1)
			break
		}
	}
	hist = append(hist, flowEntry{
		sessionID:   evt.SessionID,
		toolID:      evt.ToolID,
		kind:        kind,
		timestamp:   now,
		principalID: evt.PrincipalID,
		dprID:       evt.DPRID,
	})
	if len(hist) > maxEventsPerPrincipal {
		hist = hist[len(hist)-maxEventsPerPrincipal:]
	}
	ft.byPrincipal[pid] = hist
	return nil
}

func pruneFlowHistory(h []flowEntry, now time.Time) []flowEntry {
	cutoff := now.Add(-crossSessionAnalysisWindow)
	out := h[:0]
	for _, e := range h {
		if !e.timestamp.Before(cutoff) {
			out = append(out, e)
		}
	}
	return out
}

func classifyToolKind(toolID string) flowKind {
	t := strings.ToLower(toolID)
	switch {
	case strings.Contains(t, "exfil"),
		strings.Contains(t, "slack"),
		strings.Contains(t, "email"),
		strings.Contains(t, "webhook"),
		strings.Contains(t, "upload"),
		strings.Contains(t, "post:"),
		strings.HasSuffix(t, "/send"),
		strings.Contains(t, "/send"),
		strings.Contains(t, "export"):
		return flowKindExfil
	case strings.Contains(t, "read"),
		strings.Contains(t, "fetch"),
		strings.Contains(t, "query"),
		strings.Contains(t, "list"),
		strings.Contains(t, "get"),
		strings.Contains(t, "download"):
		return flowKindRead
	default:
		return flowKindOther
	}
}

// flowCrossSessionAdapter implements CrossSessionTracker by delegating to FlowTracker.
type flowCrossSessionAdapter struct {
	ft *FlowTracker
}

func newFlowCrossSessionAdapter(ft *FlowTracker) CrossSessionTracker {
	if ft == nil {
		return noOpCrossSessionTracker{}
	}
	return &flowCrossSessionAdapter{ft: ft}
}

func (a *flowCrossSessionAdapter) RecordAccess(evt AccessEvent) error {
	if a == nil || a.ft == nil {
		return nil
	}
	return a.ft.RecordAccess(evt)
}

// NewCrossSessionFlowTracker returns a real cross-session tracker backed by FlowTracker.
func NewCrossSessionFlowTracker() CrossSessionTracker {
	return newFlowCrossSessionAdapter(NewFlowTracker())
}

// FlowTrackerFrom unwraps a CrossSessionTracker to the concrete FlowTracker when present.
func FlowTrackerFrom(t CrossSessionTracker) *FlowTracker {
	if t == nil {
		return nil
	}
	if a, ok := t.(*flowCrossSessionAdapter); ok && a != nil {
		return a.ft
	}
	return nil
}
