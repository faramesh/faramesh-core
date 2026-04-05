package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/reasons"
)

type crossSessionEvent struct {
	at        time.Time
	recordKey string
	bytes     int
}

type crossSessionGuardTracker struct {
	mu     sync.Mutex
	events map[string][]crossSessionEvent
}

func newCrossSessionGuardTracker() *crossSessionGuardTracker {
	return &crossSessionGuardTracker{
		events: make(map[string][]crossSessionEvent),
	}
}

// CheckAndTrack evaluates cross-session guards and records this request in the guard window.
func (t *crossSessionGuardTracker) CheckAndTrack(guards []policy.CrossSessionGuard, req CanonicalActionRequest, now time.Time) (bool, Effect, string, string) {
	if t == nil || len(guards) == 0 {
		return true, EffectPermit, "", ""
	}
	principalID := ""
	if req.Principal != nil {
		principalID = strings.TrimSpace(req.Principal.ID)
	}
	if principalID == "" {
		// Principal-scoped guards cannot be evaluated without principal identity.
		return true, EffectPermit, "", ""
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, guard := range guards {
		if !strings.EqualFold(strings.TrimSpace(guard.Scope), "principal") {
			continue
		}
		threshold := guard.MaxUniqueRecords
		if threshold <= 0 {
			continue
		}
		pattern := strings.TrimSpace(guard.ToolPattern)
		if pattern == "" {
			pattern = "*"
		}
		if !matchToolPattern(pattern, req.ToolID) {
			continue
		}

		metric := normalizeCrossSessionMetric(guard.Metric)
		window := parseCrossSessionWindow(guard.Window)
		key := fmt.Sprintf("%s|%d|%s|%s|%s", principalID, i, metric, pattern, strings.ToLower(strings.TrimSpace(guard.Scope)))
		history := pruneCrossSessionEvents(t.events[key], now.Add(-window))

		violation := false
		switch metric {
		case "call_count":
			if len(history)+1 > threshold {
				violation = true
			}
			history = append(history, crossSessionEvent{at: now})
		case "data_volume_bytes":
			currentBytes := estimateArgsPayloadBytes(req.Args)
			total := currentBytes
			for _, ev := range history {
				total += ev.bytes
			}
			if total > threshold {
				violation = true
			}
			history = append(history, crossSessionEvent{at: now, bytes: currentBytes})
		default:
			recordKey := extractCrossSessionRecordKey(req.Args, req.CallID)
			seen := make(map[string]struct{}, len(history))
			for _, ev := range history {
				if ev.recordKey == "" {
					continue
				}
				seen[ev.recordKey] = struct{}{}
			}
			if _, exists := seen[recordKey]; !exists && len(seen)+1 > threshold {
				violation = true
			}
			history = append(history, crossSessionEvent{at: now, recordKey: recordKey})
		}

		t.events[key] = history
		if violation {
			return false, normalizeCrossSessionEffect(guard.OnExceed), reasons.CrossSessionPrincipalLimit,
				crossSessionViolationReason(guard, metric, threshold, window)
		}
	}

	return true, EffectPermit, "", ""
}

func normalizeCrossSessionMetric(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "call_count":
		return "call_count"
	case "data_volume_bytes":
		return "data_volume_bytes"
	default:
		return "unique_record_count"
	}
}

func parseCrossSessionWindow(raw string) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil && d > 0 {
		return d
	}
	return 24 * time.Hour
}

func normalizeCrossSessionEffect(raw string) Effect {
	if strings.EqualFold(strings.TrimSpace(raw), "defer") {
		return EffectDefer
	}
	return EffectDeny
}

func crossSessionViolationReason(guard policy.CrossSessionGuard, metric string, threshold int, window time.Duration) string {
	if reason := strings.TrimSpace(guard.Reason); reason != "" {
		return reason
	}
	return fmt.Sprintf("cross-session limit exceeded: metric=%s limit=%d window=%s", metric, threshold, window)
}

func pruneCrossSessionEvents(history []crossSessionEvent, cutoff time.Time) []crossSessionEvent {
	if len(history) == 0 {
		return history
	}
	kept := make([]crossSessionEvent, 0, len(history))
	for _, ev := range history {
		if ev.at.Before(cutoff) {
			continue
		}
		kept = append(kept, ev)
	}
	return kept
}

func estimateArgsPayloadBytes(args map[string]any) int {
	if len(args) == 0 {
		return 0
	}
	payload, err := json.Marshal(args)
	if err != nil {
		return 0
	}
	return len(payload)
}

func extractCrossSessionRecordKey(args map[string]any, callID string) string {
	if key := extractRecordValue(args); key != "" {
		return key
	}
	if len(args) > 0 {
		if payload, err := json.Marshal(args); err == nil && len(payload) > 0 {
			return string(payload)
		}
	}
	return strings.TrimSpace(callID)
}

func extractRecordValue(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	keys := []string{
		"customer_id", "customerId",
		"record_id", "recordId",
		"account_id", "accountId",
		"user_id", "userId",
		"id",
	}
	for _, key := range keys {
		if v, ok := args[key]; ok {
			if s := scalarToString(v); s != "" {
				return key + ":" + s
			}
		}
	}
	if params, ok := args["params"].(map[string]any); ok {
		for _, key := range keys {
			if v, ok := params[key]; ok {
				if s := scalarToString(v); s != "" {
					return key + ":" + s
				}
			}
		}
	}
	return ""
}

func scalarToString(v any) string {
	switch tv := v.(type) {
	case string:
		return strings.TrimSpace(tv)
	case int:
		return fmt.Sprintf("%d", tv)
	case int32:
		return fmt.Sprintf("%d", tv)
	case int64:
		return fmt.Sprintf("%d", tv)
	case float32:
		return fmt.Sprintf("%g", tv)
	case float64:
		return fmt.Sprintf("%g", tv)
	case bool:
		if tv {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
