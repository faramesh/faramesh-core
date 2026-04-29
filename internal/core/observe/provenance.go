package observe

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// ArgProvenanceTracker infers argument origins from observed tool outputs.
type ArgProvenanceTracker interface {
	InferArgProvenance(agentID, sessionID string, args map[string]any) (map[string]string, error)
	RecordToolOutput(agentID, sessionID, toolID, recordID string, output any) error
}

type provenanceTracker struct {
	mu      sync.RWMutex
	byScope map[string][]outputSample
	global  []outputSample
}

type outputSample struct {
	recordID string
	text     string
}

// NewArgProvenanceTracker creates an in-memory provenance tracker.
func NewArgProvenanceTracker() ArgProvenanceTracker {
	return &provenanceTracker{
		byScope: make(map[string][]outputSample),
	}
}

func (p *provenanceTracker) InferArgProvenance(agentID, sessionID string, args map[string]any) (map[string]string, error) {
	flat := make(map[string]string)
	flattenArgs("", args, flat)
	if len(flat) == 0 {
		return nil, nil
	}
	p.mu.RLock()
	candidates := append([]outputSample{}, p.global...)
	candidates = append(candidates, p.byScope[scopeKey(agentID, sessionID)]...)
	p.mu.RUnlock()
	sort.SliceStable(candidates, func(i, j int) bool {
		return len(candidates[i].text) > len(candidates[j].text)
	})
	out := make(map[string]string, len(flat))
	for path, value := range flat {
		out[path] = "unknown"
		if value == "" {
			continue
		}
		for _, c := range candidates {
			if c.recordID == "" || len(c.text) < 8 {
				continue
			}
			if strings.Contains(value, c.text) {
				out[path] = c.recordID
				break
			}
		}
	}
	return out, nil
}

func (p *provenanceTracker) RecordToolOutput(agentID, sessionID, _ string, recordID string, output any) error {
	text := normalizeOutput(output)
	if text == "" {
		return nil
	}
	s := outputSample{recordID: strings.TrimSpace(recordID), text: text}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.global = appendBounded(p.global, s, 128)
	if agentID != "" || sessionID != "" {
		key := scopeKey(agentID, sessionID)
		p.byScope[key] = appendBounded(p.byScope[key], s, 64)
	}
	return nil
}

func appendBounded(in []outputSample, s outputSample, max int) []outputSample {
	in = append(in, s)
	if len(in) <= max {
		return in
	}
	return in[len(in)-max:]
}

func scopeKey(agentID, sessionID string) string {
	return agentID + "::" + sessionID
}

func normalizeOutput(v any) string {
	switch t := v.(type) {
	case string:
		return normalizeText(t)
	case []byte:
		return normalizeText(string(t))
	default:
		return normalizeText(fmt.Sprintf("%v", v))
	}
}

func normalizeText(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}

func flattenArgs(prefix string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			next := k
			if prefix != "" {
				next = prefix + "." + k
			}
			flattenArgs(next, child, out)
		}
	case []any:
		for i, child := range t {
			next := fmt.Sprintf("%s[%d]", prefix, i)
			flattenArgs(next, child, out)
		}
	case string:
		out[prefix] = normalizeText(t)
	default:
		out[prefix] = ""
	}
}
