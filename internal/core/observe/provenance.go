// Package observe — argument provenance tracking.
//
// Wraps tool arguments with provenance metadata: where each argument
// originated (user input, prior tool output, session state, etc.).
// Enables provenance-based policy conditions in FPL.
package observe

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// ProvenanceSource identifies where an argument value originated.
type ProvenanceSource string

const (
	ProvenanceUserInput    ProvenanceSource = "user_input"
	ProvenanceToolOutput   ProvenanceSource = "tool_output"
	ProvenanceSessionState ProvenanceSource = "session_state"
	ProvenanceHardcoded    ProvenanceSource = "hardcoded"
	ProvenanceDerived      ProvenanceSource = "derived"
	ProvenanceUnknown      ProvenanceSource = "unknown"
)

// ProvenanceEntry tracks one argument's origin.
type ProvenanceEntry struct {
	ArgPath     string           `json:"arg_path"`     // e.g. "recipient" or "body.text"
	Source      ProvenanceSource `json:"source"`
	SourceDPRID string           `json:"source_dpr_id,omitempty"` // DPR record that produced this value
	SourceTool  string           `json:"source_tool,omitempty"`   // tool that produced this value
	Hash        string           `json:"hash"`                    // SHA-256 of the value
}

// ProvenanceEnvelope wraps tool arguments with provenance metadata.
type ProvenanceEnvelope struct {
	ToolID   string            `json:"tool_id"`
	Entries  []ProvenanceEntry `json:"entries"`
	Complete bool              `json:"complete"` // true if all args have provenance
}

// ProvenanceTracker infers and records argument provenance.
type ProvenanceTracker struct {
	mu          sync.Mutex
	toolOutputs map[string]map[string]string // dprID → argPath → valueHash
}

// NewProvenanceTracker creates a provenance tracker.
func NewProvenanceTracker() *ProvenanceTracker {
	return &ProvenanceTracker{
		toolOutputs: make(map[string]map[string]string),
	}
}

// RecordToolOutput records the output of a tool for later provenance matching.
func (pt *ProvenanceTracker) RecordToolOutput(dprID, toolID string, outputs map[string]any) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	hashes := make(map[string]string)
	for k, v := range outputs {
		hashes[k] = hashValue(v)
	}
	pt.toolOutputs[dprID] = hashes
}

// InferProvenance analyzes tool arguments and attempts to match them
// to known sources (prior tool outputs, session state).
func (pt *ProvenanceTracker) InferProvenance(toolID string, args map[string]any, sessionState map[string]any) ProvenanceEnvelope {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	env := ProvenanceEnvelope{
		ToolID:   toolID,
		Complete: true,
	}

	for argPath, argValue := range args {
		argHash := hashValue(argValue)
		entry := ProvenanceEntry{
			ArgPath: argPath,
			Hash:    argHash,
		}

		// Try to match against prior tool outputs.
		matched := false
		for dprID, outputs := range pt.toolOutputs {
			for _, outputHash := range outputs {
				if outputHash == argHash {
					entry.Source = ProvenanceToolOutput
					entry.SourceDPRID = dprID
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}

		// Try session state.
		if !matched {
			for _, sv := range sessionState {
				if hashValue(sv) == argHash {
					entry.Source = ProvenanceSessionState
					matched = true
					break
				}
			}
		}

		// Default to unknown.
		if !matched {
			entry.Source = ProvenanceUnknown
			env.Complete = false
		}

		env.Entries = append(env.Entries, entry)
	}

	return env
}

// ToMap converts a ProvenanceEnvelope to a map for DPR storage.
func (env *ProvenanceEnvelope) ToMap() map[string]string {
	m := make(map[string]string, len(env.Entries))
	for _, e := range env.Entries {
		m[e.ArgPath] = string(e.Source)
		if e.SourceDPRID != "" {
			m[e.ArgPath+"_source_dpr"] = e.SourceDPRID
		}
	}
	return m
}

func hashValue(v any) string {
	data, _ := json.Marshal(v)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
