// Package multiagent — pipeline tamper detection.
//
// In sequential multi-agent pipelines (A → B → C), each agent's output
// is sealed with an HMAC before passing to the next agent. The next agent
// verifies the seal to detect tampering.
//
// PIPELINE_TAMPER_DETECTED reason code is set when a seal fails verification.
package multiagent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// OutputSeal is an HMAC seal on an agent's output.
type OutputSeal struct {
	AgentID    string    `json:"agent_id"`
	StepIndex  int       `json:"step_index"`
	ContentHash string   `json:"content_hash"`
	HMAC       string    `json:"hmac"`
	CreatedAt  time.Time `json:"created_at"`
}

// SealManager creates and verifies output seals between pipeline steps.
type SealManager struct {
	mu     sync.RWMutex
	key    []byte
	seals  map[string][]OutputSeal // sessionID → ordered seals
}

// NewSealManager creates a seal manager with an HMAC key.
func NewSealManager(hmacKey []byte) *SealManager {
	return &SealManager{
		key:   hmacKey,
		seals: make(map[string][]OutputSeal),
	}
}

// Seal creates an HMAC seal for an agent's output.
func (sm *SealManager) Seal(sessionID, agentID string, stepIndex int, content []byte) OutputSeal {
	contentHash := sha256.Sum256(content)
	contentHashHex := hex.EncodeToString(contentHash[:])

	// HMAC the content hash + metadata.
	mac := hmac.New(sha256.New, sm.key)
	fmt.Fprintf(mac, "%s|%s|%d|%s", sessionID, agentID, stepIndex, contentHashHex)
	seal := OutputSeal{
		AgentID:     agentID,
		StepIndex:   stepIndex,
		ContentHash: contentHashHex,
		HMAC:        hex.EncodeToString(mac.Sum(nil)),
		CreatedAt:   time.Now(),
	}

	sm.mu.Lock()
	sm.seals[sessionID] = append(sm.seals[sessionID], seal)
	sm.mu.Unlock()

	return seal
}

// Verify checks that an output seal is valid.
func (sm *SealManager) Verify(sessionID string, seal OutputSeal, content []byte) error {
	// Recompute content hash.
	contentHash := sha256.Sum256(content)
	contentHashHex := hex.EncodeToString(contentHash[:])

	if contentHashHex != seal.ContentHash {
		return fmt.Errorf("PIPELINE_TAMPER_DETECTED: content hash mismatch (step %d, agent %s)",
			seal.StepIndex, seal.AgentID)
	}

	// Recompute HMAC.
	mac := hmac.New(sha256.New, sm.key)
	fmt.Fprintf(mac, "%s|%s|%d|%s", sessionID, seal.AgentID, seal.StepIndex, seal.ContentHash)
	expected := mac.Sum(nil)
	actual, err := hex.DecodeString(seal.HMAC)
	if err != nil {
		return fmt.Errorf("PIPELINE_TAMPER_DETECTED: invalid HMAC encoding")
	}

	if !hmac.Equal(expected, actual) {
		return fmt.Errorf("PIPELINE_TAMPER_DETECTED: HMAC verification failed (step %d, agent %s)",
			seal.StepIndex, seal.AgentID)
	}

	return nil
}

// VerifyChain verifies that all seals in a session form a valid chain.
func (sm *SealManager) VerifyChain(sessionID string) []error {
	sm.mu.RLock()
	seals := sm.seals[sessionID]
	sm.mu.RUnlock()

	var errors []error
	for i := 1; i < len(seals); i++ {
		if seals[i].StepIndex != seals[i-1].StepIndex+1 {
			errors = append(errors, fmt.Errorf("seal gap: step %d → %d",
				seals[i-1].StepIndex, seals[i].StepIndex))
		}
	}
	return errors
}

// SealsForSession returns all seals for a session.
func (sm *SealManager) SealsForSession(sessionID string) []OutputSeal {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	result := make([]OutputSeal, len(sm.seals[sessionID]))
	copy(result, sm.seals[sessionID])
	return result
}
