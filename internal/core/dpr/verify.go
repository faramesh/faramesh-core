package dpr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyPublisher handles exporting public keys for offline verification and audit trails.
type KeyPublisher struct {
	dataDir string
}

func NewKeyPublisher(dataDir string) *KeyPublisher {
	return &KeyPublisher{dataDir: dataDir}
}

// PublishPublicKey writes the current DPR public key to a file that can be served
// or distributed for offline verification. Overwrites if exists.
func (kp *KeyPublisher) PublishPublicKey() error {
	pubPath := filepath.Join(kp.dataDir, "faramesh.ed25519.pub")
	keysDir := filepath.Join(kp.dataDir, "keys")
	if err := os.MkdirAll(keysDir, 0o755); err != nil {
		return fmt.Errorf("create keys dir: %w", err)
	}
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read current public key: %w", err)
	}
	publishPath := filepath.Join(keysDir, "dpr.ed25519.pub")
	if err := os.WriteFile(publishPath, pubBytes, 0o644); err != nil {
		return fmt.Errorf("write published public key: %w", err)
	}
	return nil
}

// GetPublicKeyB64 returns the base64-encoded public key for manual verification
// or display in audit logs.
func (kp *KeyPublisher) GetPublicKeyB64() (string, error) {
	pubPath := filepath.Join(kp.dataDir, "faramesh.ed25519.pub")
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	return string(pubBytes), nil
}

// VerifyRecordBatch checks a set of records for signature/hash validity and returns
// a summary with counts of valid, invalid, and unsigned records.
type VerificationSummary struct {
	Total        int
	ValidSigs    int
	InvalidSigs  int
	Unsigned     int
	HashMismatch int
	Errors       []string
}

func VerifyRecordBatch(records []*Record) *VerificationSummary {
	summary := &VerificationSummary{Total: len(records)}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if !rec.VerifyRecordHash() {
			summary.HashMismatch++
			summary.Errors = append(summary.Errors, fmt.Sprintf("record %s: hash mismatch", rec.RecordID))
			continue
		}
		if rec.SignatureAlg == "" || rec.Signature == "" {
			summary.Unsigned++
			continue
		}
		if rec.SignatureAlg == "ed25519" {
			ok, err := rec.VerifyEd25519()
			if err != nil {
				summary.InvalidSigs++
				summary.Errors = append(summary.Errors, fmt.Sprintf("record %s: verify error: %v", rec.RecordID, err))
			} else if !ok {
				summary.InvalidSigs++
				summary.Errors = append(summary.Errors, fmt.Sprintf("record %s: signature verification failed", rec.RecordID))
			} else {
				summary.ValidSigs++
			}
		} else {
			summary.Unsigned++
		}
	}
	return summary
}

// VerifyCascadeChain validates DEFER cascade lineage across a set of records.
// It checks that every defer token has a consistent parent chain, depth, and
// cascade path, and rejects missing parents, self-references, and cycles.
func VerifyCascadeChain(records []*Record) error {
	byToken := make(map[string]*Record)
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if token := strings.TrimSpace(rec.DeferToken); token != "" {
			if prev, ok := byToken[token]; ok && prev.RecordID != rec.RecordID {
				return fmt.Errorf("duplicate defer token %q across records %q and %q", token, prev.RecordID, rec.RecordID)
			}
			byToken[token] = rec
		}
	}

	for token, rec := range byToken {
		if err := validateCascadeRecord(token, rec, byToken); err != nil {
			return err
		}
	}
	return nil
}

func validateCascadeRecord(token string, rec *Record, byToken map[string]*Record) error {
	parentToken := strings.TrimSpace(rec.ParentDeferToken)
	path := append([]string(nil), rec.CascadePath...)
	if parentToken == "" {
		if rec.CascadeDepth != 0 {
			return fmt.Errorf("defer %q has cascade_depth=%d but no parent", token, rec.CascadeDepth)
		}
		if len(path) != 0 {
			return fmt.Errorf("defer %q has cascade_path but no parent", token)
		}
		return nil
	}
	if parentToken == token {
		return fmt.Errorf("defer %q cannot reference itself as parent", token)
	}

	expectedPath, err := buildCascadePath(token, byToken)
	if err != nil {
		return err
	}
	if len(expectedPath) != rec.CascadeDepth {
		return fmt.Errorf("defer %q cascade_depth=%d does not match computed depth %d", token, rec.CascadeDepth, len(expectedPath))
	}
	if len(path) != len(expectedPath) {
		return fmt.Errorf("defer %q cascade_path length=%d does not match computed depth %d", token, len(path), len(expectedPath))
	}
	for i := range path {
		if path[i] != expectedPath[i] {
			return fmt.Errorf("defer %q cascade_path[%d]=%q want %q", token, i, path[i], expectedPath[i])
		}
	}
	return nil
}

func buildCascadePath(token string, byToken map[string]*Record) ([]string, error) {
	var path []string
	seen := map[string]struct{}{token: struct{}{} }
	current, ok := byToken[token]
	if !ok {
		return nil, fmt.Errorf("missing defer token %q", token)
	}
	for parent := strings.TrimSpace(current.ParentDeferToken); parent != ""; {
		if _, cycle := seen[parent]; cycle {
			return nil, fmt.Errorf("cascade cycle detected for token %q via parent %q", token, parent)
		}
		seen[parent] = struct{}{}
		parentRec, ok := byToken[parent]
		if !ok {
			return nil, fmt.Errorf("defer %q references missing parent %q", token, parent)
		}
		path = append([]string{parent}, path...)
		parent = strings.TrimSpace(parentRec.ParentDeferToken)
	}
	return path, nil
}
