package dpr

import (
	"fmt"
	"os"
	"path/filepath"
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
