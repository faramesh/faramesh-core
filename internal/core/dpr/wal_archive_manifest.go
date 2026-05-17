package dpr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ArchiveManifest describes a rotated WAL segment for cross-segment verification.
type ArchiveManifest struct {
	APIVersion      string            `json:"api_version"`
	ActiveWAL       string            `json:"active_wal"`
	ArchivePath     string            `json:"archive_path"`
	RotatedAt       time.Time         `json:"rotated_at"`
	LastHashByAgent map[string]string `json:"last_hash_by_agent"`
	RecordCount     int               `json:"record_count"`
	SignatureB64    string            `json:"signature_b64,omitempty"`
	SignerID        string            `json:"signer_id,omitempty"`
}

// WriteArchiveManifest persists segment metadata beside a .bak WAL file.
func WriteArchiveManifest(archivePath string, activeWAL string, lastHash map[string]string, recordCount int, signer Signer) error {
	manifestPath := archivePath + ".manifest.json"
	m := ArchiveManifest{
		APIVersion:      "1",
		ActiveWAL:       activeWAL,
		ArchivePath:     filepath.Base(archivePath),
		RotatedAt:       time.Now().UTC(),
		LastHashByAgent: lastHash,
		RecordCount:     recordCount,
	}
	if signer != nil {
		payload, err := json.Marshal(m)
		if err != nil {
			return err
		}
		sig, err := signer.Sign(payload)
		if err != nil {
			return fmt.Errorf("sign archive manifest: %w", err)
		}
		m.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
		m.SignerID = signer.ID()
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, b, 0o644)
}
