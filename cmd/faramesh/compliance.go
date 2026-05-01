package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

var (
	complianceExportWALPath     string
	complianceExportOutPath     string
	complianceResignDataDir     string
	complianceResignWALPath     string
	complianceResignDBPath      string
	complianceResignApply       bool
	complianceResignLimit       int
	complianceResignOnlyMissing bool
)

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Compliance evidence operations",
}

var complianceExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export deterministic DPR compliance evidence JSON bundle",
	RunE:  runComplianceExport,
}

var complianceResignCmd = &cobra.Command{
	Use:   "resign",
	Short: "Re-sign historical DPR records with Ed25519",
	Long: `Scans WAL-validated records and updates SQLite DPR rows with Ed25519
signatures (without mutating record hashes or chain linkage).

Default mode is dry-run. Use --apply to persist signature fields.`,
	RunE: runComplianceResign,
}

func init() {
	complianceCmd.AddCommand(complianceExportCmd)
	complianceCmd.AddCommand(complianceResignCmd)
	complianceExportCmd.Flags().StringVar(&complianceExportWALPath, "wal", "", "path to DPR WAL file")
	complianceExportCmd.Flags().StringVar(&complianceExportOutPath, "out", "", "output path for JSON bundle (default stdout)")
	_ = complianceExportCmd.MarkFlagRequired("wal")

	complianceResignCmd.Flags().StringVar(&complianceResignDataDir, "data-dir", "", "runtime data directory (default: ~/.faramesh/runtime/data)")
	complianceResignCmd.Flags().StringVar(&complianceResignWALPath, "wal", "", "path to DPR WAL file (default: <data-dir>/faramesh.wal)")
	complianceResignCmd.Flags().StringVar(&complianceResignDBPath, "db", "", "path to DPR SQLite database (default: <data-dir>/faramesh.db)")
	complianceResignCmd.Flags().BoolVar(&complianceResignApply, "apply", false, "persist signature updates (default: dry-run)")
	complianceResignCmd.Flags().IntVar(&complianceResignLimit, "limit", 0, "max records to inspect from WAL (0 = all)")
	complianceResignCmd.Flags().BoolVar(&complianceResignOnlyMissing, "only-missing", true, "only sign records that do not already have ed25519 signatures")
}

func runComplianceExport(cmd *cobra.Command, _ []string) error {
	records, err := readRecordsFromWAL(complianceExportWALPath)
	if err != nil {
		return fmt.Errorf("read dpr wal: %w", err)
	}
	bundle, err := dpr.BuildComplianceExportBundle(records, time.Now())
	if err != nil {
		return fmt.Errorf("build compliance export: %w", err)
	}

	out := io.Writer(os.Stdout)
	if complianceExportOutPath != "" {
		f, err := os.Create(complianceExportOutPath)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return fmt.Errorf("encode bundle: %w", err)
	}
	return nil
}

func runComplianceResign(cmd *cobra.Command, _ []string) error {
	dataDir := strings.TrimSpace(complianceResignDataDir)
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			dataDir = filepath.Join(os.TempDir(), "faramesh", "runtime", "data")
		} else {
			dataDir = filepath.Join(home, ".faramesh", "runtime", "data")
		}
	}
	walPath := strings.TrimSpace(complianceResignWALPath)
	if walPath == "" {
		walPath = filepath.Join(dataDir, "faramesh.wal")
	}
	dbPath := strings.TrimSpace(complianceResignDBPath)
	if dbPath == "" {
		dbPath = filepath.Join(dataDir, "faramesh.db")
	}

	priv, pub, err := loadDPRSigningKeypair(dataDir)
	if err != nil {
		return err
	}
	records, err := readValidatedRecordsFromWAL(walPath)
	if err != nil {
		return fmt.Errorf("read validated wal: %w", err)
	}
	if complianceResignLimit > 0 && complianceResignLimit < len(records) {
		records = records[:complianceResignLimit]
	}

	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open dpr store: %w", err)
	}
	defer store.Close()

	type stats struct {
		total, candidates, updated, alreadySigned, hashMismatch, missingInDB, dbMismatch int
	}
	st := stats{total: len(records)}

	for _, walRec := range records {
		if walRec == nil || strings.TrimSpace(walRec.RecordID) == "" {
			continue
		}
		if !walRec.VerifyRecordHash() {
			st.hashMismatch++
			continue
		}
		dbRec, err := store.ByID(walRec.RecordID)
		if err != nil {
			st.missingInDB++
			continue
		}
		if strings.TrimSpace(dbRec.RecordHash) != strings.TrimSpace(walRec.RecordHash) {
			st.dbMismatch++
			continue
		}
		if complianceResignOnlyMissing && strings.EqualFold(strings.TrimSpace(dbRec.SignatureAlg), "ed25519") && strings.TrimSpace(dbRec.Signature) != "" {
			st.alreadySigned++
			continue
		}
		if !dbRec.VerifyRecordHash() {
			st.hashMismatch++
			continue
		}

		clone := *dbRec
		if err := clone.SignWithEd25519(priv, pub); err != nil {
			return fmt.Errorf("sign record %s: %w", dbRec.RecordID, err)
		}
		st.candidates++
		if !complianceResignApply {
			continue
		}
		if err := store.UpdateSignature(clone.RecordID, clone.SignatureAlg, clone.Signature, clone.SignerPublicKey); err != nil {
			return fmt.Errorf("update signature for %s: %w", clone.RecordID, err)
		}
		st.updated++
	}

	if complianceResignApply {
		agents, err := store.KnownAgents()
		if err != nil {
			return fmt.Errorf("list agents for chain verification: %w", err)
		}
		for _, agent := range agents {
			if br, err := store.VerifyChain(agent); err != nil {
				return fmt.Errorf("verify chain for agent %s: %w", agent, err)
			} else if br != nil {
				return fmt.Errorf("chain break after resign for agent %s at record %s", agent, br.RecordID)
			}
		}
	}

	mode := "dry-run"
	if complianceResignApply {
		mode = "applied"
	}
	fmt.Printf("compliance resign (%s): total=%d candidates=%d updated=%d already_signed=%d hash_mismatch=%d missing_in_db=%d db_mismatch=%d\n",
		mode, st.total, st.candidates, st.updated, st.alreadySigned, st.hashMismatch, st.missingInDB, st.dbMismatch)
	return nil
}

func readRecordsFromWAL(path string) ([]*dpr.Record, error) {
	w, err := dpr.OpenWAL(path)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	records := make([]*dpr.Record, 0, 64)
	if err := w.Replay(func(rec *dpr.Record) error {
		records = append(records, rec)
		return nil
	}); err != nil {
		return nil, err
	}
	return records, nil
}

func readValidatedRecordsFromWAL(path string) ([]*dpr.Record, error) {
	w, err := dpr.OpenWAL(path)
	if err != nil {
		return nil, err
	}
	defer w.Close()

	records := make([]*dpr.Record, 0, 64)
	if err := w.ReplayValidated(func(rec *dpr.Record) error {
		records = append(records, rec)
		return nil
	}); err != nil {
		return nil, err
	}
	return records, nil
}

func loadDPRSigningKeypair(dataDir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	privPath := filepath.Join(dataDir, "faramesh.ed25519.key")
	pubPath := filepath.Join(dataDir, "faramesh.ed25519.pub")

	privRaw, err := os.ReadFile(privPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read ed25519 private key: %w", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privRaw)))
	if err != nil {
		return nil, nil, fmt.Errorf("decode ed25519 private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid ed25519 private key size: %d", len(privBytes))
	}
	priv := ed25519.PrivateKey(privBytes)

	if pubRaw, err := os.ReadFile(pubPath); err == nil {
		pubBytes, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(pubRaw)))
		if decErr == nil && len(pubBytes) == ed25519.PublicKeySize {
			return priv, ed25519.PublicKey(pubBytes), nil
		}
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("derive ed25519 public key from private key")
	}
	return priv, pub, nil
}
