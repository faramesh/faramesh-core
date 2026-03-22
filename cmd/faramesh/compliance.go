package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
)

var (
	complianceExportWALPath string
	complianceExportOutPath string
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

func init() {
	complianceCmd.AddCommand(complianceExportCmd)
	complianceExportCmd.Flags().StringVar(&complianceExportWALPath, "wal", "", "path to DPR WAL file")
	complianceExportCmd.Flags().StringVar(&complianceExportOutPath, "out", "", "output path for JSON bundle (default stdout)")
	_ = complianceExportCmd.MarkFlagRequired("wal")
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
