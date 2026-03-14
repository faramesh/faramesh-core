package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/compensation"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

var compensateCmd = &cobra.Command{
	Use:   "compensate [dpr-record-id]",
	Short: "Trigger compensation for a reversible tool call",
	Long: `Trigger the compensation/rollback action for a tool call that was marked
as reversible or compensatable in the DPR. Uses the saga engine to
execute the reverse action.

Example:
  faramesh compensate dpr-abc123    # Compensate a specific tool call
  faramesh compensate --session s1  # Compensate all reversible calls in session`,
	Args: cobra.MaximumNArgs(1),
	RunE: runCompensate,
}

var compensateSessionID string
var compensateDB string
var compensateDataDir string
var compensatePolicy string
var compensateArgsJSON string
var compensateJSON bool

func init() {
	compensateCmd.Flags().StringVar(&compensateSessionID, "session", "", "Compensate all reversible calls in a session")
	compensateCmd.Flags().StringVar(&compensateDB, "db", "", "path to DPR SQLite database (default: <data-dir>/faramesh.db)")
	compensateCmd.Flags().StringVar(&compensateDataDir, "data-dir", "", "directory containing faramesh.db (default: $TMPDIR/faramesh)")
	compensateCmd.Flags().StringVar(&compensatePolicy, "policy", "policy.yaml", "path to policy YAML containing compensation mappings")
	compensateCmd.Flags().StringVar(&compensateArgsJSON, "args", "", "JSON object for original args override (required for mapped compensation args)")
	compensateCmd.Flags().BoolVar(&compensateJSON, "json", false, "output compensation result as JSON")
	rootCmd.AddCommand(compensateCmd)
}

func runCompensate(_ *cobra.Command, args []string) error {
	if len(args) == 0 && compensateSessionID == "" {
		return fmt.Errorf("specify a DPR record ID or --session")
	}
	if len(args) > 0 && compensateSessionID != "" {
		return fmt.Errorf("use either a DPR record ID or --session, not both")
	}

	doc, _, err := policy.LoadFile(compensatePolicy)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	engine := compensation.NewEngine(doc)

	dbPath := compensateDB
	if dbPath == "" {
		dataDir := compensateDataDir
		if dataDir == "" {
			dataDir = filepath.Join(os.TempDir(), "faramesh")
		}
		dbPath = filepath.Join(dataDir, "faramesh.db")
	}
	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		return fmt.Errorf("open DPR store: %w", err)
	}
	defer store.Close()

	var overrideArgs map[string]any
	if compensateArgsJSON != "" {
		if err := json.Unmarshal([]byte(compensateArgsJSON), &overrideArgs); err != nil {
			return fmt.Errorf("parse --args JSON: %w", err)
		}
	}

	if compensateSessionID != "" {
		recs, err := store.Recent(5000)
		if err != nil {
			return fmt.Errorf("query DPR records: %w", err)
		}
		results := make([]*compensation.CompensationResult, 0)
		for _, rec := range recs {
			if rec.SessionID != compensateSessionID {
				continue
			}
			if rec.Effect != "PERMIT" && rec.Effect != "SHADOW" {
				continue
			}
			if !engine.CanCompensate(rec.ToolID) {
				continue
			}
			res, err := buildCompensationForRecord(engine, rec, overrideArgs)
			if err != nil {
				return err
			}
			results = append(results, res)
		}
		if len(results) == 0 {
			fmt.Printf("No compensatable DPR records found for session %s\n", compensateSessionID)
			return nil
		}

		if compensateJSON {
			out, _ := json.MarshalIndent(results, "", "  ")
			fmt.Println(string(out))
			return nil
		}
		fmt.Printf("Compensation plan for session %s:\n", compensateSessionID)
		for _, res := range results {
			fmt.Printf("- tool=%s args=%v status=%s\n", res.CompensationToolID, res.CompensationArgs, res.Status)
		}
		color.Yellow("Note: this command builds compensation actions; it does not execute tool calls yet.")
		return nil
	}

	dprID := args[0]
	rec, err := store.ByID(dprID)
	if err != nil {
		return fmt.Errorf("lookup DPR record %s: %w", dprID, err)
	}

	res, err := buildCompensationForRecord(engine, rec, overrideArgs)
	if err != nil {
		return err
	}

	if compensateJSON {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("Compensation plan for %s\n", dprID)
	fmt.Printf("  original_tool:      %s\n", rec.ToolID)
	fmt.Printf("  compensation_tool:  %s\n", res.CompensationToolID)
	fmt.Printf("  compensation_args:  %v\n", res.CompensationArgs)
	fmt.Printf("  status:             %s\n", res.Status)
	color.Yellow("Note: this command builds compensation actions; it does not execute tool calls yet.")
	return nil
}

func buildCompensationForRecord(engine *compensation.Engine, rec *dpr.Record, overrideArgs map[string]any) (*compensation.CompensationResult, error) {
	if rec.Effect != "PERMIT" && rec.Effect != "SHADOW" {
		return nil, fmt.Errorf("record %s is %s; only PERMIT/SHADOW actions can be compensated", rec.RecordID, rec.Effect)
	}

	originalArgs := overrideArgs
	if len(originalArgs) == 0 {
		// DPR currently stores structural signatures, not full original args.
		return nil, fmt.Errorf("record %s has no persisted original args; pass --args with JSON object to build mapped compensation args", rec.RecordID)
	}

	res, err := engine.BuildCompensation(compensation.CompensationRequest{
		OriginalRecordID: rec.RecordID,
		OriginalToolID:   rec.ToolID,
		OriginalArgs:     originalArgs,
		Reason:           "manual compensation request",
		RequestedBy:      "faramesh compensate",
	})
	if err != nil {
		return nil, fmt.Errorf("build compensation: %w", err)
	}
	return res, nil
}
