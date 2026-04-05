package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/policy"
)

const policyReplaySampleLimit = 10

type policyReplayDivergence struct {
	RecordID      string `json:"record_id"`
	ToolID        string `json:"tool_id"`
	OldEffect     string `json:"old_effect"`
	NewEffect     string `json:"new_effect"`
	OldReasonCode string `json:"old_reason_code"`
	NewReasonCode string `json:"new_reason_code"`
}

type policyReplaySummary struct {
	TotalRecords int                      `json:"total_records_examined"`
	Divergences  int                      `json:"divergences"`
	Samples      []policyReplayDivergence `json:"sample_divergences,omitempty"`
}

var (
	policyReplayWALPolicyPath    string
	policyReplayWALPath          string
	policyReplayWALLimit         int
	policyReplayWALMaxDivergence int
)

var policyReplayWALCmd = &cobra.Command{
	Use:   "policy-replay",
	Short: "Counterfactually replay policy decisions from historical WAL records",
	RunE:  runPolicyReplayWALCommand,
}

func init() {
	policyReplayWALCmd.Flags().StringVar(&policyReplayWALPolicyPath, "policy", "", "path to policy file (YAML or FPL)")
	policyReplayWALCmd.Flags().StringVar(&policyReplayWALPath, "wal", "", "path to DPR WAL file")
	policyReplayWALCmd.Flags().IntVar(&policyReplayWALLimit, "limit", 0, "maximum number of records to replay (0 = all)")
	policyReplayWALCmd.Flags().IntVar(&policyReplayWALMaxDivergence, "max-divergence", -1, "fail if divergences exceed this threshold (-1 disables failure)")
	_ = policyReplayWALCmd.MarkFlagRequired("policy")
	_ = policyReplayWALCmd.MarkFlagRequired("wal")
	policyCmd.AddCommand(policyReplayWALCmd)
}

func runPolicyReplayWALCommand(cmd *cobra.Command, _ []string) error {
	summary, err := runPolicyReplayWAL(policyReplayWALPolicyPath, policyReplayWALPath, policyReplayWALLimit)
	if err != nil {
		return err
	}

	fmt.Printf("policy replay: %d record(s) examined, %d divergence(s)\n", summary.TotalRecords, summary.Divergences)
	for _, sample := range summary.Samples {
		fmt.Printf("- record=%s tool=%s old=%s/%s new=%s/%s\n",
			sample.RecordID,
			sample.ToolID,
			sample.OldEffect,
			sample.OldReasonCode,
			sample.NewEffect,
			sample.NewReasonCode,
		)
	}
	if policyReplayWALMaxDivergence >= 0 && summary.Divergences > policyReplayWALMaxDivergence {
		return fmt.Errorf("policy replay divergences %d exceed threshold %d", summary.Divergences, policyReplayWALMaxDivergence)
	}
	return nil
}

func runPolicyReplayWAL(policyPath, walPath string, limit int) (policyReplaySummary, error) {
	if strings.TrimSpace(policyPath) == "" {
		return policyReplaySummary{}, fmt.Errorf("--policy is required")
	}
	if strings.TrimSpace(walPath) == "" {
		return policyReplaySummary{}, fmt.Errorf("--wal is required")
	}
	if limit < 0 {
		return policyReplaySummary{}, fmt.Errorf("--limit must be >= 0")
	}

	doc, version, err := policy.LoadFile(policyPath)
	if err != nil {
		return policyReplaySummary{}, fmt.Errorf("load policy: %w", err)
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return policyReplaySummary{}, fmt.Errorf("compile policy: %w", err)
	}

	records, err := readRecordsFromWAL(walPath)
	if err != nil {
		return policyReplaySummary{}, fmt.Errorf("read --wal records: %w", err)
	}
	replayRecords := records
	if limit > 0 && limit < len(records) {
		replayRecords = records[:limit]
	}

	summary := policyReplaySummary{TotalRecords: len(replayRecords)}
	for _, rec := range replayRecords {
		result := engine.Evaluate(rec.ToolID, replayEvalContext(rec))
		oldEffect := normalizeEffect(rec.Effect)
		newEffect := normalizeEffect(result.Effect)
		oldReasonCode := strings.TrimSpace(rec.ReasonCode)
		newReasonCode := strings.TrimSpace(result.ReasonCode)
		if oldEffect == newEffect && oldReasonCode == newReasonCode {
			continue
		}
		summary.Divergences++
		if len(summary.Samples) < policyReplaySampleLimit {
			summary.Samples = append(summary.Samples, policyReplayDivergence{
				RecordID:      rec.RecordID,
				ToolID:        rec.ToolID,
				OldEffect:     oldEffect,
				NewEffect:     newEffect,
				OldReasonCode: oldReasonCode,
				NewReasonCode: newReasonCode,
			})
		}
	}
	return summary, nil
}

func replayEvalContext(rec *dpr.Record) policy.EvalContext {
	ctx := policy.EvalContext{
		Args: map[string]any{},
		Time: policy.TimeCtx{
			Hour:    rec.CreatedAt.UTC().Hour(),
			Weekday: normalizeWeekday(int(rec.CreatedAt.UTC().Weekday())),
			Month:   int(rec.CreatedAt.UTC().Month()),
			Day:     rec.CreatedAt.UTC().Day(),
		},
	}
	if rec.SelectorSnapshot != nil {
		ctx.Args = copyStringAnyMap(rec.SelectorSnapshot)
	}
	return ctx
}

func copyStringAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeEffect(effect string) string {
	return strings.ToUpper(strings.TrimSpace(effect))
}

func normalizeWeekday(day int) int {
	if day == 0 {
		return 7
	}
	return day
}
