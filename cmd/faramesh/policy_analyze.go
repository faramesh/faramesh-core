package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/observe"
)

const defaultPolicyAnalyzeDeadAfter = 7 * 24 * time.Hour

type pieSnapshot struct {
	Rules []observe.RuleStats `json:"rules"`
}

type policyAnalyzeRecommendation struct {
	RuleID       string  `json:"rule_id"`
	Type         string  `json:"type"`
	Reason       string  `json:"reason"`
	ApprovalRate float64 `json:"approval_rate,omitempty"`
	TotalDefers  int64   `json:"total_defers,omitempty"`
}

type policyAnalyzeResult struct {
	Source          string                        `json:"source"`
	HasData         bool                          `json:"has_data"`
	RuleCount       int                           `json:"rule_count"`
	GeneratedAt     string                        `json:"generated_at"`
	NoDataReason    string                        `json:"no_data_reason,omitempty"`
	Recommendations []policyAnalyzeRecommendation `json:"recommendations"`
}

var (
	policyAnalyzeJSON       bool
	policyAnalyzeSnapshot   string
	policyAnalyzeDataDir    string
	policyAnalyzeDeadAfter  time.Duration
	policyAnalyzeMinDefers  int64
	policyAnalyzeApprovalTH float64
)

var policyAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze PIE rule telemetry and suggest policy improvements",
	RunE:  runPolicyAnalyzeCommand,
}

func init() {
	policyAnalyzeCmd.Flags().BoolVar(&policyAnalyzeJSON, "json", false, "output deterministic JSON")
	policyAnalyzeCmd.Flags().StringVar(&policyAnalyzeSnapshot, "snapshot", "", "optional PIE snapshot JSON path")
	policyAnalyzeCmd.Flags().StringVar(&policyAnalyzeDataDir, "data-dir", "", "data directory used for default snapshot path")
	policyAnalyzeCmd.Flags().DurationVar(&policyAnalyzeDeadAfter, "dead-after", defaultPolicyAnalyzeDeadAfter, "consider rules dead after this inactivity window")
	policyAnalyzeCmd.Flags().Int64Var(&policyAnalyzeMinDefers, "min-defers", 10, "minimum defers before high-approval recommendation")
	policyAnalyzeCmd.Flags().Float64Var(&policyAnalyzeApprovalTH, "approval-threshold", 0.90, "approval threshold for DEFER-to-PERMIT recommendation")
	policyCmd.AddCommand(policyAnalyzeCmd)
}

func runPolicyAnalyzeCommand(cmd *cobra.Command, _ []string) error {
	result, err := runPolicyAnalyze(policyAnalyzeOptions{
		SnapshotPath:      policyAnalyzeSnapshot,
		DataDir:           policyAnalyzeDataDir,
		DeadAfter:         policyAnalyzeDeadAfter,
		MinDefers:         policyAnalyzeMinDefers,
		ApprovalThreshold: policyAnalyzeApprovalTH,
		Now:               time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return printPolicyAnalyze(result, policyAnalyzeJSON)
}

type policyAnalyzeOptions struct {
	SnapshotPath      string
	DataDir           string
	DeadAfter         time.Duration
	MinDefers         int64
	ApprovalThreshold float64
	Now               time.Time
}

func runPolicyAnalyze(opts policyAnalyzeOptions) (policyAnalyzeResult, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	stats, source, err := loadPIEStats(opts)
	if err != nil {
		return policyAnalyzeResult{}, err
	}
	if len(stats) == 0 {
		return policyAnalyzeResult{
			Source:          source,
			HasData:         false,
			RuleCount:       0,
			GeneratedAt:     now.Format(time.RFC3339),
			NoDataReason:    "no PIE analyzer data available yet; run traffic through faramesh serve or provide --snapshot",
			Recommendations: []policyAnalyzeRecommendation{},
		}, nil
	}

	recs := buildPIERecommendations(stats, opts, now)
	return policyAnalyzeResult{
		Source:          source,
		HasData:         true,
		RuleCount:       len(stats),
		GeneratedAt:     now.Format(time.RFC3339),
		Recommendations: recs,
	}, nil
}

func printPolicyAnalyze(result policyAnalyzeResult, asJSON bool) error {
	if asJSON {
		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("encode json: %w", err)
		}
		fmt.Println(string(out))
		return nil
	}

	fmt.Printf("PIE analysis source: %s\n", result.Source)
	fmt.Printf("rules observed: %d\n", result.RuleCount)
	if !result.HasData {
		fmt.Printf("status: %s\n", result.NoDataReason)
		return nil
	}
	if len(result.Recommendations) == 0 {
		fmt.Println("status: no actionable recommendations")
		return nil
	}
	for _, rec := range result.Recommendations {
		switch rec.Type {
		case "promote_to_permit":
			fmt.Printf("- [%s] %s (approval_rate=%.2f defers=%d)\n", rec.Type, rec.RuleID, rec.ApprovalRate, rec.TotalDefers)
		default:
			fmt.Printf("- [%s] %s: %s\n", rec.Type, rec.RuleID, rec.Reason)
		}
	}
	return nil
}

func loadPIEStats(opts policyAnalyzeOptions) ([]observe.RuleStats, string, error) {
	if strings.TrimSpace(opts.SnapshotPath) != "" {
		stats, err := loadPIEStatsFromSnapshot(opts.SnapshotPath)
		if err != nil {
			return nil, "", err
		}
		return stats, "snapshot", nil
	}

	defaultSnapshot := filepath.Join(defaultPolicyAnalyzeDataDir(opts.DataDir), "pie_snapshot.json")
	if _, err := os.Stat(defaultSnapshot); err == nil {
		stats, err := loadPIEStatsFromSnapshot(defaultSnapshot)
		if err != nil {
			return nil, "", err
		}
		return stats, "snapshot", nil
	}

	if analyzer := observe.GetPIEAnalyzer(); analyzer != nil {
		stats := analyzer.AllStats()
		sortPIEStats(stats)
		return stats, "in_process", nil
	}
	return []observe.RuleStats{}, "none", nil
}

func defaultPolicyAnalyzeDataDir(dataDir string) string {
	if strings.TrimSpace(dataDir) != "" {
		return dataDir
	}
	return filepath.Join(runtimeStateDirPath(""), "data")
}

func loadPIEStatsFromSnapshot(path string) ([]observe.RuleStats, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var snap pieSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("decode snapshot %s: %w", path, err)
	}
	sortPIEStats(snap.Rules)
	return snap.Rules, nil
}

func sortPIEStats(stats []observe.RuleStats) {
	sort.Slice(stats, func(i, j int) bool { return stats[i].RuleID < stats[j].RuleID })
}

func buildPIERecommendations(stats []observe.RuleStats, opts policyAnalyzeOptions, now time.Time) []policyAnalyzeRecommendation {
	deadAfter := opts.DeadAfter
	if deadAfter <= 0 {
		deadAfter = defaultPolicyAnalyzeDeadAfter
	}
	if opts.MinDefers <= 0 {
		opts.MinDefers = 1
	}
	if opts.ApprovalThreshold <= 0 {
		opts.ApprovalThreshold = 0.9
	}
	cutoff := now.Add(-deadAfter)

	recs := make([]policyAnalyzeRecommendation, 0)
	for _, s := range stats {
		if !s.LastTriggered.IsZero() && s.LastTriggered.Before(cutoff) {
			recs = append(recs, policyAnalyzeRecommendation{
				RuleID: s.RuleID,
				Type:   "dead_rule",
				Reason: fmt.Sprintf("rule inactive since %s", s.LastTriggered.UTC().Format(time.RFC3339)),
			})
		}

		if s.Defers >= opts.MinDefers {
			total := s.Approvals + s.Rejections
			if total > 0 {
				rate := float64(s.Approvals) / float64(total)
				if rate >= opts.ApprovalThreshold {
					recs = append(recs, policyAnalyzeRecommendation{
						RuleID:       s.RuleID,
						Type:         "promote_to_permit",
						Reason:       "high approval rate suggests DEFER friction",
						ApprovalRate: rate,
						TotalDefers:  s.Defers,
					})
				}
			}
		}

		totalDecisions := s.Permits + s.Denies + s.Defers
		if totalDecisions >= 100 {
			permitRate := float64(s.Permits) / float64(totalDecisions)
			denyRate := float64(s.Denies) / float64(totalDecisions)
			if permitRate > 0.99 {
				recs = append(recs, policyAnalyzeRecommendation{
					RuleID: s.RuleID,
					Type:   "policy_drift_nearly_always_permits",
					Reason: "rule permits >99% of calls; validate necessity",
				})
			}
			if denyRate > 0.95 {
				recs = append(recs, policyAnalyzeRecommendation{
					RuleID: s.RuleID,
					Type:   "policy_drift_nearly_always_denies",
					Reason: "rule denies >95% of calls; validate scope",
				})
			}
		}
	}

	sort.Slice(recs, func(i, j int) bool {
		if recs[i].Type != recs[j].Type {
			return recs[i].Type < recs[j].Type
		}
		return recs[i].RuleID < recs[j].RuleID
	})
	return recs
}
