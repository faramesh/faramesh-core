package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

var coverageCmd = &cobra.Command{
	Use:   "coverage",
	Short: "Report governance coverage from static discovery and observed runtime inventory",
	Args:  cobra.NoArgs,
	RunE:  runCoverageE,
}

var (
	coverageJSON     bool
	coverageCwd      string
	coverageDataDir  string
	coverageGapsOnly bool
)

type coverageReport struct {
	Root        string                          `json:"root"`
	DataDir     string                          `json:"data_dir"`
	Environment *runtimeenv.DetectedEnvironment `json:"environment,omitempty"`
	Summary     coverageSummary                 `json:"summary"`
	Tools       []coverageTool                  `json:"tools"`
}

type coverageSummary struct {
	ObservedTools int            `json:"observed_tools"`
	StaticTools   int            `json:"static_tools"`
	CombinedTools int            `json:"combined_tools"`
	Tiers         map[string]int `json:"tiers"`
}

type coverageTool struct {
	ToolID            string         `json:"tool_id"`
	Source            string         `json:"source"`
	CoverageTier      string         `json:"coverage_tier"`
	Observed          bool           `json:"observed"`
	StaticDiscovered  bool           `json:"static_discovered"`
	TotalInvocations  int64          `json:"total_invocations,omitempty"`
	Effects           map[string]int `json:"effects,omitempty"`
	InterceptAdapters []string       `json:"intercept_adapters,omitempty"`
	PolicyRuleIDs     []string       `json:"policy_rule_ids,omitempty"`
	Signals           []string       `json:"signals,omitempty"`
	KnownGaps         []string       `json:"known_gaps,omitempty"`
}

func init() {
	coverageCmd.Flags().BoolVar(&coverageJSON, "json", false, "print JSON")
	coverageCmd.Flags().StringVar(&coverageCwd, "cwd", "", "working directory to scan (default: current directory)")
	coverageCmd.Flags().StringVar(&coverageDataDir, "data-dir", "", "Faramesh data directory containing faramesh-tool-inventory.db")
	coverageCmd.Flags().BoolVar(&coverageGapsOnly, "gaps-only", false, "show only tools with known gaps or tier D/E")
}

func runCoverageE(_ *cobra.Command, _ []string) error {
	cwd := coverageCwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	dataDir := coverageDataDir
	if dataDir == "" {
		dataDir = filepath.Join(runtimeStateDirPath(""), "data")
	}

	discovery := runtimeenv.DiscoverProject(cwd)
	inventoryPath := filepath.Join(dataDir, "faramesh-tool-inventory.db")
	store, err := toolinventory.OpenStore(inventoryPath)
	if err != nil {
		return fmt.Errorf("open tool inventory: %w", err)
	}
	defer store.Close()

	entries, err := store.All()
	if err != nil {
		return fmt.Errorf("read tool inventory: %w", err)
	}
	report := buildCoverageReport(cwd, dataDir, discovery, entries)
	if coverageGapsOnly {
		report.Tools = filterCoverageGaps(report.Tools)
	}
	if coverageJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", body)
		return nil
	}

	fmt.Printf("Root:           %s\n", report.Root)
	fmt.Printf("Data Dir:       %s\n", report.DataDir)
	if report.Environment != nil {
		fmt.Printf("Runtime:        %s\n", report.Environment.Runtime)
		fmt.Printf("Framework Hint: %s\n", report.Environment.Framework)
	}
	fmt.Printf("Observed Tools: %d\n", report.Summary.ObservedTools)
	fmt.Printf("Static Tools:   %d\n", report.Summary.StaticTools)
	fmt.Printf("Combined Tools: %d\n", report.Summary.CombinedTools)
	fmt.Printf("Tier Counts:    A=%d B=%d C=%d D=%d E=%d\n",
		report.Summary.Tiers["A"],
		report.Summary.Tiers["B"],
		report.Summary.Tiers["C"],
		report.Summary.Tiers["D"],
		report.Summary.Tiers["E"],
	)
	fmt.Println()
	for _, tool := range report.Tools {
		fmt.Printf("%-22s tier=%-2s source=%-7s observed=%-5t static=%-5t calls=%d\n",
			tool.ToolID, tool.CoverageTier, tool.Source, tool.Observed, tool.StaticDiscovered, tool.TotalInvocations)
		if len(tool.KnownGaps) > 0 {
			for _, gap := range tool.KnownGaps {
				fmt.Printf("  gap: %s\n", gap)
			}
		}
	}
	return nil
}

func buildCoverageReport(root, dataDir string, discovery *runtimeenv.DiscoveryReport, entries []toolinventory.Entry) coverageReport {
	report := coverageReport{
		Root:    root,
		DataDir: dataDir,
		Summary: coverageSummary{Tiers: map[string]int{"A": 0, "B": 0, "C": 0, "D": 0, "E": 0}},
	}
	if discovery != nil {
		report.Environment = discovery.Environment
	}

	type aggregate struct {
		tool coverageTool
	}
	combined := map[string]*aggregate{}

	for _, entry := range entries {
		copyEffects := map[string]int{}
		for k, v := range entry.Effects {
			copyEffects[k] = v
		}
		combined[entry.ToolID] = &aggregate{tool: coverageTool{
			ToolID:            entry.ToolID,
			Source:            "runtime",
			CoverageTier:      defaultCoverageTier(entry.CoverageTier),
			Observed:          true,
			StaticDiscovered:  false,
			TotalInvocations:  entry.TotalInvocations,
			Effects:           copyEffects,
			InterceptAdapters: append([]string(nil), entry.InterceptAdapters...),
			PolicyRuleIDs:     append([]string(nil), entry.PolicyRuleIDs...),
		}}
	}
	report.Summary.ObservedTools = len(entries)

	staticToolSet := map[string]struct{}{}
	if discovery != nil {
		for _, discovered := range discovery.CandidateTools {
			staticToolSet[discovered.ID] = struct{}{}
			agg, ok := combined[discovered.ID]
			if !ok {
				agg = &aggregate{tool: coverageTool{
					ToolID:           discovered.ID,
					Source:           "static",
					CoverageTier:     "E",
					Observed:         false,
					StaticDiscovered: true,
				}}
				combined[discovered.ID] = agg
			}
			agg.tool.StaticDiscovered = true
			agg.tool.Source = combineSource(agg.tool.Source, "static")
			signal := discovered.Surface + ":" + discovered.Source
			if !slices.Contains(agg.tool.Signals, signal) {
				agg.tool.Signals = append(agg.tool.Signals, signal)
			}
			if agg.tool.CoverageTier == "" {
				agg.tool.CoverageTier = "E"
			}
		}
	}
	report.Summary.StaticTools = len(staticToolSet)

	report.Tools = make([]coverageTool, 0, len(combined))
	for _, agg := range combined {
		finalizeCoverageTool(&agg.tool)
		report.Tools = append(report.Tools, agg.tool)
		report.Summary.Tiers[agg.tool.CoverageTier]++
	}
	slices.SortFunc(report.Tools, func(a, b coverageTool) int {
		if a.CoverageTier != b.CoverageTier {
			return stringsCompare(a.CoverageTier, b.CoverageTier)
		}
		return stringsCompare(a.ToolID, b.ToolID)
	})
	report.Summary.CombinedTools = len(report.Tools)
	return report
}

func finalizeCoverageTool(tool *coverageTool) {
	tool.CoverageTier = defaultCoverageTier(tool.CoverageTier)
	if !tool.StaticDiscovered {
		tool.KnownGaps = append(tool.KnownGaps, "observed at runtime but not discovered statically")
	}
	if tool.StaticDiscovered && !tool.Observed {
		tool.KnownGaps = append(tool.KnownGaps, "discovered statically but not yet observed at runtime")
	}
	if len(tool.PolicyRuleIDs) == 0 {
		tool.KnownGaps = append(tool.KnownGaps, "no explicit matched policy rules recorded for this tool")
	}
	slices.Sort(tool.Signals)
	slices.Sort(tool.PolicyRuleIDs)
	slices.Sort(tool.InterceptAdapters)
}

func filterCoverageGaps(tools []coverageTool) []coverageTool {
	out := make([]coverageTool, 0, len(tools))
	for _, tool := range tools {
		if len(tool.KnownGaps) > 0 || tool.CoverageTier == "D" || tool.CoverageTier == "E" {
			out = append(out, tool)
		}
	}
	return out
}

func combineSource(current, next string) string {
	switch {
	case current == "" || current == next:
		return next
	case (current == "runtime" && next == "static") || (current == "static" && next == "runtime"):
		return "both"
	default:
		return current
	}
}

func defaultCoverageTier(tier string) string {
	switch tier {
	case "A", "B", "C", "D", "E":
		return tier
	default:
		return "E"
	}
}

func stringsCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
