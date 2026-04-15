package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/runtimeenv"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

var (
	gapsJSON     bool
	gapsCwd      string
	gapsDataDir  string
	gapsPolicy   string
)

type gapsReport struct {
	Root                  string   `json:"root"`
	DataDir               string   `json:"data_dir"`
	PolicyPath            string   `json:"policy_path,omitempty"`
	StaticNotObserved     []string `json:"static_not_observed"`
	ObservedNotStatic     []string `json:"observed_not_static"`
	ObservedNotPolicy     []string `json:"observed_not_policy_visible"`
	StaticNotPolicy       []string `json:"static_not_policy_visible"`
	ShadowOnlyGovernance  []string `json:"shadow_only_governance"`
	Warnings              []string `json:"warnings,omitempty"`
}

var gapsCmd = &cobra.Command{
	Use:   "gaps",
	Short: "Report governance coverage gaps across discovery, runtime, and policy",
	Args:  cobra.NoArgs,
	RunE:  runGapsE,
}

func init() {
	gapsCmd.Flags().BoolVar(&gapsJSON, "json", false, "print JSON")
	gapsCmd.Flags().StringVar(&gapsCwd, "cwd", "", "working directory to scan (default: current directory)")
	gapsCmd.Flags().StringVar(&gapsDataDir, "data-dir", "", "Faramesh data directory containing faramesh-tool-inventory.db")
	gapsCmd.Flags().StringVar(&gapsPolicy, "policy", "", "optional policy file used to check tool visibility")
}

func runGapsE(_ *cobra.Command, _ []string) error {
	cwd := gapsCwd
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	dataDir := gapsDataDir
	if dataDir == "" {
		dataDir = filepath.Join(os.TempDir(), "faramesh")
	}

	discovery := runtimeenv.DiscoverProject(cwd)
	store, err := toolinventory.OpenStore(filepath.Join(dataDir, "faramesh-tool-inventory.db"))
	if err != nil {
		return fmt.Errorf("open tool inventory: %w", err)
	}
	defer store.Close()

	entries, err := store.All()
	if err != nil {
		return fmt.Errorf("read tool inventory: %w", err)
	}

	report, err := buildGapsReport(cwd, dataDir, gapsPolicy, discovery, entries)
	if err != nil {
		return err
	}
	if gapsJSON {
		body, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s\n", body)
		return nil
	}

	fmt.Printf("Root:                %s\n", report.Root)
	fmt.Printf("Data Dir:            %s\n", report.DataDir)
	if report.PolicyPath != "" {
		fmt.Printf("Policy:              %s\n", report.PolicyPath)
	}
	fmt.Printf("Static not observed: %d\n", len(report.StaticNotObserved))
	fmt.Printf("Observed not static: %d\n", len(report.ObservedNotStatic))
	fmt.Printf("Observed not policy: %d\n", len(report.ObservedNotPolicy))
	fmt.Printf("Static not policy:   %d\n", len(report.StaticNotPolicy))
	fmt.Printf("Shadow-only:         %d\n", len(report.ShadowOnlyGovernance))
	for _, warning := range report.Warnings {
		fmt.Printf("warning: %s\n", warning)
	}
	printGapList("static-only tools", report.StaticNotObserved)
	printGapList("runtime-only tools", report.ObservedNotStatic)
	printGapList("runtime tools missing policy coverage", report.ObservedNotPolicy)
	printGapList("discovered tools missing policy coverage", report.StaticNotPolicy)
	printGapList("shadow-only governance signals", report.ShadowOnlyGovernance)
	return nil
}

func buildGapsReport(root, dataDir, policyPath string, discovery *runtimeenv.DiscoveryReport, entries []toolinventory.Entry) (gapsReport, error) {
	report := gapsReport{
		Root:                 root,
		DataDir:              dataDir,
		PolicyPath:           strings.TrimSpace(policyPath),
		StaticNotObserved:    []string{},
		ObservedNotStatic:    []string{},
		ObservedNotPolicy:    []string{},
		StaticNotPolicy:      []string{},
		ShadowOnlyGovernance: []string{},
	}

	var doc *policy.Doc
	if report.PolicyPath != "" {
		loaded, _, err := policy.LoadFile(report.PolicyPath)
		if err != nil {
			return gapsReport{}, fmt.Errorf("load policy: %w", err)
		}
		doc = loaded
	} else {
		report.Warnings = append(report.Warnings, "no --policy provided; policy visibility checks fall back to matched runtime rule IDs only")
	}

	staticTools := map[string]struct{}{}
	if discovery != nil {
		for _, tool := range discovery.CandidateTools {
			staticTools[tool.ID] = struct{}{}
		}
	}

	runtimeTools := map[string]toolinventory.Entry{}
	for _, entry := range entries {
		runtimeTools[entry.ToolID] = entry
	}

	for toolID, entry := range runtimeTools {
		if _, ok := staticTools[toolID]; !ok {
			report.ObservedNotStatic = append(report.ObservedNotStatic, toolID)
		}
		if !toolCoveredByPolicy(toolID, entry, doc) {
			report.ObservedNotPolicy = append(report.ObservedNotPolicy, toolID)
		}
		if len(entry.PolicyRuleIDs) == 0 {
			report.ShadowOnlyGovernance = append(report.ShadowOnlyGovernance, toolID)
		}
	}

	for toolID := range staticTools {
		if _, ok := runtimeTools[toolID]; !ok {
			report.StaticNotObserved = append(report.StaticNotObserved, toolID)
		}
		if !toolCoveredByPolicy(toolID, toolinventory.Entry{}, doc) {
			report.StaticNotPolicy = append(report.StaticNotPolicy, toolID)
		}
	}

	sortGapStrings(&report.StaticNotObserved)
	sortGapStrings(&report.ObservedNotStatic)
	sortGapStrings(&report.ObservedNotPolicy)
	sortGapStrings(&report.StaticNotPolicy)
	sortGapStrings(&report.ShadowOnlyGovernance)
	return report, nil
}

func toolCoveredByPolicy(toolID string, entry toolinventory.Entry, doc *policy.Doc) bool {
	if doc == nil {
		return len(entry.PolicyRuleIDs) > 0
	}
	for _, rule := range doc.Rules {
		if ruleMatchesTool(rule.Match.Tool, toolID) {
			return true
		}
	}
	return false
}

func ruleMatchesTool(pattern, toolID string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	matched, err := path.Match(pattern, toolID)
	return err == nil && matched
}

func sortGapStrings(values *[]string) {
	slices.Sort(*values)
	*values = slices.Compact(*values)
}

func printGapList(label string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Printf("\n%s:\n", label)
	for _, value := range values {
		fmt.Printf("  - %s\n", value)
	}
}
