package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/core/policygen"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
)

var (
	suggestDataDir string
	suggestAgentID string
	suggestFormat  string
	suggestOutPath string
)

var suggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Generate a starter policy from observed tool inventory",
	RunE:  runSuggestCommand,
}

func init() {
	suggestCmd.Flags().StringVar(&suggestDataDir, "data-dir", "", "Faramesh data directory containing the tool inventory store")
	suggestCmd.Flags().StringVar(&suggestAgentID, "agent-id", "suggested-agent", "agent ID to embed into the generated policy")
	suggestCmd.Flags().StringVar(&suggestFormat, "format", "yaml", "output format: yaml|json")
	suggestCmd.Flags().StringVar(&suggestOutPath, "out", "", "optional file path to write output")
}

func runSuggestCommand(cmd *cobra.Command, _ []string) error {
	output, err := runSuggest(suggestOptions{
		DataDir: suggestDataDir,
		AgentID: suggestAgentID,
		Format:  suggestFormat,
		Now:     time.Now().UTC(),
	})
	if err != nil {
		return err
	}

	if strings.TrimSpace(suggestOutPath) != "" {
		if err := os.WriteFile(suggestOutPath, output, 0o644); err != nil {
			return fmt.Errorf("write suggestion output: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote suggested policy to %s\n", suggestOutPath)
		return nil
	}

	_, err = cmd.OutOrStdout().Write(output)
	return err
}

type suggestOptions struct {
	DataDir string
	AgentID string
	Format  string
	Now     time.Time
}

type suggestJSONOutput struct {
	GeneratedAt      string                     `json:"generated_at"`
	ObservedTools    int                        `json:"observed_tools"`
	TotalInvocations int64                      `json:"total_invocations"`
	Warnings         []string                   `json:"warnings,omitempty"`
	Recommendations  []policygen.Recommendation `json:"recommendations"`
	Policy           any                        `json:"policy"`
}

func runSuggest(opts suggestOptions) ([]byte, error) {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	if format == "" {
		format = "yaml"
	}
	if format != "yaml" && format != "json" {
		return nil, fmt.Errorf("invalid --format %q (expected yaml or json)", opts.Format)
	}

	store, err := toolinventory.OpenStore(filepath.Join(defaultSuggestDataDir(opts.DataDir), "faramesh-tool-inventory.db"))
	if err != nil {
		return nil, fmt.Errorf("open tool inventory: %w", err)
	}
	defer store.Close()

	entries, err := store.All()
	if err != nil {
		return nil, fmt.Errorf("read tool inventory: %w", err)
	}

	result := policygen.Generate(entries, policygen.Options{
		AgentID: opts.AgentID,
		Now:     opts.Now,
	})

	switch format {
	case "json":
		out, err := json.MarshalIndent(suggestJSONOutput{
			GeneratedAt:      result.GeneratedAt.Format(time.RFC3339),
			ObservedTools:    result.ObservedTools,
			TotalInvocations: result.TotalInvocations,
			Warnings:         result.Warnings,
			Recommendations:  result.Recommendations,
			Policy:           result.Doc,
		}, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("encode suggestion json: %w", err)
		}
		return append(out, '\n'), nil
	default:
		out, err := policygen.RenderYAML(result)
		if err != nil {
			return nil, fmt.Errorf("render policy yaml: %w", err)
		}
		return out, nil
	}
}

func defaultSuggestDataDir(dataDir string) string {
	if strings.TrimSpace(dataDir) != "" {
		return dataDir
	}
	return filepath.Join(os.TempDir(), "faramesh")
}
