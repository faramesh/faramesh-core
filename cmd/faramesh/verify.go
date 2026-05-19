package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/artifactverify"
	"github.com/faramesh/faramesh-core/internal/reprobuild"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Generate and inspect supply-chain verification artifacts",
}

var verifyManifestGenerateCmd = &cobra.Command{
	Use:   "manifest-generate <files...>",
	Short: "Generate an integrity manifest for one or more files",
	Long: `Generate a version-1 SHA-256 manifest for the supplied files.

Paths are recorded relative to --base-dir and the manifest is sorted by path.

  faramesh verify manifest-generate --base-dir . --output integrity.json policy.yaml`,
	Args: cobra.MinimumNArgs(1),
	RunE: runVerifyManifestGenerate,
}

var verifyBuildinfoCmd = &cobra.Command{
	Use:   "buildinfo",
	Short: "Emit the running binary build fingerprint as JSON",
	Long: `Emit the runtime build fingerprint used by strict preflight checks.

The output is the JSON snapshot consumed by buildinfo-expected gates.

  faramesh verify buildinfo --emit`,
	RunE: runVerifyBuildinfo,
}

var (
	verifyManifestBaseDir string
	verifyManifestOutput   string
	verifyBuildinfoEmit    bool
)

func init() {
	verifyManifestGenerateCmd.Flags().StringVar(&verifyManifestBaseDir, "base-dir", ".", "base directory for relative manifest paths")
	verifyManifestGenerateCmd.Flags().StringVar(&verifyManifestOutput, "output", "", "write the manifest to a file instead of stdout")

	verifyBuildinfoCmd.Flags().BoolVar(&verifyBuildinfoEmit, "emit", false, "emit the buildinfo JSON to stdout")

	verifyCmd.AddCommand(verifyManifestGenerateCmd)
	verifyCmd.AddCommand(verifyBuildinfoCmd)
}

func runVerifyManifestGenerate(cmd *cobra.Command, args []string) error {
	baseDir := strings.TrimSpace(verifyManifestBaseDir)
	if baseDir == "" {
		baseDir = "."
	}

	manifest, err := artifactverify.BuildManifestV1(baseDir, args)
	if err != nil {
		return err
	}
	raw, err := artifactverify.MarshalManifestJSONPretty(manifest)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	outputPath := strings.TrimSpace(verifyManifestOutput)
	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return fmt.Errorf("create manifest output dir: %w", err)
		}
		if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		return nil
	}

	_, err = fmt.Fprint(cmd.OutOrStdout(), string(raw))
	return err
}

func runVerifyBuildinfo(cmd *cobra.Command, _ []string) error {
	fingerprint, err := reprobuild.Current()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(fingerprint, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	if !verifyBuildinfoEmit {
		verifyBuildinfoEmit = true
	}
	_, err = fmt.Fprint(cmd.OutOrStdout(), string(raw))
	return err
}