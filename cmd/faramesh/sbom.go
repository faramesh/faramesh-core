package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/sbom"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Emit CycloneDX JSON SBOM for this binary (Go module dependencies)",
	Long: `Generates a CycloneDX 1.5 JSON document from runtime/debug.ReadBuildInfo(),
listing the main module and required dependencies. Use for CI, SBOM archives, and
supply-chain review (overlaps NIST SSDF / SLSA consumption practices).

  faramesh sbom > faramesh.cdx.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		b, err := sbom.GenerateJSON("", "")
		if err != nil {
			return err
		}
		_, err = fmt.Fprint(os.Stdout, string(b))
		return err
	},
}

func init() {
	rootCmd.AddCommand(sbomCmd)
}
