package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/artifactverify"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign artifacts with Ed25519 (supply chain)",
	Long: `Sign or emit manifests for reproducibility checks. Distinct from hub registry signing.

Examples:
  faramesh sign file --private-key key.pem --file policy.yaml --output sig.b64`,
}

var (
	signPrivPath string
	signFilePath string
	signOutPath  string
)

var signFileCmd = &cobra.Command{
	Use:   "file",
	Short: "Sign a file with an Ed25519 private key (PEM)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if signPrivPath == "" || signFilePath == "" {
			return fmt.Errorf("--private-key and --file are required")
		}
		privPEM, err := os.ReadFile(signPrivPath)
		if err != nil {
			return err
		}
		sig, err := artifactverify.SignFile(privPEM, signFilePath)
		if err != nil {
			return err
		}
		out := base64.StdEncoding.EncodeToString(sig)
		if signOutPath != "" {
			return os.WriteFile(signOutPath, []byte(out+"\n"), 0o600)
		}
		fmt.Print(out)
		fmt.Println()
		return nil
	},
}

func init() {
	signFileCmd.Flags().StringVar(&signPrivPath, "private-key", "", "path to Ed25519 private key PEM")
	signFileCmd.Flags().StringVar(&signFilePath, "file", "", "file to sign")
	signFileCmd.Flags().StringVar(&signOutPath, "output", "", "write base64 signature to file (default: stdout)")

	signCmd.AddCommand(signFileCmd)
	rootCmd.AddCommand(signCmd)
}
