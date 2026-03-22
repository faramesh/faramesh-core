package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/faramesh/faramesh-core/internal/artifactverify"
	"github.com/faramesh/faramesh-core/internal/reprobuild"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify artifact digests and signatures (supply chain)",
	Long: `Commands for verifying file SHA-256 digests against a manifest and Ed25519 signatures.

This is distinct from "faramesh hub verify" (registry policy packs).

Examples:
  faramesh verify digest ./policy.yaml
  faramesh verify manifest ./manifest.json --base-dir .
  faramesh verify manifest-generate --base-dir . policy.yaml packs/foo/policy.yaml
  faramesh verify buildinfo --emit
  faramesh verify buildinfo --emit | faramesh verify buildinfo -
  faramesh verify signature --public-key pub.pem --file policy.yaml --signature sig.b64`,
}

var (
	verifyManifestPath  string
	verifyBaseDir         string
	verifyManifestGenOut  string
	verifySigPub          string
	verifySigFile         string
	verifySigData         string
)

var verifyDigestCmd = &cobra.Command{
	Use:   "digest <file>",
	Short: "Print lowercase hex SHA-256 of a file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		h, err := artifactverify.FileSHA256Hex(args[0])
		if err != nil {
			return err
		}
		fmt.Println(h)
		return nil
	},
}

var verifyManifestCmd = &cobra.Command{
	Use:   "manifest <manifest.json>",
	Short: "Verify files match SHA-256 entries in a JSON manifest",
	Args:  cobra.ExactArgs(1),
	Long: `Manifest format:
  { "version": 1, "artifacts": [ { "path": "rel/path", "sha256": "hex..." } ] }

Paths are relative to --base-dir (default: current directory).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		m, err := artifactverify.LoadManifestJSON(raw)
		if err != nil {
			return err
		}
		base := verifyBaseDir
		if base == "" {
			base = "."
		}
		if err := artifactverify.VerifyManifest(base, m); err != nil {
			return err
		}
		color.Green("✓ all %d artifacts match manifest", len(m.Artifacts))
		return nil
	},
}

var verifyManifestGenCmd = &cobra.Command{
	Use:   "manifest-generate [files...]",
	Short: "Emit a version-1 SHA-256 manifest for listed files",
	Args:  cobra.MinimumNArgs(1),
	Long: `Each file must sit under --base-dir (default "."). Output is JSON suitable for "faramesh verify manifest".

Example:
  faramesh verify manifest-generate --base-dir faramesh-core --output manifest.json faramesh-core/go.mod faramesh-core/cmd/faramesh/main.go`,
	RunE: func(cmd *cobra.Command, args []string) error {
		base := verifyBaseDir
		if base == "" {
			base = "."
		}
		m, err := artifactverify.BuildManifestV1(base, args)
		if err != nil {
			return err
		}
		raw, err := artifactverify.MarshalManifestJSONPretty(m)
		if err != nil {
			return err
		}
		if verifyManifestGenOut != "" {
			return os.WriteFile(verifyManifestGenOut, append(raw, '\n'), 0o644)
		}
		fmt.Print(string(raw))
		fmt.Println()
		return nil
	},
}

var verifyBuildinfoEmit bool

var verifyBuildinfoCmd = &cobra.Command{
	Use:   "buildinfo [expected.json]",
	Short: "Emit or compare Go build metadata (reproducible-build / attestation)",
	Long: `Emits a JSON fingerprint from runtime/debug.ReadBuildInfo(), or compares the
running binary to a JSON file. Empty fields in the expected file are ignored so CI
can assert only vcs.revision, main_sum, GOOS/GOARCH, etc.

Examples:
  faramesh verify buildinfo --emit
  faramesh verify buildinfo expected-buildinfo.json
  faramesh verify buildinfo --emit | faramesh verify buildinfo -`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cur, err := reprobuild.Current()
		if err != nil {
			return err
		}
		if verifyBuildinfoEmit {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(cur); err != nil {
				return err
			}
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("expected JSON path required (use --emit to print current fingerprint)")
		}
		var raw []byte
		var readErr error
		if args[0] == "-" {
			raw, readErr = io.ReadAll(os.Stdin)
		} else {
			raw, readErr = os.ReadFile(args[0])
		}
		if readErr != nil {
			return readErr
		}
		var exp reprobuild.Fingerprint
		if err := json.Unmarshal(raw, &exp); err != nil {
			return fmt.Errorf("parse expected buildinfo: %w", err)
		}
		diff := reprobuild.Compare(&exp, cur)
		if len(diff) > 0 {
			for _, line := range diff {
				_, _ = fmt.Fprintln(os.Stderr, line)
			}
			return fmt.Errorf("%d buildinfo mismatch(es)", len(diff))
		}
		color.Green("✓ buildinfo matches")
		return nil
	},
}

var verifySignatureCmd = &cobra.Command{
	Use:   "signature",
	Short: "Verify Ed25519 signature over a file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifySigPub == "" || verifySigFile == "" || verifySigData == "" {
			return fmt.Errorf("--public-key, --file, and --signature are required")
		}
		pubPEM, err := os.ReadFile(verifySigPub)
		if err != nil {
			return err
		}
		sigBytes, err := loadSignatureArg(verifySigData)
		if err != nil {
			return err
		}
		if err := artifactverify.VerifyFileSignature(pubPEM, verifySigFile, sigBytes); err != nil {
			return err
		}
		color.Green("✓ signature OK for %s", verifySigFile)
		return nil
	},
}

func loadSignatureArg(s string) ([]byte, error) {
	if b, err := os.ReadFile(s); err == nil {
		return artifactverify.DecodeSignatureArg(string(b))
	}
	return artifactverify.DecodeSignatureArg(s)
}

func init() {
	verifyManifestCmd.Flags().StringVar(&verifyBaseDir, "base-dir", ".", "directory containing artifact paths")

	verifyManifestGenCmd.Flags().StringVar(&verifyBaseDir, "base-dir", ".", "directory that manifest paths are relative to")
	verifyManifestGenCmd.Flags().StringVar(&verifyManifestGenOut, "output", "", "write manifest to file (default: stdout)")

	verifySignatureCmd.Flags().StringVar(&verifySigPub, "public-key", "", "path to Ed25519 public key PEM")
	verifySignatureCmd.Flags().StringVar(&verifySigFile, "file", "", "file that was signed")
	verifySignatureCmd.Flags().StringVar(&verifySigData, "signature", "", "base64 Ed25519 signature (or path to file containing base64)")

	verifyCmd.AddCommand(verifyDigestCmd)
	verifyCmd.AddCommand(verifyManifestCmd)
	verifyCmd.AddCommand(verifyManifestGenCmd)
	verifyBuildinfoCmd.Flags().BoolVar(&verifyBuildinfoEmit, "emit", false, "print JSON fingerprint for this binary to stdout")
	verifyCmd.AddCommand(verifyBuildinfoCmd)
	verifyCmd.AddCommand(verifySignatureCmd)
	rootCmd.AddCommand(verifyCmd)
}
