package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key utilities (export/inspect)",
}

var keyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export public keys",
}

var keyExportDPRCmd = &cobra.Command{
	Use:   "dpr",
	Short: "Export DPR Ed25519 public key and metadata",
	RunE: func(cmd *cobra.Command, args []string) error {
		dataDir, _ := cmd.Flags().GetString("data-dir")
		if strings.TrimSpace(dataDir) == "" {
			home, err := os.UserHomeDir()
			if err != nil || strings.TrimSpace(home) == "" {
				dataDir = filepath.Join(os.TempDir(), "faramesh", "runtime", "data")
			} else {
				dataDir = filepath.Join(home, ".faramesh", "runtime", "data")
			}
		}
		pubPath := filepath.Join(dataDir, "faramesh.ed25519.pub")
		metaPath := filepath.Join(dataDir, "faramesh.ed25519.meta.json")

		out := map[string]any{
			"data_dir": dataDir,
			"found":    false,
		}

		if b, err := os.ReadFile(pubPath); err == nil {
			pubB64 := strings.TrimSpace(string(b))
			pubBytes, _ := base64.StdEncoding.DecodeString(pubB64)
			out["found"] = true
			out["public_key_b64"] = pubB64
			out["public_key_len"] = len(pubBytes)
		}
		if bm, err := os.ReadFile(metaPath); err == nil {
			var meta any
			_ = json.Unmarshal(bm, &meta)
			out["metadata"] = meta
		}
		out["exported_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		enc, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(enc))
		return nil
	},
}

func init() {
	keyExportDPRCmd.Flags().String("data-dir", "", "data directory where faramesh keys are stored (default: ~/.faramesh/runtime/data)")
	keyExportCmd.AddCommand(keyExportDPRCmd)
	keyCmd.AddCommand(keyExportCmd)
	rootCmd.AddCommand(keyCmd)
}
