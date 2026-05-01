package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/spf13/cobra"
)

var (
    keyRotateDataDir string
    keyRotateGenerate bool
    keyRotateNewKeyFile string
    keyRotateApply bool
)

var keyRotateCmd = &cobra.Command{
    Use:   "rotate",
    Short: "Rotate DPR Ed25519 keypair",
    Long:  "Rotate the DPR Ed25519 keypair. By default runs as a dry-run. Use --apply to persist changes.",
    RunE: func(cmd *cobra.Command, args []string) error {
        dataDir := keyRotateDataDir
        if dataDir == "" {
            home, _ := os.UserHomeDir()
            if home == "" {
                dataDir = filepath.Join(os.TempDir(), "faramesh", "runtime", "data")
            } else {
                dataDir = filepath.Join(home, ".faramesh", "runtime", "data")
            }
        }
        privPath := filepath.Join(dataDir, "faramesh.ed25519.key")
        pubPath := filepath.Join(dataDir, "faramesh.ed25519.pub")
        metaPath := filepath.Join(dataDir, "faramesh.ed25519.meta.json")

        // Describe planned actions
        fmt.Println("DPR key rotate — dry-run summary")
        fmt.Println("data_dir:", dataDir)
        if _, err := os.Stat(privPath); err == nil {
            fmt.Println("existing_private_key:", privPath)
        } else {
            fmt.Println("existing_private_key: (not found)")
        }

        if !keyRotateGenerate && keyRotateNewKeyFile == "" {
            fmt.Println("no new key specified; use --generate or --new-key-file to provide a replacement key")
            if !keyRotateApply {
                fmt.Println("dry-run complete")
                return nil
            }
        }

        var newPriv ed25519.PrivateKey
        var newPub ed25519.PublicKey
        if keyRotateGenerate {
            pub, priv, err := ed25519.GenerateKey(rand.Reader)
            if err != nil {
                return fmt.Errorf("generate key: %w", err)
            }
            newPriv = priv
            newPub = pub
            fmt.Println("generated new keypair (in-memory)")
        } else if keyRotateNewKeyFile != "" {
            data, err := os.ReadFile(keyRotateNewKeyFile)
            if err != nil {
                return fmt.Errorf("read new key file: %w", err)
            }
            b, err := base64.StdEncoding.DecodeString(string(data))
            if err != nil {
                return fmt.Errorf("decode new key file as base64: %w", err)
            }
            if len(b) != ed25519.PrivateKeySize {
                return fmt.Errorf("new key has invalid size: %d", len(b))
            }
            newPriv = ed25519.PrivateKey(b)
            pub, ok := newPriv.Public().(ed25519.PublicKey)
            if !ok {
                return fmt.Errorf("derive public key failed")
            }
            newPub = pub
            fmt.Println("loaded new private key from file")
        }

        if !keyRotateApply {
            fmt.Println("dry-run: no on-disk changes will be made. Pass --apply to execute rotation.")
            return nil
        }

        // Apply: backup existing files and write new key
        ts := time.Now().UTC().Format("20060102T150405Z")
        if _, err := os.Stat(privPath); err == nil {
            _ = os.Rename(privPath, privPath+"."+ts+".bak")
        }
        if _, err := os.Stat(pubPath); err == nil {
            _ = os.Rename(pubPath, pubPath+"."+ts+".bak")
        }
        if _, err := os.Stat(metaPath); err == nil {
            _ = os.Rename(metaPath, metaPath+"."+ts+".bak")
        }

        encPriv := base64.StdEncoding.EncodeToString(newPriv)
        if err := os.WriteFile(privPath, []byte(encPriv), 0o600); err != nil {
            return fmt.Errorf("write new private key: %w", err)
        }
        encPub := base64.StdEncoding.EncodeToString(newPub)
        if err := os.WriteFile(pubPath, []byte(encPub), 0o644); err != nil {
            return fmt.Errorf("write new public key: %w", err)
        }

        fmt.Println("rotation applied: new key written and backups created")
        fmt.Println("next: run 'faramesh compliance resign --apply' to re-sign historical records if desired")
        return nil
    },
}

func init() {
    keyRotateCmd.Flags().StringVar(&keyRotateDataDir, "data-dir", "", "data directory where faramesh keys are stored (default: ~/.faramesh/runtime/data)")
    keyRotateCmd.Flags().BoolVar(&keyRotateGenerate, "generate", false, "generate a new ed25519 keypair")
    keyRotateCmd.Flags().StringVar(&keyRotateNewKeyFile, "new-key-file", "", "path to base64-encoded ed25519 private key file to use as replacement")
    keyRotateCmd.Flags().BoolVar(&keyRotateApply, "apply", false, "apply changes (default: dry-run)")
    keyCmd.AddCommand(keyRotateCmd)
}
