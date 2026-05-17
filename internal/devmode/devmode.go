// Package devmode wires in-process dev providers and WAL for faramesh dev.
package devmode

import (
	"os"
	"path/filepath"

	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/daemon"
	"github.com/faramesh/faramesh-core/internal/provider"
)

// Apply configures daemon.Config for local development (FARAMESH.md §11).
func Apply(cfg *daemon.Config, stackDir string) {
	if cfg == nil {
		return
	}
	cfg.DevMode = true
	cfg.WALBackend = "memory"
	home, _ := os.UserHomeDir()
	if home == "" {
		home = stackDir
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(home, ".faramesh", "runtime", "faramesh.sock")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(stackDir, ".faramesh", "dev-data")
	}
	_ = os.MkdirAll(cfg.DataDir, 0o755)
	_ = os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o755)

	// Stub providers when stack declares none (FARAMESH.md §11).
	if len(cfg.Providers) == 0 {
		cfg.Providers = []provider.Spec{
			{Name: "vault", Type: "dev-vault", Config: map[string]string{}},
			{Name: "spiffe", Type: "dev-spiffe", Config: map[string]string{}},
			{Name: "kms", Type: "dev-kms", Config: map[string]string{}},
		}
	}
	cfg.AllowEnvCredentialFallback = true
	cfg.DPRSigner = "localkms://dev"
}

// NewWAL returns an in-memory WAL for dev mode.
func NewWAL() dpr.Writer {
	return &dpr.NullWAL{}
}
