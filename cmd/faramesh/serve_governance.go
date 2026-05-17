package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/faramesh/faramesh-core/internal/core/governance"
	"github.com/faramesh/faramesh-core/internal/daemon"
	"go.uber.org/zap"
)

var serveFromCompiled string

func init() {
	serveCmd.Flags().StringVar(&serveFromCompiled, "from-compiled", "", "load daemon configuration from governance.compiled.json (used by faramesh apply)")
	_ = serveCmd.Flags().MarkHidden("from-compiled")
}

func daemonConfigFromCompiled(log *zap.Logger) (daemon.Config, bool, error) {
	path := strings.TrimSpace(serveFromCompiled)
	if path == "" {
		return daemon.Config{}, false, nil
	}
	compiled, err := governance.LoadCompiledFromPath(path)
	if err != nil {
		return daemon.Config{}, true, err
	}
	cfg := compiled.ToDaemonConfig()
	cfg.Log = log
	return cfg, true, nil
}

func warnServeDeprecatedFlags() {
	if strings.TrimSpace(serveFromCompiled) != "" {
		return
	}
	for _, w := range serveDeprecationWarnings() {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
		fmt.Fprintf(os.Stderr, "  Migrate settings to governance.fms and run: faramesh apply\n")
	}
}
