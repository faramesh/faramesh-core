package main

import (
	"context"
	"fmt"

	"github.com/faramesh/faramesh-core/internal/daemon"
	"github.com/spf13/cobra"
)

func runServeWithConfig(_ *cobra.Command, cfg daemon.Config) error {
	d, err := daemon.New(cfg)
	if err != nil {
		return fmt.Errorf("init daemon: %w", err)
	}
	return d.Run(context.Background())
}
