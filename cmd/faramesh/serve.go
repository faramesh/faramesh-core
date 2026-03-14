package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/cloud"
	"github.com/faramesh/faramesh-core/internal/daemon"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Faramesh governance daemon",
	Long: `faramesh serve starts the governance daemon. Agents connect via the
Unix socket (default: /tmp/faramesh.sock) to submit tool calls and receive
PERMIT/DENY/DEFER decisions. The daemon loads the policy file, opens the WAL
and SQLite DPR store, and starts accepting connections.

To stream DPR records to Faramesh Horizon, authenticate first:

  faramesh auth login
  faramesh serve --policy policy.yaml --sync-horizon`,
	RunE: runServe,
}

var (
	servePolicy     string
	serveDataDir    string
	serveSocket     string
	serveSlack      string
	serveLogLevel   string
	serveSyncHorizon bool
	serveProxyPort   int
	serveGRPCPort    int
	serveMCPProxyPort int
	serveMCPTarget   string
	serveMetricsPort int
	serveDPRDSN      string
)

func init() {
	serveCmd.Flags().StringVar(&servePolicy, "policy", "policy.yaml", "path to the policy YAML file")
	serveCmd.Flags().StringVar(&serveDataDir, "data-dir", "", "directory for WAL and DPR SQLite (default: $TMPDIR/faramesh)")
	serveCmd.Flags().StringVar(&serveSocket, "socket", sdk.SocketPath, "Unix socket path")
	serveCmd.Flags().StringVar(&serveSlack, "slack-webhook", "", "Slack webhook URL for DEFER notifications")
	serveCmd.Flags().StringVar(&serveLogLevel, "log-level", "info", "log level: debug|info|warn|error")
	serveCmd.Flags().BoolVar(&serveSyncHorizon, "sync-horizon", false, "stream DPR records to Faramesh Horizon cloud (requires: faramesh auth login)")
	serveCmd.Flags().IntVar(&serveProxyPort, "proxy-port", 0, "start HTTP proxy adapter on this port (0 disables)")
	serveCmd.Flags().IntVar(&serveGRPCPort, "grpc-port", 0, "start gRPC daemon adapter on this port (0 disables)")
	serveCmd.Flags().IntVar(&serveMCPProxyPort, "mcp-proxy-port", 0, "start MCP HTTP gateway on this port (0 disables)")
	serveCmd.Flags().StringVar(&serveMCPTarget, "mcp-target", "", "upstream MCP HTTP server base URL (required when --mcp-proxy-port is set)")
	serveCmd.Flags().IntVar(&serveMetricsPort, "metrics-port", 0, "start Prometheus metrics endpoint on this port (0 disables)")
	serveCmd.Flags().StringVar(&serveDPRDSN, "dpr-dsn", "", "PostgreSQL DSN for mirrored DPR writes")
}

func runServe(cmd *cobra.Command, args []string) error {
	log, err := buildLogger(serveLogLevel)
	if err != nil {
		return fmt.Errorf("build logger: %w", err)
	}
	defer log.Sync()

	cfg := daemon.Config{
		PolicyPath:   servePolicy,
		DataDir:      serveDataDir,
		SocketPath:   serveSocket,
		SlackWebhook: serveSlack,
		Log:          log,
		ProxyPort:    serveProxyPort,
		GRPCPort:     serveGRPCPort,
		MCPProxyPort: serveMCPProxyPort,
		MCPTarget:    serveMCPTarget,
		MetricsPort:  serveMetricsPort,
		DPRDSN:       serveDPRDSN,
	}

	if serveSyncHorizon {
		tok, err := cloud.LoadToken()
		if err != nil {
			return fmt.Errorf("read Horizon credentials: %w\nRun: faramesh auth login", err)
		}
		if tok == nil {
			return fmt.Errorf("not authenticated with Horizon\nRun: faramesh auth login")
		}
		if tok.IsExpired() {
			return fmt.Errorf("Horizon token expired\nRun: faramesh auth login")
		}
		cfg.HorizonToken = tok.Token
		cfg.HorizonURL = tok.HorizonURL
		cfg.HorizonOrgID = tok.OrgID
		log.Info("horizon sync enabled",
			zap.String("org", tok.OrgName),
			zap.String("user", tok.UserEmail),
			zap.String("url", tok.HorizonURL),
		)
	}

	d, err := daemon.New(cfg)
	if err != nil {
		return fmt.Errorf("init daemon: %w", err)
	}

	return d.Run(context.Background())
}

func buildLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	switch level {
	case "debug":
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "warn":
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	default:
		cfg.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	return cfg.Build()
}
