// Package daemon implements the faramesh serve lifecycle:
// load policy, open WAL + SQLite, start SDK socket server, handle signals.
package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"go.uber.org/zap"

	gatewaydaemon "github.com/faramesh/faramesh-core/internal/adapter/daemon"
	"github.com/faramesh/faramesh-core/internal/adapter/mcp"
	"github.com/faramesh/faramesh-core/internal/adapter/proxy"
	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/cloud"
	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/session"
)

// Config configures the daemon.
type Config struct {
	PolicyPath   string
	DataDir      string
	SocketPath   string
	SlackWebhook string
	Log          *zap.Logger

	// Horizon sync (optional). If HorizonToken is set, DPR records are
	// streamed to the Horizon API in real time.
	HorizonToken string
	HorizonURL   string
	HorizonOrgID string

	ProxyPort    int
	GRPCPort     int
	MCPProxyPort int
	MCPTarget    string
	MetricsPort  int
	DPRDSN       string
}

// Daemon is the governance daemon.
type Daemon struct {
	cfg        Config
	engine     *policy.AtomicEngine
	server     *sdk.Server
	wal        dpr.Writer
	store      dpr.StoreBackend
	syncer     *cloud.Syncer
	proxy      *proxy.Server
	grpc       *gatewaydaemon.Server
	grpcLis    net.Listener
	mcpGateway *mcp.HTTPGateway
	metricsSrv *http.Server
	log        *zap.Logger
}

// New creates a Daemon from a Config. Call Run() to start it.
func New(cfg Config) (*Daemon, error) {
	if cfg.Log == nil {
		log, _ := zap.NewProduction()
		cfg.Log = log
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(os.TempDir(), "faramesh")
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = sdk.SocketPath
	}
	return &Daemon{cfg: cfg, log: cfg.Log}, nil
}

// Run starts the daemon and blocks until a signal is received.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.start(); err != nil {
		return err
	}
	d.log.Info("faramesh daemon running",
		zap.String("socket", d.cfg.SocketPath),
		zap.String("policy", d.cfg.PolicyPath),
		zap.String("data_dir", d.cfg.DataDir),
	)

	// Start Horizon syncer in background if configured.
	if d.syncer != nil {
		go d.syncer.Run()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				d.log.Info("SIGHUP received — reloading policy", zap.String("path", d.cfg.PolicyPath))
				if err := d.reloadPolicy(); err != nil {
					d.log.Error("policy reload failed — continuing with current policy", zap.Error(err))
				}
			default:
				d.log.Info("shutting down", zap.String("signal", sig.String()))
				return d.stop()
			}
		case <-ctx.Done():
			return d.stop()
		}
	}
}

// reloadPolicy re-reads the policy file and hot-swaps the AtomicEngine.
// If compilation fails the running engine is untouched.
func (d *Daemon) reloadPolicy() error {
	doc, version, err := policy.LoadFile(d.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if errs := policy.Validate(doc); len(errs) > 0 {
		for _, e := range errs {
			d.log.Warn("policy validation warning", zap.String("error", e))
		}
	}
	if err := d.engine.HotReload(doc, version); err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	d.log.Info("policy reloaded",
		zap.String("version", version),
		zap.String("agent_id", doc.AgentID),
		zap.Int("rules", len(doc.Rules)),
	)
	return nil
}

// Server returns the SDK server (used by audit tail).
func (d *Daemon) Server() *sdk.Server { return d.server }

func (d *Daemon) start() error {
	if err := os.MkdirAll(d.cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Load and compile policy.
	doc, version, err := policy.LoadFile(d.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	if errs := policy.Validate(doc); len(errs) > 0 {
		for _, e := range errs {
			d.log.Warn("policy validation error", zap.String("error", e))
		}
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	d.engine = policy.NewAtomicEngine(engine)
	d.log.Info("policy loaded",
		zap.String("version", version),
		zap.String("agent_id", doc.AgentID),
		zap.Int("rules", len(doc.Rules)),
	)

	// Open WAL.
	walPath := filepath.Join(d.cfg.DataDir, "faramesh.wal")
	wal, err := dpr.OpenWAL(walPath)
	if err != nil {
		return fmt.Errorf("open WAL: %w", err)
	}
	d.wal = wal

	// Open SQLite DPR store.
	dbPath := filepath.Join(d.cfg.DataDir, "faramesh.db")
	sqliteStore, err := dpr.OpenStore(dbPath)
	if err != nil {
		d.log.Warn("failed to open DPR SQLite store; audit queries will be unavailable",
			zap.Error(err))
	}

	// Optional PostgreSQL mirror for DPR writes.
	var store dpr.StoreBackend
	if sqliteStore != nil {
		store = sqliteStore
	}
	if d.cfg.DPRDSN != "" {
		pgStore, pgErr := dpr.OpenPGStore(d.cfg.DPRDSN)
		if pgErr != nil {
			return fmt.Errorf("open PostgreSQL DPR store: %w", pgErr)
		}
		if store != nil {
			store = dpr.NewMultiStore(store, pgStore)
			d.log.Info("DPR dual-write enabled (sqlite primary + postgres mirror)")
		} else {
			store = pgStore
			d.log.Info("DPR PostgreSQL store enabled (primary)")
		}
	}
	d.store = store

	// Write PID file so `faramesh policy reload` can find the daemon.
	pidPath := filepath.Join(d.cfg.DataDir, "faramesh.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		d.log.Warn("failed to write PID file", zap.String("path", pidPath), zap.Error(err))
	}

	// Build pipeline.
	pipeline := core.NewPipeline(core.Config{
		Engine:   d.engine,
		WAL:      wal,
		Store:    store,
		Sessions: session.NewManager(),
		Defers:   deferwork.NewWorkflow(d.cfg.SlackWebhook),
	})

	// Wire up Horizon sync if configured.
	if d.cfg.HorizonToken != "" {
		d.syncer = cloud.NewSyncer(cloud.SyncConfig{
			Token:      d.cfg.HorizonToken,
			HorizonURL: d.cfg.HorizonURL,
			OrgID:      d.cfg.HorizonOrgID,
			AgentID:    doc.AgentID,
			Log:        d.log,
		})
		pipeline.SetHorizonSyncer(&horizonSyncAdapter{s: d.syncer})
	}

	// Start SDK socket server.
	server := sdk.NewServer(pipeline, d.log)
	if err := server.Listen(d.cfg.SocketPath); err != nil {
		return fmt.Errorf("start SDK server: %w", err)
	}
	d.server = server

	if d.cfg.ProxyPort > 0 {
		d.proxy = proxy.NewServer(pipeline, d.log)
		if err := d.proxy.Listen(fmt.Sprintf(":%d", d.cfg.ProxyPort)); err != nil {
			return fmt.Errorf("start proxy adapter: %w", err)
		}
	}

	if d.cfg.GRPCPort > 0 {
		d.grpc = gatewaydaemon.NewServer(gatewaydaemon.Config{Pipeline: pipeline})
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", d.cfg.GRPCPort))
		if err != nil {
			return fmt.Errorf("start gRPC adapter listener: %w", err)
		}
		d.grpcLis = lis
		go func() {
			if err := d.grpc.Serve(lis); err != nil {
				d.log.Error("gRPC adapter stopped", zap.Error(err))
			}
		}()
		d.log.Info("gRPC adapter listening", zap.Int("port", d.cfg.GRPCPort))
	}

	if d.cfg.MCPProxyPort > 0 {
		if d.cfg.MCPTarget == "" {
			return fmt.Errorf("--mcp-target is required when --mcp-proxy-port is set")
		}
		d.mcpGateway = mcp.NewHTTPGateway(pipeline, doc.AgentID, d.cfg.MCPTarget, d.log)
		if err := d.mcpGateway.Listen(fmt.Sprintf(":%d", d.cfg.MCPProxyPort)); err != nil {
			return fmt.Errorf("start MCP HTTP gateway: %w", err)
		}
	}

	if d.cfg.MetricsPort > 0 {
		mux := http.NewServeMux()
		mux.Handle("/metrics", observe.Default.Handler())
		d.metricsSrv = &http.Server{Addr: fmt.Sprintf(":%d", d.cfg.MetricsPort), Handler: mux}
		go func() {
			if err := d.metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				d.log.Error("metrics endpoint stopped", zap.Error(err))
			}
		}()
		d.log.Info("metrics endpoint listening", zap.Int("port", d.cfg.MetricsPort))
	}

	return nil
}

func (d *Daemon) stop() error {
	// Remove PID file.
	pidPath := filepath.Join(d.cfg.DataDir, "faramesh.pid")
	_ = os.Remove(pidPath)

	if d.server != nil {
		_ = d.server.Close()
	}
	if d.proxy != nil {
		_ = d.proxy.Close()
	}
	if d.grpc != nil {
		d.grpc.GracefulStop()
	}
	if d.grpcLis != nil {
		_ = d.grpcLis.Close()
	}
	if d.mcpGateway != nil {
		_ = d.mcpGateway.Close()
	}
	if d.metricsSrv != nil {
		_ = d.metricsSrv.Close()
	}
	if d.wal != nil {
		_ = d.wal.Close()
	}
	if d.store != nil {
		_ = d.store.Close()
	}
	if d.syncer != nil {
		d.syncer.Close() // flushes remaining records
	}
	d.log.Info("daemon stopped cleanly")
	return nil
}

// horizonSyncAdapter adapts cloud.Syncer to core.DecisionSyncer without
// importing core from the cloud package (avoids circular imports).
type horizonSyncAdapter struct {
	s *cloud.Syncer
}

func (a *horizonSyncAdapter) Send(d core.Decision) {
	a.s.SendDecision(
		string(d.Effect),
		d.RuleID,
		d.ReasonCode,
		d.PolicyVersion,
		d.Latency,
		d.AgentID,
		d.ToolID,
		d.SessionID,
		d.DPRRecordID,
		d.Timestamp,
	)
}
