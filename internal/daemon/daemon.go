// Package daemon implements the faramesh serve lifecycle:
// load policy, open WAL + SQLite, start SDK socket server, handle signals.
package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.uber.org/zap"

	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/cloud"
	"github.com/faramesh/faramesh-core/internal/core"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
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
}

// Daemon is the governance daemon.
type Daemon struct {
	cfg    Config
	server *sdk.Server
	wal    dpr.Writer
	store  *dpr.Store
	syncer *cloud.Syncer
	log    *zap.Logger
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
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		d.log.Info("shutting down", zap.String("signal", sig.String()))
	case <-ctx.Done():
	}
	return d.stop()
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
	store, err := dpr.OpenStore(dbPath)
	if err != nil {
		d.log.Warn("failed to open DPR SQLite store; audit queries will be unavailable",
			zap.Error(err))
	} else {
		d.store = store
	}

	// Build pipeline.
	pipeline := core.NewPipeline(core.Config{
		Engine:   engine,
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

	return nil
}

func (d *Daemon) stop() error {
	if d.server != nil {
		_ = d.server.Close()
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
	)
}
