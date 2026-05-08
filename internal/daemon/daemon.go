// Package daemon implements the faramesh serve lifecycle:
// load policy, open WAL + SQLite, start SDK socket server, handle signals.
package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	gatewaydaemon "github.com/faramesh/faramesh-core/internal/adapter/daemon"
	"github.com/faramesh/faramesh-core/internal/adapter/ebpf"
	"github.com/faramesh/faramesh-core/internal/adapter/mcp"
	"github.com/faramesh/faramesh-core/internal/adapter/proxy"
	"github.com/faramesh/faramesh-core/internal/adapter/sdk"
	"github.com/faramesh/faramesh-core/internal/artifactverify"
	"github.com/faramesh/faramesh-core/internal/cloud"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/callbacks"
	"github.com/faramesh/faramesh-core/internal/core/credential"
	deferwork "github.com/faramesh/faramesh-core/internal/core/defer"
	deferbackends "github.com/faramesh/faramesh-core/internal/core/defer/backends"
	"github.com/faramesh/faramesh-core/internal/core/degraded"
	"github.com/faramesh/faramesh-core/internal/core/delegate"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/jobs"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/phases"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	principalidp "github.com/faramesh/faramesh-core/internal/core/principal/idp"
	"github.com/faramesh/faramesh-core/internal/core/schedule"
	"github.com/faramesh/faramesh-core/internal/core/session"
	"github.com/faramesh/faramesh-core/internal/core/standing"
	"github.com/faramesh/faramesh-core/internal/core/toolinventory"
	"github.com/faramesh/faramesh-core/internal/core/webhook"
	"github.com/faramesh/faramesh-core/internal/reprobuild"
	"github.com/faramesh/faramesh-core/internal/sbom"
)

var ebpfNew = ebpf.New

const (
	fleetRegistryKey            = "faramesh:fleet:instances"
	fleetPolicyReloadChannel    = "faramesh:fleet:policy-reload"
	fleetPolicyReloadActionName = "policy_reload"
)

// Config configures the daemon.
type Config struct {
	PolicyPath         string
	PolicyURL          string
	PolicyPollInterval time.Duration
	DataDir            string
	SocketPath         string
	SlackWebhook       string
	Log                *zap.Logger

	// Horizon sync (optional). If HorizonToken is set, DPR records are
	// streamed to the Horizon API in real time.
	HorizonToken string
	HorizonURL   string
	HorizonOrgID string

	ProxyPort                   int
	ProxyConnect                bool // HTTP CONNECT only (governed as proxy/connect)
	ProxyForward                bool // CONNECT + RFC 7230 absolute-form HTTP (proxy/connect + proxy/http)
	NetworkHardeningMode        string
	InferenceRoutesFile         string
	IntentClassifierURL         string
	IntentClassifierTimeout     time.Duration
	IntentClassifierBearerToken string
	AllowedPrivateCIDRs         []string
	AllowedPrivateHosts         []string
	GRPCPort                    int
	MCPProxyPort                int
	MCPTarget                   string
	MCPAllowedOrigins           []string
	MCPEdgeAuthMode             string
	MCPEdgeAuthBearerToken      string
	MCPProtocolVersionMode      string
	MCPProtocolVersion          string
	MCPSessionTTL               time.Duration
	MCPSessionIdleTimeout       time.Duration
	MCPSSEReplayEnabled         bool
	MCPSSEReplayMaxEvents       int
	MCPSSEReplayMaxAge          time.Duration
	OTLPEnabled                 bool
	OTLPEndpoint                string
	OTLPProtocol                string
	OTLPInsecure                bool
	OTLPServiceName             string
	OTLPServiceVersion          string
	OTLPTracesEnabled           bool
	OTLPMetricsEnabled          bool
	OTLPLogsEnabled             bool
	MetricsPort                 int
	DPRDSN                      string
	RedisURL                    string
	DeferBackend                string
	DeferRedisPrefix            string
	RuntimeMode                 core.RuntimeMode
	RequireGovernanceBootstrap  bool
	DPRHMACKey                  string
	CanonicalizationAlgorithm   string
	// DPRSigner configures which signing backend to use for DPR records.
	// Supported values: "" (default = on-disk keypair), "file", or a KMS URI like "kms://...".
	DPRSigner           string
	TLSCertFile         string
	TLSKeyFile          string
	ClientCAFile        string
	TLSAuto             bool
	PagerDutyRoutingKey string
	PolicyAdminToken    string
	// StandingAdminToken authenticates standing_grant_* SDK messages. If empty,
	// serve resolves it from FARAMESH_STANDING_ADMIN_TOKEN or falls back to PolicyAdminToken.
	StandingAdminToken    string
	EnableEBPF            bool
	EBPFObjectPath        string
	EBPFAttachTracepoints bool
	SPIFFESocketPath      string
	StrictPreflight       bool
	IDPProvider           string
	IntegrityManifestPath string
	IntegrityBaseDir      string
	BuildInfoExpectedPath string
	// AllowEnvCredentialFallback permits env-based credential brokering as an explicit
	// development escape hatch. Keep false in production strict mode.
	AllowEnvCredentialFallback bool

	// DelegateMaxDepth caps delegation chain length. Zero falls back to
	// delegate.DefaultMaxDepth.
	DelegateMaxDepth int

	// Credential broker backends.
	VaultAddr         string
	VaultToken        string
	VaultMount        string
	VaultNamespace    string
	AWSSecretsRegion  string
	GCPSecretsProject string
	AzureKeyVaultURL  string
	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string
}

// Daemon is the governance daemon.
type Daemon struct {
	cfg                  Config
	engine               *policy.AtomicEngine
	policyLoader         *policy.PolicyLoader
	lastPolicyHash       string
	policySourceType     string
	policySourceID       string
	policyPollCancel     context.CancelFunc
	reloadMu             sync.Mutex
	server               *sdk.Server
	pipeline             *core.Pipeline
	wal                  dpr.Writer
	store                dpr.StoreBackend
	dprQueue             jobs.DPRQueue
	toolInventory        *toolinventory.Store
	syncer               *cloud.Syncer
	proxy                *proxy.Server
	grpc                 *gatewaydaemon.Server
	grpcLis              net.Listener
	mcpGateway           *mcp.HTTPGateway
	metricsSrv           *http.Server
	sessBackend          session.Backend
	deferBackend         deferbackends.Backend
	fleetRedis           *redis.Client
	fleetInstanceID      string
	fleetPolicySubCancel context.CancelFunc
	dailyCostStore       session.DailyCostStore
	webhooks             *webhook.Sender
	degraded             *degraded.Manager
	elevationEngine      *principal.ElevationEngine
	revocationMgr        *principal.RevocationManager
	workloadProvider     principal.WorkloadProvider
	ebpfAdapter          ebpf.Lifecycle
	delegate             *delegate.Service
	delegateStore        *delegate.SQLiteStore
	schedule             *schedule.Service
	scheduleStore        *schedule.SQLiteStore
	log                  *zap.Logger
	fleetPolicyApply     func(context.Context, fleetPolicyReloadEvent) (bool, error)
}

type fleetPolicyReloadEvent struct {
	Action        string `json:"action"`
	InstanceID    string `json:"instance_id"`
	SourceType    string `json:"source_type"`
	SourceID      string `json:"source_id,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	PolicyHash    string `json:"policy_hash,omitempty"`
	PolicyYAML    string `json:"policy_yaml,omitempty"`
	Timestamp     string `json:"timestamp"`
}

// New creates a Daemon from a Config. Call Run() to start it.
func New(cfg Config) (*Daemon, error) {
	if cfg.Log == nil {
		log, _ := zap.NewProduction()
		cfg.Log = log
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(defaultRuntimeDir(), "data")
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = sdk.SocketPath
	}
	cfg.NetworkHardeningMode = strings.ToLower(strings.TrimSpace(cfg.NetworkHardeningMode))
	cfg.DeferBackend = strings.ToLower(strings.TrimSpace(cfg.DeferBackend))
	cfg.RuntimeMode = core.RuntimeMode(strings.ToLower(strings.TrimSpace(string(cfg.RuntimeMode))))
	if cfg.NetworkHardeningMode == "" {
		cfg.NetworkHardeningMode = string(proxy.HardeningModeOff)
	}
	if cfg.DeferBackend == "" {
		cfg.DeferBackend = "memory"
	}
	if cfg.DeferBackend != "memory" && cfg.DeferBackend != "redis" {
		return nil, fmt.Errorf("invalid defer backend %q (supported: memory|redis)", cfg.DeferBackend)
	}
	if cfg.DeferBackend == "redis" && strings.TrimSpace(cfg.RedisURL) == "" {
		return nil, fmt.Errorf("defer backend %q requires --redis-url", cfg.DeferBackend)
	}
	if cfg.RuntimeMode == "" {
		cfg.RuntimeMode = core.RuntimeModeEnforce
	}
	if strings.TrimSpace(cfg.CanonicalizationAlgorithm) == "" {
		canonEnv := strings.ToLower(strings.TrimSpace(os.Getenv("FARAMESH_USE_JCS")))
		switch canonEnv {
		case "0", "false", "no", "legacy":
			cfg.CanonicalizationAlgorithm = dpr.CanonicalizationLegacyJSON
		default:
			cfg.CanonicalizationAlgorithm = dpr.CanonicalizationJCS
		}
	}
	if cfg.RuntimeMode != core.RuntimeModeEnforce &&
		cfg.RuntimeMode != core.RuntimeModeShadow &&
		cfg.RuntimeMode != core.RuntimeModeAudit {
		return nil, fmt.Errorf("invalid runtime mode %q (supported: enforce|shadow|audit)", cfg.RuntimeMode)
	}
	if cfg.ProxyForward {
		cfg.ProxyConnect = true
	}
	if cfg.NetworkHardeningMode != string(proxy.HardeningModeOff) &&
		cfg.NetworkHardeningMode != string(proxy.HardeningModeAudit) &&
		cfg.NetworkHardeningMode != string(proxy.HardeningModeEnforce) {
		return nil, fmt.Errorf("invalid network hardening mode %q (supported: off|audit|enforce)", cfg.NetworkHardeningMode)
	}
	if cfg.NetworkHardeningMode != string(proxy.HardeningModeOff) && cfg.ProxyPort <= 0 {
		return nil, fmt.Errorf("network hardening mode %q requires --proxy-port", cfg.NetworkHardeningMode)
	}
	if strings.TrimSpace(cfg.InferenceRoutesFile) != "" && !cfg.ProxyForward {
		return nil, fmt.Errorf("inference routes require --proxy-forward")
	}
	cfg.MCPEdgeAuthMode = strings.ToLower(strings.TrimSpace(cfg.MCPEdgeAuthMode))
	if cfg.MCPEdgeAuthMode == "" {
		cfg.MCPEdgeAuthMode = "off"
	}
	if cfg.MCPEdgeAuthMode != "off" &&
		cfg.MCPEdgeAuthMode != "bearer" &&
		cfg.MCPEdgeAuthMode != "mtls" &&
		cfg.MCPEdgeAuthMode != "bearer_or_mtls" {
		return nil, fmt.Errorf("invalid MCP edge auth mode %q (supported: off|bearer|mtls|bearer_or_mtls)", cfg.MCPEdgeAuthMode)
	}
	if (cfg.MCPEdgeAuthMode == "bearer" || cfg.MCPEdgeAuthMode == "bearer_or_mtls") && strings.TrimSpace(cfg.MCPEdgeAuthBearerToken) == "" {
		return nil, fmt.Errorf("MCP edge auth mode %q requires a bearer token", cfg.MCPEdgeAuthMode)
	}
	cfg.MCPProtocolVersionMode = strings.ToLower(strings.TrimSpace(cfg.MCPProtocolVersionMode))
	if cfg.MCPProtocolVersionMode == "" {
		cfg.MCPProtocolVersionMode = "off"
	}
	if cfg.MCPProtocolVersionMode != "off" && cfg.MCPProtocolVersionMode != "strict" {
		return nil, fmt.Errorf("invalid MCP protocol version mode %q (supported: off|strict)", cfg.MCPProtocolVersionMode)
	}
	if cfg.MCPSessionTTL < 0 {
		return nil, fmt.Errorf("MCP session TTL must be >= 0")
	}
	if cfg.MCPSessionIdleTimeout < 0 {
		return nil, fmt.Errorf("MCP session idle timeout must be >= 0")
	}
	if cfg.MCPSSEReplayMaxEvents < 0 {
		return nil, fmt.Errorf("MCP SSE replay max events must be >= 0")
	}
	if cfg.MCPSSEReplayMaxAge < 0 {
		return nil, fmt.Errorf("MCP SSE replay max age must be >= 0")
	}
	return &Daemon{cfg: cfg, log: cfg.Log}, nil
}

func defaultRuntimeDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(os.TempDir(), "faramesh", "runtime")
	}
	return filepath.Join(home, ".faramesh", "runtime")
}

// Run starts the daemon and blocks until a signal is received.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.start(); err != nil {
		return err
	}
	d.startPolicyWatcher()
	d.log.Info("faramesh daemon running",
		zap.String("socket", d.cfg.SocketPath),
		zap.String("policy", d.cfg.PolicyPath),
		zap.String("policy_url", d.cfg.PolicyURL),
		zap.String("data_dir", d.cfg.DataDir),
	)

	// Start Horizon syncer in background if configured.
	if d.syncer != nil {
		go d.syncer.Run()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, daemonNotifySignals()...)
	for {
		select {
		case sig := <-sigCh:
			if d.handleSignal(sig) {
				return d.stop()
			}
		case <-ctx.Done():
			return d.stop()
		}
	}
}

func (d *Daemon) handleSignal(sig os.Signal) bool {
	switch {
	case isReloadSignal(sig):
		d.log.Info("SIGHUP received — reloading policy", zap.String("path", d.cfg.PolicyPath))
		if err := d.reloadPolicy(); err != nil {
			d.log.Error("policy reload failed — continuing with current policy", zap.Error(err))
		}
		if w, ok := d.wal.(*dpr.WAL); ok {
			if err := w.Compact(); err != nil {
				d.log.Error("SIGHUP WAL compaction failed", zap.Error(err))
			} else {
				d.log.Info("SIGHUP WAL compaction completed")
			}
		}
		return false
	case isChaosDegradedSignal(sig):
		if d.degraded == nil {
			d.log.Warn("SIGUSR1 received but degraded manager is not initialized")
			return false
		}
		enabled := d.degraded.ToggleDegraded()
		d.log.Warn("chaos toggle degraded mode",
			zap.Bool("forced_degraded", enabled),
			zap.String("degraded_mode", d.degraded.Current().String()),
		)
		return false
	case isChaosFaultSignal(sig):
		if d.degraded == nil {
			d.log.Warn("SIGUSR2 received but degraded manager is not initialized")
			return false
		}
		enabled := d.degraded.ToggleFault()
		d.log.Warn("chaos toggle fault mode",
			zap.Bool("fault_injected", enabled),
			zap.String("degraded_mode", d.degraded.Current().String()),
		)
		return false
	default:
		d.log.Info("shutting down", zap.String("signal", sig.String()))
		return true
	}
}

// reloadPolicy re-reads the policy file and hot-swaps the AtomicEngine.
// If compilation fails the running engine is untouched.
func (d *Daemon) reloadPolicy() error {
	_, _, err := d.reloadPolicyIfChangedInternal(true)
	return err
}

func (d *Daemon) reloadPolicyIfChanged() (bool, error) {
	changed, _, err := d.reloadPolicyIfChangedInternal(true)
	return changed, err
}

func (d *Daemon) reloadPolicyIfChangedInternal(publish bool) (bool, *fleetPolicyReloadEvent, error) {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()

	if d.cfg.PolicyURL != "" {
		if d.policyLoader == nil {
			d.policyLoader = policy.NewPolicyLoader()
		}
		src, err := d.policyLoader.FromURL(context.Background(), d.cfg.PolicyURL)
		if err != nil {
			return false, nil, fmt.Errorf("load policy from URL: %w", err)
		}
		if src.Hash == d.lastPolicyHash {
			return false, nil, nil
		}
		if errs := policy.Validate(src.Doc); len(errs) > 0 {
			for _, e := range errs {
				d.log.Warn("policy validation warning", zap.String("error", e))
			}
		}
		if d.pipeline != nil {
			if err := d.pipeline.ApplyPolicyBundle(src.Doc, src.Engine); err != nil {
				return false, nil, fmt.Errorf("apply policy bundle: %w", err)
			}
		} else {
			if err := d.engine.HotReload(src.Doc, src.Version); err != nil {
				return false, nil, fmt.Errorf("compile policy: %w", err)
			}
		}
		d.policyLoader.Activate(src)
		d.lastPolicyHash = src.Hash
		observe.EmitGovernanceLog(d.log, zap.InfoLevel, "policy reloaded", observe.EventPolicyReload,
			zap.String("version", src.Version),
			zap.String("policy_hash", src.Hash),
			zap.String("agent_id", src.Doc.AgentID),
			zap.Int("rules", len(src.Doc.Rules)),
			zap.String("source_type", string(policy.SourceURL)),
			zap.String("source_id", d.cfg.PolicyURL),
		)
		event := &fleetPolicyReloadEvent{
			Action:        fleetPolicyReloadActionName,
			InstanceID:    d.fleetInstanceID,
			SourceType:    string(policy.SourceURL),
			SourceID:      d.cfg.PolicyURL,
			PolicyVersion: src.Version,
			PolicyHash:    src.Hash,
			Timestamp:     time.Now().UTC().Format(time.RFC3339),
		}
		if publish {
			d.publishFleetPolicyReloadEvent(context.Background(), *event)
		}
		return true, event, nil
	}

	doc, version, err := policy.LoadFile(d.cfg.PolicyPath)
	if err != nil {
		return false, nil, fmt.Errorf("load policy: %w", err)
	}
	if errs := policy.Validate(doc); len(errs) > 0 {
		for _, e := range errs {
			d.log.Warn("policy validation warning", zap.String("error", e))
		}
	}
	newEngine, err := policy.NewEngine(doc, version)
	if err != nil {
		return false, nil, fmt.Errorf("compile policy: %w", err)
	}
	if d.pipeline != nil {
		if err := d.pipeline.ApplyPolicyBundle(doc, newEngine); err != nil {
			return false, nil, fmt.Errorf("apply policy bundle: %w", err)
		}
	} else {
		d.engine.Swap(newEngine)
	}
	d.lastPolicyHash = version
	observe.EmitGovernanceLog(d.log, zap.InfoLevel, "policy reloaded", observe.EventPolicyReload,
		zap.String("version", version),
		zap.String("policy_hash", version),
		zap.String("agent_id", doc.AgentID),
		zap.Int("rules", len(doc.Rules)),
		zap.String("source_type", string(policy.SourceFile)),
		zap.String("source_id", d.cfg.PolicyPath),
	)
	event := &fleetPolicyReloadEvent{
		Action:        fleetPolicyReloadActionName,
		InstanceID:    d.fleetInstanceID,
		SourceType:    string(policy.SourceFile),
		SourceID:      d.cfg.PolicyPath,
		PolicyVersion: version,
		PolicyHash:    version,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}
	if raw, readErr := os.ReadFile(d.cfg.PolicyPath); readErr == nil {
		event.PolicyYAML = string(raw)
	}
	if publish {
		d.publishFleetPolicyReloadEvent(context.Background(), *event)
	}
	return true, event, nil
}

// Server returns the SDK server (used by audit tail).
func (d *Daemon) Server() *sdk.Server { return d.server }

func (d *Daemon) start() error {
	if err := os.MkdirAll(d.cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	tlsCfg, err := d.buildAdapterTLSConfig()
	if err != nil {
		return err
	}

	// Load and compile policy.
	doc, version, err := d.loadInitialPolicy()
	if err != nil {
		return err
	}
	if err := observe.InitOTLP(context.Background(), observe.OTLPConfig{
		Enabled:        d.cfg.OTLPEnabled,
		Endpoint:       d.cfg.OTLPEndpoint,
		Protocol:       d.cfg.OTLPProtocol,
		Insecure:       d.cfg.OTLPInsecure,
		ServiceName:    d.cfg.OTLPServiceName,
		ServiceVersion: coalesceString(d.cfg.OTLPServiceVersion, version),
		TracesEnabled:  d.cfg.OTLPTracesEnabled,
		MetricsEnabled: d.cfg.OTLPMetricsEnabled,
		LogsEnabled:    d.cfg.OTLPLogsEnabled,
	}); err != nil {
		return fmt.Errorf("init OTLP telemetry: %w", err)
	}
	d.log.Info("policy loaded",
		zap.String("version", version),
		zap.String("agent_id", doc.AgentID),
		zap.Int("rules", len(doc.Rules)),
		zap.String("source_type", d.policySourceType),
		zap.String("source_id", d.policySourceID),
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
	} else {
		warnOnDPRReconciliationDrift(d.log, wal, sqliteStore)
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

	toolInventoryPath := filepath.Join(d.cfg.DataDir, "faramesh-tool-inventory.db")
	toolInventoryStore, invErr := toolinventory.OpenStore(toolInventoryPath)
	if invErr != nil {
		d.log.Warn("failed to open tool inventory store; observed-tool catalog will be unavailable", zap.Error(invErr))
	} else {
		d.toolInventory = toolInventoryStore
		if err := d.seedToolInventory(store); err != nil {
			d.log.Warn("failed to seed tool inventory from DPR history", zap.Error(err))
		}
	}

	// Optional async DPR queue:
	// - river:// DSN attempts River-backed queue
	// - fallback is in-proc queue when River backend is unavailable
	var dprQueue jobs.DPRQueue
	if jobs.SupportsRiverDSN(d.cfg.DPRDSN) && store != nil {
		riverQueue, qErr := jobs.NewRiverDPRQueue(d.cfg.DPRDSN, store)
		if qErr != nil {
			d.log.Warn("river queue unavailable; falling back to in-process DPR queue", zap.Error(qErr))
			dprQueue = jobs.NewInprocDPRQueue(store, jobs.InprocDPRQueueConfig{})
		} else {
			dprQueue = riverQueue
			d.log.Info("DPR River queue enabled")
		}
	}
	d.dprQueue = dprQueue

	// Write PID file so `faramesh policy reload` can find the daemon.
	pidPath := filepath.Join(d.cfg.DataDir, "faramesh.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		d.log.Warn("failed to write PID file", zap.String("path", pidPath), zap.Error(err))
	}

	// Build pipeline.
	hmacKey, err := d.loadOrCreateDPRHMACKey()
	if err != nil {
		return fmt.Errorf("load DPR HMAC key: %w", err)
	}

	// Load or create DPR Ed25519 signing keypair (for tamper-evident receipts).
	signPriv, signPub, err := d.loadOrCreateDPRSigningKey()
	if err != nil {
		return fmt.Errorf("load DPR signing key: %w", err)
	}

	delegateDBPath := filepath.Join(d.cfg.DataDir, "delegations.db")
	delegateStore, err := delegate.OpenSQLiteStore(delegateDBPath)
	if err != nil {
		return fmt.Errorf("open delegation store: %w", err)
	}
	d.delegateStore = delegateStore
	d.delegate = delegate.NewService(
		delegateStore,
		delegate.DeriveKey(hmacKey),
		d.cfg.DelegateMaxDepth,
		nil,
	)

	scheduleDBPath := filepath.Join(d.cfg.DataDir, "schedules.db")
	scheduleStore, err := schedule.OpenSQLiteStore(scheduleDBPath)
	if err != nil {
		return fmt.Errorf("open schedule store: %w", err)
	}
	d.scheduleStore = scheduleStore
	d.schedule = schedule.NewService(scheduleStore, nil, nil)

	sessionManager := session.NewManager()
	dailyCostPath := filepath.Join(d.cfg.DataDir, "session_daily_costs.db")
	if dailyStore, err := session.NewSQLiteDailyCostStore(dailyCostPath); err != nil {
		d.log.Warn("failed to open daily cost sqlite store; daily cost will be in-memory only", zap.Error(err))
	} else {
		d.dailyCostStore = dailyStore
		sessionManager = session.NewManagerWithDailyStore(d.dailyCostStore)
	}
	if d.cfg.RedisURL != "" {
		redisOpts, err := redis.ParseURL(d.cfg.RedisURL)
		if err != nil {
			return fmt.Errorf("parse redis url: %w", err)
		}
		redisClient := redis.NewClient(redisOpts)
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			return fmt.Errorf("connect redis session backend: %w", err)
		}
		d.sessBackend = session.NewRedisBackend(session.RedisConfig{Client: redisClient})
		d.fleetRedis = redisClient
		sessionManager = session.NewManagerWithStores(d.sessBackend, d.dailyCostStore)
		d.log.Info("redis session backend enabled")
	}
	if d.fleetRedis != nil {
		_ = d.registerFleetInstance(doc.AgentID)
		d.startFleetPolicyReloadSubscriber()
	}

	if doc.Webhooks != nil && doc.Webhooks.URL != "" {
		d.webhooks = webhook.NewSender(*doc.Webhooks)
	}

	standingPath := filepath.Join(d.cfg.DataDir, "faramesh-standing-grants.db")
	standingReg, err := standing.OpenRegistryStore(standingPath)
	if err != nil {
		return fmt.Errorf("open standing grants store: %w", err)
	}

	d.degraded = degraded.NewManager()
	redisAvailable := d.cfg.RedisURL == "" || d.sessBackend != nil
	postgresAvailable := d.cfg.DPRDSN == "" || d.store != nil
	d.degraded.SetBackendStatus(redisAvailable, postgresAvailable)
	observe.Default.SetCrossSessionTracker(observe.NewCrossSessionFlowTracker())
	observe.Default.SetPIEAnalyzer(observe.NewPIEAnalyzer())
	provenanceTracker := observe.NewArgProvenanceTracker()

	wf := deferwork.NewWorkflow(d.cfg.SlackWebhook)
	wf.SetLogger(d.log)
	wf.SetPagerDutyRoutingKey(d.cfg.PagerDutyRoutingKey)
	wf.SetApprovalHMACKey(hmacKey)
	if d.cfg.DeferBackend == "redis" {
		if d.fleetRedis == nil {
			return fmt.Errorf("redis defer backend requires initialized redis client")
		}
		d.deferBackend = deferbackends.NewRedisBackend(deferbackends.RedisConfig{
			Client: d.fleetRedis,
			Prefix: d.cfg.DeferRedisPrefix,
		})
		wf.SetBackend(d.deferBackend)
		d.log.Info("redis defer backend enabled",
			zap.String("defer_backend", d.cfg.DeferBackend),
			zap.String("defer_redis_prefix", strings.TrimSpace(d.cfg.DeferRedisPrefix)),
		)
	}
	if doc.DeferPriority != nil {
		wf.SetTriage(buildTriageFromPolicy(doc.DeferPriority))
	}
	subPolicies := multiagent.NewSubPolicyManager()
	routingGovernor := multiagent.NewRoutingGovernor()
	sessionGovernor := session.NewGovernor()
	loopGovernor := multiagent.NewLoopGovernor()
	if strings.EqualFold(strings.TrimSpace(os.Getenv("FARAMESH_LOOP_GOV_ENABLED")), "true") {
		loopGovernor.ConfigureRuntime(multiagent.LoopRuntimeConfig{
			Enabled:     true,
			Window:      parseDurationEnv("FARAMESH_LOOP_GOV_WINDOW", 30*time.Second),
			MaxRepeats:  parseIntEnv("FARAMESH_LOOP_GOV_MAX_REPEATS", 4),
			MaxCalls:    parseIntEnv("FARAMESH_LOOP_GOV_MAX_CALLS", 12),
			MaxArgBytes: parseIntEnv("FARAMESH_LOOP_GOV_MAX_ARG_BYTES", 512),
		})
	}
	aggGovernor := multiagent.NewAggregationGovernor(multiagent.AggregatePolicy{})
	if strings.EqualFold(strings.TrimSpace(os.Getenv("FARAMESH_AGG_GOV_ENABLED")), "true") {
		aggGovernor.ConfigureRuntime(multiagent.AggregationRuntimeConfig{
			Enabled:         true,
			Window:          parseDurationEnv("FARAMESH_AGG_GOV_WINDOW", 5*time.Minute),
			MaxRiskyActions: parseIntEnv("FARAMESH_AGG_GOV_MAX_RISKY_ACTIONS", 8),
		})
	}
	callbackManager := callbacks.NewFromPolicyCallbacks(extractPolicyCallbacks(doc))
	elevationEngine := principal.NewElevationEngine(nil)
	revocationMgr := principal.NewRevocationManager(elevationEngine)
	var workloadProvider principal.WorkloadProvider
	if spiffeSocket := strings.TrimSpace(d.cfg.SPIFFESocketPath); spiffeSocket != "" {
		provider := principal.NewSPIFFEProvider(spiffeSocket)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		if provider.Available(ctx) {
			workloadProvider = provider
			d.log.Info("workload identity provider configured",
				zap.String("provider", provider.Name()),
				zap.String("spiffe_socket", spiffeSocket),
			)
		}
		cancel()
	} else if provider := principal.DetectWorkloadProvider(); provider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		if provider.Available(ctx) {
			workloadProvider = provider
			d.log.Info("workload identity provider detected", zap.String("provider", provider.Name()))
		}
		cancel()
	}

	credentialRouter := buildCredentialRouter(d.cfg)
	if err := d.enforceStartupPreflight(doc, workloadProvider); err != nil {
		return err
	}

	intentClassifier, classifierURL, classifierTimeout := buildIntentClassifier(d.cfg)
	if intentClassifier != nil {
		d.log.Info("async intent classifier writer enabled",
			zap.String("classifier_url", classifierURL),
			zap.Duration("classifier_timeout", classifierTimeout),
		)
	}

	var bootstrap *core.BootstrapEnforcer
	if d.cfg.RequireGovernanceBootstrap {
		bootstrap = core.NewBootstrapEnforcer(true)
	}

	pipeline := core.NewPipeline(core.Config{
		Engine:                    d.engine,
		WAL:                       wal,
		Store:                     store,
		DPRQueue:                  dprQueue,
		Sessions:                  sessionManager,
		SessionGovernor:           sessionGovernor,
		Standing:                  standingReg,
		Defers:                    wf,
		Webhooks:                  d.webhooks,
		Degraded:                  d.degraded,
		SubPolicies:               subPolicies,
		RoutingGovernor:           routingGovernor,
		LoopGovernor:              loopGovernor,
		AggregationGov:            aggGovernor,
		Callbacks:                 callbackManager,
		Revocations:               revocationMgr,
		Elevations:                elevationEngine,
		WorkloadIdentity:          workloadProvider,
		CredentialRouter:          credentialRouter,
		IntentClassifier:          intentClassifier,
		Provenance:                provenanceTracker,
		PhaseManager:              buildPhaseManagerFromPolicy(doc),
		RuntimeMode:               d.cfg.RuntimeMode,
		Bootstrap:                 bootstrap,
		ToolInventory:             d.toolInventory,
		PolicySourceType:          d.policySourceType,
		PolicySourceID:            d.policySourceID,
		StrictModelVerification:   d.cfg.StrictPreflight,
		HMACKey:                   hmacKey,
		SigningPrivKey:            signPriv,
		SigningPubKey:             signPub,
		CanonicalizationAlgorithm: d.cfg.CanonicalizationAlgorithm,
		Log:                       d.log,
	})
	d.pipeline = pipeline
	// Configure optional DPR Signer backend per R4 design. If DPRSigner is
	// empty or "file", prefer the on-disk keypair already present under
	// DataDir. Future work: support KMS URIs (kms://...).
	ds := strings.TrimSpace(d.cfg.DPRSigner)
	if ds == "" || ds == "file" {
		privPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.key")
		pubPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.pub")
		if privBytes, err := os.ReadFile(privPath); err == nil {
			if pubBytes, err := os.ReadFile(pubPath); err == nil {
				fs := dpr.NewFileSigner(privBytes, pubBytes)
				pipeline.SetSigner(fs)
				d.log.Info("configured file-based DPR signer from data dir", zap.String("data_dir", d.cfg.DataDir))
			} else {
				d.log.Warn("DPR signer public key not found; continuing without signer", zap.String("pub_path", pubPath), zap.Error(err))
			}
		} else {
			d.log.Warn("DPR signer private key not found; continuing without signer", zap.String("priv_path", privPath), zap.Error(err))
		}
	} else if strings.HasPrefix(ds, "localkms://") {
		// localkms://<keyid>
		keyID := strings.TrimPrefix(ds, "localkms://")
		if keyID != "" {
			if lks, err := dpr.NewLocalKMSSigner(d.cfg.DataDir, keyID); err == nil {
				pipeline.SetSigner(lks)
				d.log.Info("configured local-kms DPR signer", zap.String("key_id", keyID))
			} else {
				d.log.Warn("configure local-kms signer failed; continuing without signer", zap.Error(err))
			}
		} else {
			d.log.Warn("localkms URI missing key id; continuing without signer", zap.String("dpr_signer", d.cfg.DPRSigner))
		}
	} else {
		d.log.Info("DPR signer configured (non-file); KMS signer support is TODO", zap.String("dpr_signer", d.cfg.DPRSigner))
	}
	d.elevationEngine = elevationEngine
	d.revocationMgr = revocationMgr
	d.workloadProvider = workloadProvider
	principalResolver := buildPrincipalTokenResolver(d.cfg, d.log)

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
	server.SetPrincipalResolver(principalResolver)
	server.SetShutdownFunc(func() {
		d.log.Info("shutdown requested via SDK socket")
		proc, err := os.FindProcess(os.Getpid())
		if err != nil {
			d.log.Error("resolve daemon process for shutdown signal", zap.Error(err))
			return
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			d.log.Error("signal daemon shutdown", zap.Error(err))
		}
	})
	server.SetStandingAdminToken(strings.TrimSpace(d.cfg.StandingAdminToken))
	if strings.TrimSpace(d.cfg.StandingAdminToken) != "" {
		d.log.Info("standing grant admin authentication enabled (SDK standing_grant_* requires admin_token)")
	} else {
		d.log.Warn("standing grant SDK APIs are disabled until --standing-admin-token, FARAMESH_STANDING_ADMIN_TOKEN, or --policy-admin-token is set")
	}

	if d.delegate != nil {
		server.SetDelegateService(d.delegate)
	}
	if d.schedule != nil {
		server.SetScheduleService(d.schedule)
	}
	if err := server.Listen(d.cfg.SocketPath); err != nil {
		return fmt.Errorf("start SDK server: %w", err)
	}
	d.server = server

	if d.cfg.ProxyPort > 0 {
		var pOpts []proxy.ServerOption
		if d.cfg.ProxyConnect {
			pOpts = append(pOpts, proxy.WithConnectProxy(true))
		}
		if d.cfg.ProxyForward {
			pOpts = append(pOpts, proxy.WithHTTPForwardProxy(true))
		}
		pOpts = append(pOpts, proxy.WithNetworkHardeningMode(d.cfg.NetworkHardeningMode))
		if len(d.cfg.AllowedPrivateCIDRs) > 0 {
			pOpts = append(pOpts, proxy.WithAllowedPrivateCIDRs(d.cfg.AllowedPrivateCIDRs))
		}
		if len(d.cfg.AllowedPrivateHosts) > 0 {
			pOpts = append(pOpts, proxy.WithAllowedPrivateHosts(d.cfg.AllowedPrivateHosts))
		}
		if routeFile := strings.TrimSpace(d.cfg.InferenceRoutesFile); routeFile != "" {
			routes, err := loadInferenceRoutesFromFile(routeFile)
			if err != nil {
				return fmt.Errorf("load inference routes from %q: %w", routeFile, err)
			}
			pOpts = append(pOpts, proxy.WithInferenceRoutes(routes))
		}
		d.proxy = proxy.NewServer(pipeline, d.log, pOpts...)
		if tlsCfg != nil {
			if err := d.proxy.ListenTLS(fmt.Sprintf(":%d", d.cfg.ProxyPort), d.cfg.TLSCertFile, d.cfg.TLSKeyFile, tlsCfg); err != nil {
				return fmt.Errorf("start proxy adapter (tls): %w", err)
			}
		} else {
			if err := d.proxy.Listen(fmt.Sprintf(":%d", d.cfg.ProxyPort)); err != nil {
				return fmt.Errorf("start proxy adapter: %w", err)
			}
		}
		if d.cfg.ProxyForward {
			d.log.Info("proxy forward mode: CONNECT (proxy/connect) and HTTP absolute-form (proxy/http); permit both in policy",
				zap.Int("port", d.cfg.ProxyPort))
		} else if d.cfg.ProxyConnect {
			d.log.Info("proxy HTTP CONNECT enabled (governed as tool proxy/connect; permit in policy)",
				zap.Int("port", d.cfg.ProxyPort))
		}
	}

	if d.cfg.GRPCPort > 0 {
		d.grpc = gatewaydaemon.NewServer(gatewaydaemon.Config{
			Pipeline:          pipeline,
			TLSConfig:         tlsCfg,
			PolicyAdminToken:  d.cfg.PolicyAdminToken,
			PrincipalResolver: principalResolver,
		})
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
		d.mcpGateway = mcp.NewHTTPGatewayWithConfig(pipeline, doc.AgentID, d.cfg.MCPTarget, d.log, mcp.HTTPGatewayConfig{
			AllowedOrigins:      d.cfg.MCPAllowedOrigins,
			EdgeAuthMode:        d.cfg.MCPEdgeAuthMode,
			EdgeAuthBearerToken: d.cfg.MCPEdgeAuthBearerToken,
			ProtocolVersionMode: d.cfg.MCPProtocolVersionMode,
			ProtocolVersion:     d.cfg.MCPProtocolVersion,
			SessionTTL:          d.cfg.MCPSessionTTL,
			SessionIdleTimeout:  d.cfg.MCPSessionIdleTimeout,
			SSEReplayEnabled:    d.cfg.MCPSSEReplayEnabled,
			SSEReplayMaxEvents:  d.cfg.MCPSSEReplayMaxEvents,
			SSEReplayMaxAge:     d.cfg.MCPSSEReplayMaxAge,
		})
		if tlsCfg != nil {
			if err := d.mcpGateway.ListenTLS(fmt.Sprintf(":%d", d.cfg.MCPProxyPort), d.cfg.TLSCertFile, d.cfg.TLSKeyFile, tlsCfg); err != nil {
				return fmt.Errorf("start MCP HTTP gateway (tls): %w", err)
			}
		} else {
			if err := d.mcpGateway.Listen(fmt.Sprintf(":%d", d.cfg.MCPProxyPort)); err != nil {
				return fmt.Errorf("start MCP HTTP gateway: %w", err)
			}
		}
	}

	if d.cfg.MetricsPort > 0 {
		mux := http.NewServeMux()
		mux.Handle("/metrics", observe.Default.Handler())
		mux.HandleFunc("/healthz", d.handleHealthz)
		d.metricsSrv = &http.Server{Addr: fmt.Sprintf(":%d", d.cfg.MetricsPort), Handler: mux}
		go func() {
			if err := d.metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				d.log.Error("metrics endpoint stopped", zap.Error(err))
			}
		}()
		d.log.Info("metrics endpoint listening", zap.Int("port", d.cfg.MetricsPort))
	}

	d.bootstrapEBPF()

	return nil
}

func (d *Daemon) loadOrCreateDPRHMACKey() ([]byte, error) {
	if explicit := []byte(d.cfg.DPRHMACKey); len(explicit) > 0 {
		return explicit, nil
	}

	keyPath := filepath.Join(d.cfg.DataDir, "faramesh.hmac.key")
	if existing, err := os.ReadFile(keyPath); err == nil {
		if len(existing) == 0 {
			return nil, fmt.Errorf("persisted DPR HMAC key file is empty: %s", keyPath)
		}
		d.log.Info("loaded persisted DPR HMAC key", zap.String("path", keyPath))
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, buf, 0o600); err != nil {
		return nil, err
	}
	d.log.Info("generated and persisted DPR HMAC key",
		zap.String("path", keyPath),
		zap.String("key_prefix", hex.EncodeToString(buf[:4])))
	return buf, nil
}

func (d *Daemon) loadOrCreateDPRSigningKey() ([]byte, []byte, error) {
	// Persisted as base64-encoded private key in data dir: faramesh.ed25519.key
	keyPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.key")
	pubPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.pub")
	if existing, err := os.ReadFile(keyPath); err == nil {
		// decode base64
		priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(existing)))
		if err != nil {
			return nil, nil, fmt.Errorf("decode persisted ed25519 key: %w", err)
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid persisted ed25519 private key size: %d", len(priv))
		}
		pub := priv[32:]
		d.log.Info("loaded persisted DPR Ed25519 key", zap.String("path", keyPath))
		return priv, pub, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	// Generate new keypair and persist
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// Write private key as base64
	enc := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(keyPath, []byte(enc), 0o600); err != nil {
		return nil, nil, err
	}
	// Write public key for convenience
	encPub := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(pubPath, []byte(encPub), 0o644); err != nil {
		return nil, nil, err
	}

	// Compute key id and write metadata file for offline verification and rotation tracking
	sum := sha256.Sum256(pub)
	keyID := hex.EncodeToString(sum[:])
	meta := map[string]any{
		"key_id":         keyID,
		"algorithm":      "ed25519",
		"public_key_b64": encPub,
		"created_at":     time.Now().UTC().Format(time.RFC3339Nano),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := filepath.Join(d.cfg.DataDir, "faramesh.ed25519.meta.json")
	if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		return nil, nil, err
	}

	d.log.Info("generated and persisted DPR Ed25519 key", zap.String("path", keyPath), zap.String("meta", metaPath))
	return priv, pub, nil
}

func (d *Daemon) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	type backendStatus struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	type healthResponse struct {
		OK            bool            `json:"ok"`
		PolicyLoaded  bool            `json:"policy_loaded"`
		WALOpen       bool            `json:"wal_open"`
		PipelineReady bool            `json:"pipeline_ready"`
		Backends      []backendStatus `json:"backends"`
	}

	backends := []backendStatus{
		{Name: "sqlite_dpr", Status: backendHealth(d.store != nil)},
		{Name: "session_backend", Status: backendHealth(d.sessBackend != nil)},
		{Name: "fleet_redis", Status: backendHealth(d.fleetRedis != nil)},
	}
	resp := healthResponse{
		PolicyLoaded:  d.engine != nil && d.engine.Get() != nil,
		WALOpen:       d.wal != nil,
		PipelineReady: d.pipeline != nil,
		Backends:      backends,
	}
	resp.OK = resp.PolicyLoaded && resp.WALOpen && resp.PipelineReady

	status := http.StatusOK
	if !resp.OK {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func backendHealth(ok bool) string {
	if ok {
		return "ok"
	}
	return "unavailable"
}

type dprAgentCheckpoint struct {
	count    int
	lastHash string
}

func warnOnDPRReconciliationDrift(log *zap.Logger, wal *dpr.WAL, store *dpr.Store) {
	if log == nil || wal == nil || store == nil {
		return
	}

	walState, totalRecords, err := collectWALCheckpoints(wal)
	if err != nil {
		log.Warn("unable to reconcile WAL against SQLite on startup", zap.Error(err))
		return
	}
	if len(walState) == 0 {
		return
	}

	var drifted []string
	for agentID, state := range walState {
		lastHash, err := store.LastHash(agentID)
		if err != nil {
			drifted = append(drifted, fmt.Sprintf("%s: sqlite lookup failed (%v)", agentID, err))
			continue
		}
		if lastHash == "" {
			drifted = append(drifted, fmt.Sprintf("%s: sqlite missing %d WAL record(s)", agentID, state.count))
			continue
		}
		if lastHash != state.lastHash {
			drifted = append(drifted, fmt.Sprintf("%s: sqlite last hash does not match WAL tail", agentID))
		}
	}
	if len(drifted) == 0 {
		return
	}

	sort.Strings(drifted)
	exampleCount := len(drifted)
	if exampleCount > 5 {
		drifted = append(drifted[:5], fmt.Sprintf("... %d more", exampleCount-5))
	}
	log.Warn("DPR SQLite store is not fully reconciled with WAL; query results may lag until backlog drains",
		zap.Int("wal_records", totalRecords),
		zap.Int("drifted_agents", exampleCount),
		zap.Strings("examples", drifted))
}

func collectWALCheckpoints(wal *dpr.WAL) (map[string]dprAgentCheckpoint, int, error) {
	checkpoints := make(map[string]dprAgentCheckpoint)
	total := 0
	err := wal.ReplayValidated(func(rec *dpr.Record) error {
		if rec == nil {
			return nil
		}
		total++
		state := checkpoints[rec.AgentID]
		state.count++
		state.lastHash = rec.RecordHash
		checkpoints[rec.AgentID] = state
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return checkpoints, total, nil
}

func buildIntentClassifier(cfg Config) (core.IntentClassifier, string, time.Duration) {
	classifierURL := strings.TrimSpace(cfg.IntentClassifierURL)
	if classifierURL == "" {
		classifierURL = strings.TrimSpace(os.Getenv("FARAMESH_INTENT_CLASSIFIER_URL"))
	}
	if classifierURL == "" {
		return nil, "", 0
	}

	timeout := cfg.IntentClassifierTimeout
	if timeout <= 0 {
		if raw := strings.TrimSpace(os.Getenv("FARAMESH_INTENT_CLASSIFIER_TIMEOUT")); raw != "" {
			if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
				timeout = parsed
			}
		}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	bearerToken := strings.TrimSpace(cfg.IntentClassifierBearerToken)
	if bearerToken == "" {
		bearerToken = strings.TrimSpace(os.Getenv("FARAMESH_INTENT_CLASSIFIER_BEARER_TOKEN"))
	}

	classifier := core.NewHTTPIntentClassifier(core.HTTPIntentClassifierConfig{
		URL:         classifierURL,
		Timeout:     timeout,
		BearerToken: bearerToken,
		Headers: map[string]string{
			"X-Faramesh-Component": "daemon_intent_classifier",
		},
	})
	if classifier == nil {
		return nil, "", 0
	}
	return classifier, classifierURL, timeout
}

func buildCredentialRouter(cfg Config) *credential.Router {
	backends := []credential.Broker{
		&credential.EnvBroker{},
	}
	externalDefaultBackend := ""

	vaultAddr := cfg.VaultAddr
	if vaultAddr == "" {
		vaultAddr = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_ADDR"))
	}
	vaultToken := cfg.VaultToken
	if vaultToken == "" {
		vaultToken = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_TOKEN"))
	}
	if vaultAddr != "" {
		backends = append(backends, credential.NewVaultBroker(credential.VaultConfig{
			Addr:      vaultAddr,
			Token:     vaultToken,
			MountPath: cfg.VaultMount,
			Namespace: cfg.VaultNamespace,
		}))
		if externalDefaultBackend == "" {
			externalDefaultBackend = "vault"
		}
	}

	awsRegion := cfg.AWSSecretsRegion
	if awsRegion == "" {
		awsRegion = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_AWS_REGION"))
	}
	if awsRegion != "" {
		backends = append(backends, credential.NewAWSSecretsBroker(credential.AWSSecretsConfig{
			Region: awsRegion,
		}))
		if externalDefaultBackend == "" {
			externalDefaultBackend = "aws_secrets_manager"
		}
	}

	gcpProject := cfg.GCPSecretsProject
	if gcpProject == "" {
		gcpProject = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_GCP_PROJECT"))
	}
	if gcpProject != "" {
		backends = append(backends, credential.NewGCPSecretsBroker(credential.GCPSecretsConfig{
			Project: gcpProject,
		}))
		if externalDefaultBackend == "" {
			externalDefaultBackend = "gcp_secret_manager"
		}
	}

	azureURL := cfg.AzureKeyVaultURL
	if azureURL == "" {
		azureURL = strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_AZURE_VAULT_URL"))
	}
	if azureURL != "" {
		tenantID := cfg.AzureTenantID
		if tenantID == "" {
			tenantID = strings.TrimSpace(os.Getenv("AZURE_TENANT_ID"))
		}
		clientID := cfg.AzureClientID
		if clientID == "" {
			clientID = strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
		}
		clientSecret := cfg.AzureClientSecret
		if clientSecret == "" {
			clientSecret = strings.TrimSpace(os.Getenv("AZURE_CLIENT_SECRET"))
		}
		backends = append(backends, credential.NewAzureKeyVaultBroker(credential.AzureKeyVaultConfig{
			VaultURL:     azureURL,
			TenantID:     tenantID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		}))
		if externalDefaultBackend == "" {
			externalDefaultBackend = "azure_key_vault"
		}
	}

	opHost := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_HOST"))
	opToken := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_TOKEN"))
	opVault := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_VAULT"))
	if opHost != "" && opToken != "" {
		backends = append(backends, &credential.OnePasswordBroker{
			ConnectHost:  opHost,
			ConnectToken: opToken,
			VaultID:      opVault,
		})
		if externalDefaultBackend == "" {
			externalDefaultBackend = "1password"
		}
	}

	infHost := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_HOST"))
	infToken := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_TOKEN"))
	infProject := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_PROJECT"))
	if infHost != "" && infToken != "" {
		backends = append(backends, &credential.InfisicalBroker{
			Host:      infHost,
			Token:     infToken,
			ProjectID: infProject,
		})
		if externalDefaultBackend == "" {
			externalDefaultBackend = "infisical"
		}
	}

	router := credential.NewRouter(backends, &credential.EnvBroker{})

	defaultBackend := "env"
	if externalDefaultBackend != "" {
		defaultBackend = externalDefaultBackend
	}
	envDefault := strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_DEFAULT_BACKEND"))
	if envDefault != "" {
		defaultBackend = envDefault
	}
	if err := router.AddRoute("*", defaultBackend); err != nil {
		_ = router.AddRoute("*", "env")
	}
	return router
}

func (d *Daemon) enforceStartupPreflight(doc *policy.Doc, workloadProvider principal.WorkloadProvider) error {
	if !d.cfg.StrictPreflight {
		return nil
	}

	if doc == nil {
		return fmt.Errorf("startup preflight failed: policy gate (policy document unavailable)")
	}
	if d.wal == nil || d.store == nil {
		return fmt.Errorf("startup preflight failed: provenance gate (wal/store must both be initialized)")
	}
	if workloadProvider == nil {
		return fmt.Errorf("startup preflight failed: identity gate (no workload identity provider configured)")
	}

	identityCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resolvedIdentity, err := workloadProvider.Identity(identityCtx)
	if err != nil {
		return fmt.Errorf("startup preflight failed: identity gate (resolve identity: %w)", err)
	}
	if resolvedIdentity == nil || strings.TrimSpace(resolvedIdentity.ID) == "" || !resolvedIdentity.Verified {
		return fmt.Errorf("startup preflight failed: identity gate (workload identity must be verified)")
	}
	if !principal.IsTrustedVerificationMethod(resolvedIdentity.Method) {
		return fmt.Errorf("startup preflight failed: identity gate (untrusted verification method %q)", resolvedIdentity.Method)
	}

	if policyRequiresCredentialSequestration(doc) && !hasCredentialSequestrationBackend(d.cfg) {
		return fmt.Errorf("startup preflight failed: credential sequestration gate (policy requires brokered credentials but no broker backend is configured)")
	}

	if policyRequiresIDPProvider(doc) {
		provider := strings.ToLower(strings.TrimSpace(d.cfg.IDPProvider))
		if provider == "" {
			return fmt.Errorf("startup preflight failed: idp gate (policy references principal/delegation claims but no idp provider is configured)")
		}
		if err := principalidp.ValidateProviderConfigFromEnv(provider); err != nil {
			return fmt.Errorf("startup preflight failed: idp gate (%v)", err)
		}
	}

	if missing := missingDeferBackends(doc, d.cfg); len(missing) > 0 {
		return fmt.Errorf("startup preflight failed: defer backend gate (missing %s)", strings.Join(missing, ", "))
	}

	if err := d.enforceArtifactIntegrityPreflight(); err != nil {
		return err
	}

	d.log.Info("startup preflight passed",
		zap.String("workload_provider", workloadProvider.Name()),
		zap.String("identity_method", resolvedIdentity.Method),
		zap.Bool("credential_sequestration_required", policyRequiresCredentialSequestration(doc)),
		zap.Bool("idp_required", policyRequiresIDPProvider(doc)),
		zap.Bool("defer_effects_present", policyHasDeferEffects(doc)),
		zap.String("integrity_manifest_path", strings.TrimSpace(d.cfg.IntegrityManifestPath)),
		zap.String("buildinfo_expected_path", strings.TrimSpace(d.cfg.BuildInfoExpectedPath)),
	)
	return nil
}

func (d *Daemon) enforceArtifactIntegrityPreflight() error {
	manifestPath := strings.TrimSpace(d.cfg.IntegrityManifestPath)
	if manifestPath == "" {
		return fmt.Errorf("startup preflight failed: integrity gate (--integrity-manifest is required in strict mode)")
	}
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("startup preflight failed: integrity gate (read manifest: %w)", err)
	}
	manifest, err := artifactverify.LoadManifestJSON(rawManifest)
	if err != nil {
		return fmt.Errorf("startup preflight failed: integrity gate (parse manifest: %w)", err)
	}
	baseDir := strings.TrimSpace(d.cfg.IntegrityBaseDir)
	if baseDir == "" {
		baseDir = "."
	}
	if err := artifactverify.VerifyManifest(baseDir, manifest); err != nil {
		return fmt.Errorf("startup preflight failed: integrity gate (manifest verification: %w)", err)
	}

	buildinfoPath := strings.TrimSpace(d.cfg.BuildInfoExpectedPath)
	if buildinfoPath == "" {
		return fmt.Errorf("startup preflight failed: integrity gate (--buildinfo-expected is required in strict mode)")
	}
	rawExpected, err := os.ReadFile(buildinfoPath)
	if err != nil {
		return fmt.Errorf("startup preflight failed: integrity gate (read buildinfo expected: %w)", err)
	}
	var expected reprobuild.Fingerprint
	if err := json.Unmarshal(rawExpected, &expected); err != nil {
		return fmt.Errorf("startup preflight failed: integrity gate (parse buildinfo expected: %w)", err)
	}
	actual, err := reprobuild.Current()
	if err != nil {
		return fmt.Errorf("startup preflight failed: integrity gate (load runtime buildinfo: %w)", err)
	}
	if diff := reprobuild.Compare(&expected, actual); len(diff) > 0 {
		return fmt.Errorf("startup preflight failed: integrity gate (buildinfo mismatch: %s)", strings.Join(diff, "; "))
	}

	bomRaw, err := sbom.GenerateJSON("", "")
	if err != nil {
		return fmt.Errorf("startup preflight failed: sbom gate (generate cyclonedx: %w)", err)
	}
	var bomDoc struct {
		BOMFormat  string `json:"bomFormat"`
		Components []any  `json:"components"`
	}
	if err := json.Unmarshal(bomRaw, &bomDoc); err != nil {
		return fmt.Errorf("startup preflight failed: sbom gate (parse cyclonedx: %w)", err)
	}
	if !strings.EqualFold(strings.TrimSpace(bomDoc.BOMFormat), "cyclonedx") {
		return fmt.Errorf("startup preflight failed: sbom gate (unexpected bomFormat %q)", bomDoc.BOMFormat)
	}
	if len(bomDoc.Components) == 0 {
		return fmt.Errorf("startup preflight failed: sbom gate (components empty)")
	}

	return nil
}

func policyRequiresCredentialSequestration(doc *policy.Doc) bool {
	if doc == nil {
		return false
	}
	for _, tool := range doc.Tools {
		for _, tag := range tool.Tags {
			normalized := strings.ToLower(strings.TrimSpace(tag))
			if normalized == "credential:required" || normalized == "credential:broker" {
				return true
			}
		}
	}
	return false
}

func hasCredentialSequestrationBackend(cfg Config) bool {
	if hasExternalCredentialSequestrationBackend(cfg) {
		return true
	}
	if cfg.AllowEnvCredentialFallback {
		return true
	}
	if parseBoolEnvDefault("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", false) {
		return true
	}
	return false
}

func hasExternalCredentialSequestrationBackend(cfg Config) bool {
	if strings.TrimSpace(cfg.VaultAddr) != "" || strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_VAULT_ADDR")) != "" {
		return true
	}
	if strings.TrimSpace(cfg.AWSSecretsRegion) != "" || strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_AWS_REGION")) != "" {
		return true
	}
	if strings.TrimSpace(cfg.GCPSecretsProject) != "" || strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_GCP_PROJECT")) != "" {
		return true
	}
	if strings.TrimSpace(cfg.AzureKeyVaultURL) != "" || strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_AZURE_VAULT_URL")) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_HOST")) != "" && strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_1PASSWORD_TOKEN")) != "" {
		return true
	}
	if strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_HOST")) != "" && strings.TrimSpace(os.Getenv("FARAMESH_CREDENTIAL_INFISICAL_TOKEN")) != "" {
		return true
	}
	return false
}

func policyRequiresIDPProvider(doc *policy.Doc) bool {
	if doc == nil {
		return false
	}
	requiresFromExpr := func(expr string) bool {
		e := strings.ToLower(strings.TrimSpace(expr))
		return strings.Contains(e, "principal.") || strings.Contains(e, "delegation.")
	}

	for _, rule := range doc.Rules {
		if requiresFromExpr(rule.Match.When) {
			return true
		}
	}
	for _, tr := range doc.PhaseTransitions {
		if requiresFromExpr(tr.Conditions) {
			return true
		}
	}
	for _, guard := range doc.CrossSessionGuards {
		if strings.EqualFold(strings.TrimSpace(guard.Scope), "principal") {
			return true
		}
	}
	return false
}

func policyHasDeferEffects(doc *policy.Doc) bool {
	if doc == nil {
		return false
	}
	for _, rule := range doc.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.Effect), "defer") {
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(doc.DefaultEffect), "defer") {
		return true
	}
	if doc.Budget != nil && strings.EqualFold(strings.TrimSpace(doc.Budget.OnExceed), "defer") {
		return true
	}
	for _, guard := range doc.ContextGuards {
		if strings.EqualFold(strings.TrimSpace(guard.OnStale), "defer") ||
			strings.EqualFold(strings.TrimSpace(guard.OnMissing), "defer") ||
			strings.EqualFold(strings.TrimSpace(guard.OnInconsistent), "defer") {
			return true
		}
	}
	for _, tr := range doc.PhaseTransitions {
		if strings.EqualFold(strings.TrimSpace(tr.Effect), "defer") {
			return true
		}
	}
	if doc.PhaseEnforcement != nil && strings.EqualFold(strings.TrimSpace(doc.PhaseEnforcement.OnOutOfPhaseCall), "defer") {
		return true
	}
	for _, guard := range doc.CrossSessionGuards {
		if strings.EqualFold(strings.TrimSpace(guard.OnExceed), "defer") {
			return true
		}
	}
	if doc.LoopGovernance != nil && strings.EqualFold(strings.TrimSpace(doc.LoopGovernance.OnMaxReached), "defer") {
		return true
	}
	if doc.LoopGovernance != nil && doc.LoopGovernance.ConvergenceTrack != nil {
		if strings.EqualFold(strings.TrimSpace(doc.LoopGovernance.ConvergenceTrack.OnEvasion), "defer") {
			return true
		}
	}
	for _, out := range doc.OutputPolicies {
		for _, rule := range out.Rules {
			if strings.EqualFold(strings.TrimSpace(rule.OnMatch), "defer") {
				return true
			}
		}
	}
	return false
}

func missingDeferBackends(doc *policy.Doc, cfg Config) []string {
	if !policyHasDeferEffects(doc) || doc == nil || doc.DeferPriority == nil {
		return nil
	}

	channels := map[string]struct{}{}
	addChannel := func(tier *policy.DeferTier) {
		if tier == nil {
			return
		}
		channel := strings.ToLower(strings.TrimSpace(tier.Channel))
		if channel != "" {
			channels[channel] = struct{}{}
		}
	}
	addChannel(doc.DeferPriority.Critical)
	addChannel(doc.DeferPriority.High)
	addChannel(doc.DeferPriority.Normal)

	missing := []string{}
	if _, ok := channels["slack"]; ok && strings.TrimSpace(cfg.SlackWebhook) == "" {
		missing = append(missing, "--slack-webhook")
	}
	if _, ok := channels["pagerduty"]; ok && strings.TrimSpace(cfg.PagerDutyRoutingKey) == "" {
		missing = append(missing, "--pagerduty-routing-key")
	}
	return missing
}

func extractPolicyCallbacks(doc *policy.Doc) any {
	if doc == nil {
		return nil
	}
	v := reflect.ValueOf(doc)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	f := v.FieldByName("Callbacks")
	if !f.IsValid() {
		return nil
	}
	return f.Interface()
}

func (d *Daemon) bootstrapEBPF() {
	if !d.cfg.EnableEBPF {
		return
	}
	adapter, err := ebpfNew(d.log, ebpf.Config{
		ObjectPath:        d.cfg.EBPFObjectPath,
		AttachTracepoints: d.cfg.EBPFAttachTracepoints,
	})
	if err != nil {
		if errors.Is(err, ebpf.ErrUnsupported) {
			d.log.Warn("eBPF adapter unsupported; continuing without eBPF", zap.Error(err))
			return
		}
		d.log.Warn("eBPF adapter initialization failed; continuing without eBPF", zap.Error(err))
		return
	}
	if err := adapter.Attach(); err != nil {
		d.log.Warn("eBPF adapter attach failed; continuing without eBPF", zap.Error(err))
		_ = adapter.Close()
		return
	}
	d.ebpfAdapter = adapter
	d.log.Info("eBPF adapter initialized",
		zap.Bool("loaded", adapter.Loaded()),
		zap.Int("program_count", adapter.ProgramCount()),
	)
}

func buildTriageFromPolicy(cfg *policy.DeferPriorityConfig) *deferwork.Triage {
	out := deferwork.TriageConfig{
		DefaultSLA:      15 * time.Minute,
		DefaultPriority: deferwork.PriorityNormal,
	}
	if cfg == nil {
		return deferwork.NewTriage(out)
	}
	if cfg.Critical != nil && cfg.Critical.SLASeconds > 0 {
		out.DefaultSLA = time.Duration(cfg.Critical.SLASeconds) * time.Second
	}
	addRule := func(tier *policy.DeferTier, priority string) {
		if tier == nil {
			return
		}
		pattern := parseSimpleToolPattern(tier.Criteria)
		if pattern == "" {
			return
		}
		out.Rules = append(out.Rules, deferwork.TriageRule{
			ToolPattern:   pattern,
			Priority:      priority,
			SLA:           time.Duration(tier.SLASeconds) * time.Second,
			AutoDeny:      tier.AutoDenyAfterSecs > 0,
			AutoDenyAfter: time.Duration(tier.AutoDenyAfterSecs) * time.Second,
			EscalateTo:    strings.ToLower(strings.TrimSpace(tier.Channel)),
		})
	}
	addRule(cfg.Critical, deferwork.PriorityCritical)
	addRule(cfg.High, deferwork.PriorityHigh)
	addRule(cfg.Normal, deferwork.PriorityNormal)
	return deferwork.NewTriage(out)
}

func parseSimpleToolPattern(criteria string) string {
	c := strings.TrimSpace(criteria)
	if c == "" {
		return ""
	}
	// Accept only simple glob-like criteria as direct tool patterns.
	if strings.ContainsAny(c, " ()=><&|![]\"'") {
		return ""
	}
	return c
}

func buildPhaseManagerFromPolicy(doc *policy.Doc) *phases.PhaseManager {
	if doc == nil || len(doc.Phases) == 0 {
		return nil
	}
	ordered := make([]phases.Phase, 0, len(doc.Phases))
	ids := make([]string, 0, len(doc.Phases))
	for id := range doc.Phases {
		ids = append(ids, id)
	}
	// Keep deterministic order so first phase selection remains stable.
	// init still wins at runtime through firstPhaseName in pipeline.
	sort.Strings(ids)
	for _, id := range ids {
		cfg := doc.Phases[id]
		ordered = append(ordered, phases.Phase{
			ID:                 id,
			Name:               id,
			AllowedTools:       append([]string(nil), cfg.Tools...),
			AllowedTransitions: []string{"*"},
		})
	}
	return phases.NewPhaseManager(ordered)
}

func buildPrincipalTokenResolver(cfg Config, log *zap.Logger) func(context.Context, string) (*principal.Identity, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.IDPProvider))
	if provider == "" {
		return nil
	}
	if err := principalidp.ValidateProviderConfigFromEnv(provider); err != nil {
		log.Warn("idp resolver disabled: invalid provider configuration", zap.String("provider", provider), zap.Error(err))
		return nil
	}

	verifier, err := principalidp.NewVerifierFromEnv(provider)
	if err != nil {
		log.Warn("idp resolver disabled: failed to configure provider", zap.String("provider", provider), zap.Error(err))
		return nil
	}
	chain := principalidp.NewProviderChain(verifier)
	log.Info("idp principal resolver configured", zap.String("provider", provider))

	return func(ctx context.Context, token string) (*principal.Identity, error) {
		verified, resolvedProvider, err := chain.VerifyToken(ctx, token)
		if err != nil {
			return nil, err
		}
		resolved := principalFromIDPIdentity(verified, resolvedProvider)
		if resolved == nil {
			return nil, fmt.Errorf("idp verification returned no resolvable principal identity")
		}
		return resolved, nil
	}
}

func principalFromIDPIdentity(verified *principalidp.VerifiedIdentity, provider string) *principal.Identity {
	if verified == nil {
		return nil
	}

	id := strings.TrimSpace(verified.Subject)
	if id == "" {
		id = strings.TrimSpace(verified.Email)
	}
	if id == "" {
		id = strings.TrimSpace(verified.Name)
	}
	if id == "" {
		return nil
	}

	role := ""
	if len(verified.Roles) > 0 {
		role = strings.TrimSpace(verified.Roles[0])
	}
	if role == "" && len(verified.Groups) > 0 {
		role = strings.TrimSpace(verified.Groups[0])
	}

	tier := ""
	if verified.RawClaims != nil {
		tier = strings.TrimSpace(firstStringClaim(verified.RawClaims, "tier", "plan", "subscription_tier"))
	}

	org := strings.TrimSpace(verified.Org)
	if org == "" && verified.RawClaims != nil {
		org = strings.TrimSpace(firstStringClaim(verified.RawClaims, "org", "hd", "tenant", "tenant_id", "tid"))
	}

	method := "idp_oidc"
	if normalizedProvider := strings.ToLower(strings.TrimSpace(provider)); normalizedProvider != "" {
		switch normalizedProvider {
		case "ldap":
			method = "ldap_bind"
		case "local", "default":
			method = "idp_local"
		default:
			method = normalizedProvider + "_oidc"
		}
	}

	return &principal.Identity{
		ID:       id,
		Tier:     tier,
		Role:     role,
		Org:      org,
		Verified: true,
		Method:   method,
	}
}

func firstStringClaim(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := claims[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			if v := strings.TrimSpace(typed); v != "" {
				return v
			}
		case []any:
			for _, item := range typed {
				if s, ok := item.(string); ok {
					s = strings.TrimSpace(s)
					if s != "" {
						return s
					}
				}
			}
		}
	}
	return ""
}

func parseIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func parseBoolEnvDefault(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func (d *Daemon) seedToolInventory(store dpr.StoreBackend) error {
	if d == nil || d.toolInventory == nil || store == nil {
		return nil
	}
	agents, err := store.KnownAgents()
	if err != nil {
		return err
	}
	for _, agentID := range agents {
		records, err := store.RecentByAgent(agentID, 100000)
		if err != nil {
			return err
		}
		if err := d.toolInventory.SeedFromDPRRecords(records); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) stop() error {
	if d.policyPollCancel != nil {
		d.policyPollCancel()
	}
	// Remove PID file.
	pidPath := filepath.Join(d.cfg.DataDir, "faramesh.pid")
	_ = os.Remove(pidPath)

	if d.server != nil {
		_ = d.server.Close()
	}
	d.stopFleetPolicyReloadSubscriber()
	d.unregisterFleetInstance()
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
	if d.pipeline != nil {
		_ = d.pipeline.CloseStandingPersistence()
	}
	if d.wal != nil {
		_ = d.wal.Close()
	}
	if d.dprQueue != nil {
		_ = d.dprQueue.Close()
	}
	if d.store != nil {
		_ = d.store.Close()
	}
	if d.toolInventory != nil {
		_ = d.toolInventory.Close()
	}
	if d.sessBackend != nil {
		_ = d.sessBackend.Close()
	}
	if d.deferBackend != nil {
		_ = d.deferBackend.Close()
	}
	if d.dailyCostStore != nil {
		_ = d.dailyCostStore.Close()
	}
	if d.delegateStore != nil {
		_ = d.delegateStore.Close()
	}
	if d.scheduleStore != nil {
		_ = d.scheduleStore.Close()
	}
	if d.webhooks != nil {
		d.webhooks.Close()
	}
	if d.syncer != nil {
		d.syncer.Close() // flushes remaining records
	}
	if d.ebpfAdapter != nil {
		_ = d.ebpfAdapter.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	observe.ShutdownOTLP(ctx)
	cancel()
	d.log.Info("daemon stopped cleanly")
	return nil
}

func coalesceString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (d *Daemon) registerFleetInstance(agentID string) error {
	if d.fleetRedis == nil {
		return nil
	}
	host, _ := os.Hostname()
	instanceID := strings.TrimSpace(host) + ":" + strconv.Itoa(os.Getpid())
	now := time.Now().UTC().Format(time.RFC3339)
	entry := map[string]any{
		"instance_id": instanceID,
		"agent_id":    strings.TrimSpace(agentID),
		"host":        strings.TrimSpace(host),
		"pid":         os.Getpid(),
		"socket":      d.cfg.SocketPath,
		"started_at":  now,
		"updated_at":  now,
		"status":      "running",
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if err := d.fleetRedis.HSet(context.Background(), fleetRegistryKey, instanceID, raw).Err(); err != nil {
		return err
	}
	d.fleetInstanceID = instanceID
	return nil
}

func (d *Daemon) unregisterFleetInstance() {
	if d.fleetRedis == nil || d.fleetInstanceID == "" {
		return
	}
	_ = d.fleetRedis.HDel(context.Background(), fleetRegistryKey, d.fleetInstanceID).Err()
}

func (d *Daemon) publishFleetPolicyReloadEvent(ctx context.Context, event fleetPolicyReloadEvent) {
	if d.fleetRedis == nil || strings.TrimSpace(event.Action) != fleetPolicyReloadActionName {
		return
	}
	payload, err := json.Marshal(event)
	if err != nil {
		d.log.Warn("marshal fleet policy reload event failed", zap.Error(err))
		return
	}
	if err := d.fleetRedis.Publish(ctx, fleetPolicyReloadChannel, payload).Err(); err != nil {
		d.log.Warn("publish fleet policy reload event failed", zap.Error(err))
	}
}

func (d *Daemon) startFleetPolicyReloadSubscriber() {
	if d.fleetRedis == nil || d.fleetPolicySubCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.fleetPolicySubCancel = cancel
	sub := d.fleetRedis.Subscribe(ctx, fleetPolicyReloadChannel)
	if _, err := sub.Receive(ctx); err != nil {
		d.log.Warn("fleet policy-reload subscribe failed", zap.Error(err))
		_ = sub.Close()
		cancel()
		d.fleetPolicySubCancel = nil
		return
	}
	ch := sub.Channel()
	go func() {
		defer func() {
			_ = sub.Close()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				var event fleetPolicyReloadEvent
				if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
					d.log.Warn("ignore malformed fleet policy-reload payload", zap.Error(err))
					continue
				}
				if !event.valid() {
					d.log.Warn("ignore invalid fleet policy-reload event", zap.String("instance_id", event.InstanceID))
					continue
				}
				if event.InstanceID != "" && event.InstanceID == d.fleetInstanceID {
					continue
				}
				handler := d.applyFleetPolicyReloadEvent
				if d.fleetPolicyApply != nil {
					handler = d.fleetPolicyApply
				}
				applied, err := handler(ctx, event)
				if err != nil {
					d.log.Warn("fleet policy-reload apply failed", zap.Error(err))
					continue
				}
				if applied {
					d.log.Info("fleet policy-reload applied",
						zap.String("instance_id", event.InstanceID),
						zap.String("source_type", event.SourceType),
						zap.String("source_id", event.SourceID),
						zap.String("policy_hash", event.PolicyHash),
					)
				}
			}
		}
	}()
}

func (d *Daemon) stopFleetPolicyReloadSubscriber() {
	if d.fleetPolicySubCancel != nil {
		d.fleetPolicySubCancel()
		d.fleetPolicySubCancel = nil
	}
}

func (e fleetPolicyReloadEvent) valid() bool {
	if strings.TrimSpace(e.Action) != fleetPolicyReloadActionName {
		return false
	}
	if strings.TrimSpace(e.PolicyYAML) == "" && strings.TrimSpace(e.SourceType) == "" {
		return false
	}
	return true
}

func (d *Daemon) applyFleetPolicyReloadEvent(ctx context.Context, event fleetPolicyReloadEvent) (bool, error) {
	if strings.TrimSpace(event.PolicyHash) != "" && event.PolicyHash == d.lastPolicyHash {
		return false, nil
	}

	if strings.TrimSpace(event.PolicyYAML) != "" {
		tmpFile, err := os.CreateTemp("", "faramesh-fleet-policy-*.yaml")
		if err != nil {
			return false, fmt.Errorf("create temp policy file: %w", err)
		}
		tmpPath := tmpFile.Name()
		_ = tmpFile.Close()
		defer os.Remove(tmpPath)
		if err := os.WriteFile(tmpPath, []byte(event.PolicyYAML), 0o600); err != nil {
			return false, fmt.Errorf("write temp policy file: %w", err)
		}
		doc, version, err := policy.LoadFile(tmpPath)
		if err != nil {
			return false, fmt.Errorf("load policy payload: %w", err)
		}
		if errs := policy.Validate(doc); len(errs) > 0 {
			for _, msg := range errs {
				d.log.Warn("fleet policy payload validation warning", zap.String("error", msg))
			}
		}
		engine, err := policy.NewEngine(doc, version)
		if err != nil {
			return false, fmt.Errorf("compile policy payload: %w", err)
		}
		if d.pipeline != nil {
			if err := d.pipeline.ApplyPolicyBundle(doc, engine); err != nil {
				return false, fmt.Errorf("apply policy payload bundle: %w", err)
			}
		} else {
			d.engine.Swap(engine)
		}
		if strings.TrimSpace(event.PolicyHash) != "" {
			d.lastPolicyHash = event.PolicyHash
		} else {
			d.lastPolicyHash = version
		}
		return true, nil
	}

	switch strings.TrimSpace(event.SourceType) {
	case string(policy.SourceURL):
		if d.policyLoader == nil {
			d.policyLoader = policy.NewPolicyLoader()
		}
		src, err := d.policyLoader.FromURL(ctx, event.SourceID)
		if err != nil {
			return false, fmt.Errorf("load policy from source URL: %w", err)
		}
		if errs := policy.Validate(src.Doc); len(errs) > 0 {
			for _, msg := range errs {
				d.log.Warn("fleet policy source validation warning", zap.String("error", msg))
			}
		}
		if d.pipeline != nil {
			if err := d.pipeline.ApplyPolicyBundle(src.Doc, src.Engine); err != nil {
				return false, fmt.Errorf("apply policy source bundle: %w", err)
			}
		} else {
			if err := d.engine.HotReload(src.Doc, src.Version); err != nil {
				return false, fmt.Errorf("compile policy source: %w", err)
			}
		}
		d.policyLoader.Activate(src)
		d.lastPolicyHash = src.Hash
		return true, nil
	case string(policy.SourceFile):
		doc, version, err := policy.LoadFile(event.SourceID)
		if err != nil {
			return false, fmt.Errorf("load policy from source file: %w", err)
		}
		if errs := policy.Validate(doc); len(errs) > 0 {
			for _, msg := range errs {
				d.log.Warn("fleet policy source validation warning", zap.String("error", msg))
			}
		}
		engine, err := policy.NewEngine(doc, version)
		if err != nil {
			return false, fmt.Errorf("compile policy source: %w", err)
		}
		if d.pipeline != nil {
			if err := d.pipeline.ApplyPolicyBundle(doc, engine); err != nil {
				return false, fmt.Errorf("apply policy source bundle: %w", err)
			}
		} else {
			d.engine.Swap(engine)
		}
		if strings.TrimSpace(event.PolicyHash) != "" {
			d.lastPolicyHash = event.PolicyHash
		} else {
			d.lastPolicyHash = version
		}
		return true, nil
	default:
		return false, nil
	}
}

func (d *Daemon) loadInitialPolicy() (*policy.Doc, string, error) {
	if d.cfg.PolicyURL != "" {
		d.policyLoader = policy.NewPolicyLoader()
		src, err := d.policyLoader.FromURL(context.Background(), d.cfg.PolicyURL)
		if err != nil {
			return nil, "", fmt.Errorf("load policy from URL: %w", err)
		}
		if errs := policy.Validate(src.Doc); len(errs) > 0 {
			for _, e := range errs {
				d.log.Warn("policy validation error", zap.String("error", e))
			}
		}
		d.policyLoader.Activate(src)
		d.lastPolicyHash = src.Hash
		d.policySourceType = string(policy.SourceURL)
		d.policySourceID = d.cfg.PolicyURL
		d.engine = policy.NewAtomicEngine(src.Engine)
		return src.Doc, src.Version, nil
	}

	doc, version, err := policy.LoadFile(d.cfg.PolicyPath)
	if err != nil {
		return nil, "", fmt.Errorf("load policy: %w", err)
	}
	if errs := policy.Validate(doc); len(errs) > 0 {
		for _, e := range errs {
			d.log.Warn("policy validation error", zap.String("error", e))
		}
	}
	engine, err := policy.NewEngine(doc, version)
	if err != nil {
		return nil, "", fmt.Errorf("compile policy: %w", err)
	}
	d.policySourceType = string(policy.SourceFile)
	d.policySourceID = d.cfg.PolicyPath
	d.lastPolicyHash = version
	d.engine = policy.NewAtomicEngine(engine)
	return doc, version, nil
}

func (d *Daemon) startPolicyWatcher() {
	if d.cfg.PolicyURL == "" {
		return
	}
	interval := d.cfg.PolicyPollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.policyPollCancel = cancel
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				changed, err := d.reloadPolicyIfChanged()
				if err != nil {
					d.log.Warn("policy URL poll reload failed", zap.Error(err), zap.String("policy_url", d.cfg.PolicyURL))
					continue
				}
				if changed {
					d.log.Info("policy URL change applied", zap.String("policy_url", d.cfg.PolicyURL))
				}
			}
		}
	}()
}

func (d *Daemon) buildAdapterTLSConfig() (*tls.Config, error) {
	if d.cfg.TLSCertFile == "" && d.cfg.TLSKeyFile == "" && d.cfg.ClientCAFile == "" && !d.cfg.TLSAuto {
		return nil, nil
	}
	if !d.cfg.TLSAuto && (d.cfg.TLSCertFile == "" || d.cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}
	var (
		cert tls.Certificate
		err  error
	)
	if d.cfg.TLSCertFile != "" && d.cfg.TLSKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(d.cfg.TLSCertFile, d.cfg.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert/key: %w", err)
		}
	} else {
		cert, err = generateSelfSignedAdapterCertificate()
		if err != nil {
			return nil, fmt.Errorf("generate self-signed tls cert: %w", err)
		}
		d.log.Warn("adapter TLS auto-cert enabled with ephemeral self-signed certificate",
			zap.String("mode", "auto"),
			zap.Duration("valid_for", 24*time.Hour),
		)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if d.cfg.ClientCAFile != "" {
		caPEM, err := os.ReadFile(d.cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse client ca pem")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func generateSelfSignedAdapterCertificate() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	certTemplate := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "faramesh-local",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	if hostname, hostErr := os.Hostname(); hostErr == nil {
		hostname = strings.TrimSpace(hostname)
		if hostname != "" && !strings.EqualFold(hostname, "localhost") {
			certTemplate.DNSNames = append(certTemplate.DNSNames, hostname)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})

	generated, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("build key pair: %w", err)
	}
	return generated, nil
}

func loadInferenceRoutesFromFile(path string) ([]proxy.InferenceRoute, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	routes := make([]proxy.InferenceRoute, 0)
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	for i := range routes {
		routes[i].Name = strings.TrimSpace(routes[i].Name)
		routes[i].HostPattern = strings.TrimSpace(routes[i].HostPattern)
		routes[i].PathPattern = strings.TrimSpace(routes[i].PathPattern)
		routes[i].Upstream = strings.TrimSpace(routes[i].Upstream)
		routes[i].AuthType = strings.TrimSpace(routes[i].AuthType)
		routes[i].AuthHeader = strings.TrimSpace(routes[i].AuthHeader)
		routes[i].AuthToken = strings.TrimSpace(routes[i].AuthToken)
		routes[i].AuthTokenEnv = strings.TrimSpace(routes[i].AuthTokenEnv)
		routes[i].AuthBrokerToolID = strings.TrimSpace(routes[i].AuthBrokerToolID)
		routes[i].AuthBrokerOperation = strings.TrimSpace(routes[i].AuthBrokerOperation)
		routes[i].AuthBrokerScope = strings.TrimSpace(routes[i].AuthBrokerScope)
		routes[i].ModelRewrite = strings.TrimSpace(routes[i].ModelRewrite)
		if routes[i].HostPattern == "" {
			routes[i].HostPattern = "*"
		}
		if routes[i].PathPattern == "" {
			routes[i].PathPattern = "*"
		}
		if routes[i].Name == "" {
			routes[i].Name = fmt.Sprintf("route-%d", i+1)
		}
		if routes[i].Upstream == "" {
			return nil, fmt.Errorf("route %q has empty upstream", routes[i].Name)
		}
	}
	return routes, nil
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
