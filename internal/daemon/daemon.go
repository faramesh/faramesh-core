// Package daemon implements the faramesh serve lifecycle:
// load policy, open WAL + SQLite, start SDK socket server, handle signals.
package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"github.com/faramesh/faramesh-core/internal/core/degraded"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/jobs"
	"github.com/faramesh/faramesh-core/internal/core/multiagent"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/phases"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	principalidp "github.com/faramesh/faramesh-core/internal/core/principal/idp"
	"github.com/faramesh/faramesh-core/internal/core/session"
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

	ProxyPort             int
	ProxyConnect          bool // HTTP CONNECT only (governed as proxy/connect)
	ProxyForward          bool // CONNECT + RFC 7230 absolute-form HTTP (proxy/connect + proxy/http)
	NetworkHardeningMode  string
	InferenceRoutesFile   string
	AllowedPrivateCIDRs   []string
	AllowedPrivateHosts   []string
	GRPCPort              int
	MCPProxyPort          int
	MCPTarget             string
	MetricsPort           int
	DPRDSN                string
	RedisURL              string
	DPRHMACKey            string
	TLSCertFile           string
	TLSKeyFile            string
	ClientCAFile          string
	TLSAuto               bool
	PagerDutyRoutingKey   string
	PolicyAdminToken      string
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
	syncer               *cloud.Syncer
	proxy                *proxy.Server
	grpc                 *gatewaydaemon.Server
	grpcLis              net.Listener
	mcpGateway           *mcp.HTTPGateway
	metricsSrv           *http.Server
	sessBackend          session.Backend
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
		cfg.DataDir = filepath.Join(os.TempDir(), "faramesh")
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = sdk.SocketPath
	}
	cfg.NetworkHardeningMode = strings.ToLower(strings.TrimSpace(cfg.NetworkHardeningMode))
	if cfg.NetworkHardeningMode == "" {
		cfg.NetworkHardeningMode = string(proxy.HardeningModeOff)
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
	return &Daemon{cfg: cfg, log: cfg.Log}, nil
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
	hmacKey := []byte(d.cfg.DPRHMACKey)
	if len(hmacKey) == 0 {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err == nil {
			hmacKey = buf
			d.log.Warn("using ephemeral DPR HMAC key; configure --dpr-hmac-key for stable signatures",
				zap.String("ephemeral_key_prefix", hex.EncodeToString(buf[:4])))
		}
	}

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

	pipeline := core.NewPipeline(core.Config{
		Engine:                  d.engine,
		WAL:                     wal,
		Store:                   store,
		DPRQueue:                dprQueue,
		Sessions:                sessionManager,
		SessionGovernor:         sessionGovernor,
		Defers:                  wf,
		Webhooks:                d.webhooks,
		Degraded:                d.degraded,
		SubPolicies:             subPolicies,
		RoutingGovernor:         routingGovernor,
		LoopGovernor:            loopGovernor,
		AggregationGov:          aggGovernor,
		Callbacks:               callbackManager,
		Revocations:             revocationMgr,
		Elevations:              elevationEngine,
		WorkloadIdentity:        workloadProvider,
		CredentialRouter:        credentialRouter,
		Provenance:              provenanceTracker,
		PhaseManager:            buildPhaseManagerFromPolicy(doc),
		PolicySourceType:        d.policySourceType,
		PolicySourceID:          d.policySourceID,
		StrictModelVerification: d.cfg.StrictPreflight,
		HMACKey:                 hmacKey,
		Log:                     d.log,
	})
	d.pipeline = pipeline
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
		d.mcpGateway = mcp.NewHTTPGateway(pipeline, doc.AgentID, d.cfg.MCPTarget, d.log)
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
			ToolPattern: pattern,
			Priority:    priority,
			SLA:         time.Duration(tier.SLASeconds) * time.Second,
			AutoDeny:    tier.AutoDenyAfterSecs > 0,
			EscalateTo:  strings.ToLower(strings.TrimSpace(tier.Channel)),
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
	if d.wal != nil {
		_ = d.wal.Close()
	}
	if d.dprQueue != nil {
		_ = d.dprQueue.Close()
	}
	if d.store != nil {
		_ = d.store.Close()
	}
	if d.sessBackend != nil {
		_ = d.sessBackend.Close()
	}
	if d.dailyCostStore != nil {
		_ = d.dailyCostStore.Close()
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
	d.log.Info("daemon stopped cleanly")
	return nil
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
