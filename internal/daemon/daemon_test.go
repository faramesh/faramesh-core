package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	adapterebpf "github.com/faramesh/faramesh-core/internal/adapter/ebpf"
	"github.com/faramesh/faramesh-core/internal/artifactverify"
	"github.com/faramesh/faramesh-core/internal/core"
	"github.com/faramesh/faramesh-core/internal/core/degraded"
	"github.com/faramesh/faramesh-core/internal/core/dpr"
	"github.com/faramesh/faramesh-core/internal/core/observe"
	"github.com/faramesh/faramesh-core/internal/core/policy"
	"github.com/faramesh/faramesh-core/internal/core/principal"
	principalidp "github.com/faramesh/faramesh-core/internal/core/principal/idp"
	"github.com/faramesh/faramesh-core/internal/reprobuild"
)

func testDPRRecord(agentID, recordID, prevHash string) *dpr.Record {
	rec := &dpr.Record{
		SchemaVersion:  dpr.SchemaVersion,
		RecordID:       recordID,
		PrevRecordHash: prevHash,
		AgentID:        agentID,
		SessionID:      "sess-" + agentID,
		ToolID:         "tool/run",
		Effect:         "PERMIT",
		PolicyVersion:  "test-policy",
		CreatedAt:      time.Now().UTC(),
	}
	rec.ComputeHash()
	return rec
}

func TestFleetPolicyReloadPublishConsumeApplyFlow(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	applied := make(chan fleetPolicyReloadEvent, 1)
	d := &Daemon{
		log:             zap.NewNop(),
		fleetRedis:      client,
		fleetInstanceID: "local-instance",
		fleetPolicyApply: func(_ context.Context, event fleetPolicyReloadEvent) (bool, error) {
			applied <- event
			return true, nil
		},
	}
	d.startFleetPolicyReloadSubscriber()
	defer d.stopFleetPolicyReloadSubscriber()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	event := fleetPolicyReloadEvent{
		Action:        fleetPolicyReloadActionName,
		InstanceID:    "peer-instance",
		SourceType:    "file",
		SourceID:      "/tmp/policy.yaml",
		PolicyVersion: "v1",
		PolicyHash:    "hash-v1",
		PolicyYAML:    "faramesh-version: \"1.0\"\nagent-id: \"a\"\nrules: []\ndefault_effect: deny\n",
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
	}
	d.publishFleetPolicyReloadEvent(ctx, event)

	select {
	case got := <-applied:
		if got.PolicyHash != "hash-v1" {
			t.Fatalf("expected hash-v1, got %+v", got)
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for applied event")
	}
}

func TestFleetPolicyReloadSubscriberIgnoresMalformedEvents(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	calls := 0
	d := &Daemon{
		log:             zap.NewNop(),
		fleetRedis:      client,
		fleetInstanceID: "local-instance",
		fleetPolicyApply: func(_ context.Context, event fleetPolicyReloadEvent) (bool, error) {
			calls++
			return true, nil
		},
	}
	d.startFleetPolicyReloadSubscriber()
	defer d.stopFleetPolicyReloadSubscriber()

	ctx := context.Background()
	if err := client.Publish(ctx, fleetPolicyReloadChannel, "{not-json").Err(); err != nil {
		t.Fatalf("publish malformed json: %v", err)
	}
	badEvent := fleetPolicyReloadEvent{Action: "other", InstanceID: "peer-instance"}
	raw, _ := json.Marshal(badEvent)
	if err := client.Publish(ctx, fleetPolicyReloadChannel, raw).Err(); err != nil {
		t.Fatalf("publish invalid event: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if calls != 0 {
		t.Fatalf("expected no apply calls for malformed events, got %d", calls)
	}
}

func TestLoadInitialPolicyFromURL(t *testing.T) {
	var mu sync.RWMutex
	body := `
faramesh-version: "1.0"
agent-id: "agent-url"
rules:
  - id: allow-all
    match:
      tool: "*"
    effect: permit
default_effect: deny
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d, err := New(Config{
		PolicyURL: srv.URL,
		Log:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}

	doc, version, err := d.loadInitialPolicy()
	if err != nil {
		t.Fatalf("load initial policy: %v", err)
	}

	if doc.AgentID != "agent-url" {
		t.Fatalf("expected agent-id agent-url, got %q", doc.AgentID)
	}
	if version == "" {
		t.Fatalf("expected non-empty version")
	}
	if d.policySourceType != "url" {
		t.Fatalf("expected policy source type url, got %q", d.policySourceType)
	}
	if d.policySourceID != srv.URL {
		t.Fatalf("expected policy source id %q, got %q", srv.URL, d.policySourceID)
	}
	if d.lastPolicyHash == "" {
		t.Fatalf("expected initial policy hash to be set")
	}
	if d.engine == nil {
		t.Fatalf("expected atomic engine to be initialized")
	}
}

func TestReloadPolicyIfChangedURL(t *testing.T) {
	var mu sync.RWMutex
	body := `
faramesh-version: "1.0"
agent-id: "agent-url"
rules:
  - id: allow-all
    match:
      tool: "*"
    effect: permit
default_effect: deny
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d, err := New(Config{
		PolicyURL: srv.URL,
		Log:       zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	if _, _, err := d.loadInitialPolicy(); err != nil {
		t.Fatalf("load initial policy: %v", err)
	}
	initialHash := d.lastPolicyHash

	changed, err := d.reloadPolicyIfChanged()
	if err != nil {
		t.Fatalf("reload unchanged policy: %v", err)
	}
	if changed {
		t.Fatalf("expected no reload when URL content is unchanged")
	}

	mu.Lock()
	body = `
faramesh-version: "1.0"
agent-id: "agent-url-v2"
rules:
  - id: deny-all
    match:
      tool: "*"
    effect: deny
default_effect: permit
`
	mu.Unlock()

	changed, err = d.reloadPolicyIfChanged()
	if err != nil {
		t.Fatalf("reload changed policy: %v", err)
	}
	if !changed {
		t.Fatalf("expected reload when URL content changes")
	}
	if d.lastPolicyHash == initialHash {
		t.Fatalf("expected policy hash to change after reload")
	}
}

func TestWarnOnDPRReconciliationDriftWarnsWhenSQLiteLagsWAL(t *testing.T) {
	dir := t.TempDir()
	wal, err := dpr.OpenWAL(filepath.Join(dir, "faramesh.wal"))
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer wal.Close()

	store, err := dpr.OpenStore(filepath.Join(dir, "faramesh.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	r1 := testDPRRecord("agent-a", "r1", dpr.GenesisPrevHash("agent-a"))
	if err := wal.Write(r1); err != nil {
		t.Fatalf("write wal r1: %v", err)
	}
	if err := store.Save(r1); err != nil {
		t.Fatalf("save store r1: %v", err)
	}

	r2 := testDPRRecord("agent-a", "r2", r1.RecordHash)
	if err := wal.Write(r2); err != nil {
		t.Fatalf("write wal r2: %v", err)
	}

	coreObs, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(coreObs)
	warnOnDPRReconciliationDrift(logger, wal, store)

	entries := logs.FilterMessage("DPR SQLite store is not fully reconciled with WAL; query results may lag until backlog drains").All()
	if len(entries) != 1 {
		t.Fatalf("expected one reconciliation warning, got %d", len(entries))
	}
	ctx := entries[0].ContextMap()
	if got, _ := ctx["wal_records"].(int64); got != 2 {
		t.Fatalf("wal_records=%v want 2", ctx["wal_records"])
	}
	if got, _ := ctx["drifted_agents"].(int64); got != 1 {
		t.Fatalf("drifted_agents=%v want 1", ctx["drifted_agents"])
	}
	examples, _ := ctx["examples"].([]interface{})
	if len(examples) == 0 || !strings.Contains(examples[0].(string), "agent-a") {
		t.Fatalf("expected examples to mention agent-a, got %#v", ctx["examples"])
	}
}

func TestWarnOnDPRReconciliationDriftSilentWhenSQLiteMatchesWAL(t *testing.T) {
	dir := t.TempDir()
	wal, err := dpr.OpenWAL(filepath.Join(dir, "faramesh.wal"))
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer wal.Close()

	store, err := dpr.OpenStore(filepath.Join(dir, "faramesh.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	r1 := testDPRRecord("agent-a", "r1", dpr.GenesisPrevHash("agent-a"))
	r2 := testDPRRecord("agent-a", "r2", r1.RecordHash)
	for _, rec := range []*dpr.Record{r1, r2} {
		if err := wal.Write(rec); err != nil {
			t.Fatalf("write wal %s: %v", rec.RecordID, err)
		}
		if err := store.Save(rec); err != nil {
			t.Fatalf("save store %s: %v", rec.RecordID, err)
		}
	}

	coreObs, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(coreObs)
	warnOnDPRReconciliationDrift(logger, wal, store)

	if got := logs.FilterMessage("DPR SQLite store is not fully reconciled with WAL; query results may lag until backlog drains").Len(); got != 0 {
		t.Fatalf("expected no reconciliation warning, got %d", got)
	}
}

func TestLoadOrCreateDPRHMACKeyPersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	logger := zap.NewNop()

	d1 := &Daemon{cfg: Config{DataDir: dir}, log: logger}
	key1, err := d1.loadOrCreateDPRHMACKey()
	if err != nil {
		t.Fatalf("loadOrCreateDPRHMACKey first run: %v", err)
	}
	if len(key1) == 0 {
		t.Fatalf("expected generated key")
	}

	st, err := os.Stat(filepath.Join(dir, "faramesh.hmac.key"))
	if err != nil {
		t.Fatalf("stat persisted key: %v", err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Fatalf("persisted key mode = %v, want 0600", got)
	}

	d2 := &Daemon{cfg: Config{DataDir: dir}, log: logger}
	key2, err := d2.loadOrCreateDPRHMACKey()
	if err != nil {
		t.Fatalf("loadOrCreateDPRHMACKey second run: %v", err)
	}
	if string(key1) != string(key2) {
		t.Fatalf("expected persisted key to survive restart")
	}
}

func TestHandleHealthzReportsReadiness(t *testing.T) {
	d := &Daemon{
		engine:   policy.NewAtomicEngine(&policy.Engine{}),
		wal:      &dpr.NullWAL{},
		pipeline: core.NewPipeline(core.Config{}),
		store:    &dpr.Store{},
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	d.handleHealthz(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %#v", body)
	}
}

func TestHandleHealthzFailsWhenPipelineUnavailable(t *testing.T) {
	d := &Daemon{}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	d.handleHealthz(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPolicyReloadLogIncludesStructuredSchemaFields(t *testing.T) {
	var mu sync.RWMutex
	body := `
faramesh-version: "1.0"
agent-id: "agent-url"
rules:
  - id: allow-all
    match:
      tool: "*"
    effect: permit
default_effect: deny
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	coreObs, logs := observer.New(zapcore.InfoLevel)
	logger := zap.New(coreObs)
	d, err := New(Config{
		PolicyURL: srv.URL,
		Log:       logger,
	})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	if _, _, err := d.loadInitialPolicy(); err != nil {
		t.Fatalf("load initial policy: %v", err)
	}

	mu.Lock()
	body = `
faramesh-version: "1.0"
agent-id: "agent-url-v2"
rules:
  - id: deny-all
    match:
      tool: "*"
    effect: deny
default_effect: permit
`
	mu.Unlock()

	changed, err := d.reloadPolicyIfChanged()
	if err != nil {
		t.Fatalf("reload changed policy: %v", err)
	}
	if !changed {
		t.Fatalf("expected policy reload to occur")
	}

	entries := logs.FilterMessage("policy reloaded").All()
	if len(entries) == 0 {
		t.Fatalf("expected policy reloaded log entry")
	}
	fields := entries[len(entries)-1].ContextMap()
	if fields["log_schema"] != observe.GovernanceLogSchema {
		t.Fatalf("log_schema=%v", fields["log_schema"])
	}
	if fields["log_schema_version"] != observe.GovernanceLogSchemaVersion {
		t.Fatalf("log_schema_version=%v", fields["log_schema_version"])
	}
	if fields["event"] != observe.EventPolicyReload {
		t.Fatalf("event=%v", fields["event"])
	}
	for _, k := range []string{"version", "policy_hash", "source_type", "source_id"} {
		if _, ok := fields[k]; !ok {
			t.Fatalf("missing required field %q in policy reload structured log", k)
		}
	}
}

type fakeEBPFLifecycle struct {
	attachErr  error
	closeErr   error
	attachCall int
	closeCall  int
	loaded     bool
	programs   int
}

func (f *fakeEBPFLifecycle) Attach() error {
	f.attachCall++
	if f.attachErr == nil {
		f.loaded = true
	}
	return f.attachErr
}

func (f *fakeEBPFLifecycle) Close() error {
	f.closeCall++
	f.loaded = false
	return f.closeErr
}

func (f *fakeEBPFLifecycle) Loaded() bool      { return f.loaded }
func (f *fakeEBPFLifecycle) ProgramCount() int { return f.programs }

func TestBootstrapEBPFDisabled(t *testing.T) {
	orig := ebpfNew
	t.Cleanup(func() { ebpfNew = orig })
	called := false
	ebpfNew = func(_ *zap.Logger, _ adapterebpf.Config) (adapterebpf.Lifecycle, error) {
		called = true
		return &fakeEBPFLifecycle{}, nil
	}

	d := &Daemon{cfg: Config{EnableEBPF: false}, log: zap.NewNop()}
	d.bootstrapEBPF()
	if called {
		t.Fatalf("expected ebpf constructor to not be called when disabled")
	}
}

func TestBootstrapEBPFUnsupportedContinues(t *testing.T) {
	orig := ebpfNew
	t.Cleanup(func() { ebpfNew = orig })
	ebpfNew = func(_ *zap.Logger, _ adapterebpf.Config) (adapterebpf.Lifecycle, error) {
		return nil, adapterebpf.ErrUnsupported
	}

	d := &Daemon{cfg: Config{EnableEBPF: true}, log: zap.NewNop()}
	d.bootstrapEBPF()
	if d.ebpfAdapter != nil {
		t.Fatalf("expected no ebpf adapter when unsupported")
	}
}

func TestBootstrapEBPFAttachFailureCloses(t *testing.T) {
	orig := ebpfNew
	t.Cleanup(func() { ebpfNew = orig })
	fake := &fakeEBPFLifecycle{attachErr: errors.New("attach boom")}
	ebpfNew = func(_ *zap.Logger, _ adapterebpf.Config) (adapterebpf.Lifecycle, error) {
		return fake, nil
	}

	d := &Daemon{cfg: Config{EnableEBPF: true}, log: zap.NewNop()}
	d.bootstrapEBPF()
	if fake.attachCall != 1 {
		t.Fatalf("expected attach to be called once, got %d", fake.attachCall)
	}
	if fake.closeCall != 1 {
		t.Fatalf("expected close to be called once on attach failure, got %d", fake.closeCall)
	}
	if d.ebpfAdapter != nil {
		t.Fatalf("expected no stored ebpf adapter on attach failure")
	}
}

func TestBootstrapEBPFAndStopClosesAdapter(t *testing.T) {
	orig := ebpfNew
	t.Cleanup(func() { ebpfNew = orig })
	fake := &fakeEBPFLifecycle{programs: 2}
	ebpfNew = func(_ *zap.Logger, _ adapterebpf.Config) (adapterebpf.Lifecycle, error) {
		return fake, nil
	}

	d := &Daemon{cfg: Config{EnableEBPF: true}, log: zap.NewNop()}
	d.bootstrapEBPF()
	if d.ebpfAdapter == nil {
		t.Fatalf("expected ebpf adapter to be retained after successful attach")
	}
	if fake.attachCall != 1 {
		t.Fatalf("expected attach to be called once, got %d", fake.attachCall)
	}
	if err := d.stop(); err != nil {
		t.Fatalf("stop daemon: %v", err)
	}
	if fake.closeCall != 1 {
		t.Fatalf("expected close to be called once during stop, got %d", fake.closeCall)
	}
}

func TestBootstrapEBPFPassesAdapterConfig(t *testing.T) {
	orig := ebpfNew
	t.Cleanup(func() { ebpfNew = orig })
	var got adapterebpf.Config
	ebpfNew = func(_ *zap.Logger, cfg adapterebpf.Config) (adapterebpf.Lifecycle, error) {
		got = cfg
		return &fakeEBPFLifecycle{}, nil
	}

	d := &Daemon{
		cfg: Config{
			EnableEBPF:            true,
			EBPFObjectPath:        "/tmp/probe.o",
			EBPFAttachTracepoints: true,
		},
		log: zap.NewNop(),
	}
	d.bootstrapEBPF()
	if got.ObjectPath != "/tmp/probe.o" {
		t.Fatalf("expected object path to be forwarded, got %q", got.ObjectPath)
	}
	if !got.AttachTracepoints {
		t.Fatalf("expected attach tracepoints to be forwarded")
	}
}

func TestHandleSignalSIGUSR1TogglesDegradedMode(t *testing.T) {
	d := &Daemon{
		log:      zap.NewNop(),
		degraded: degraded.NewManager(),
	}
	if got := d.degraded.Current().String(); got != "FULL" {
		t.Fatalf("expected FULL mode initially, got %s", got)
	}
	if stop := d.handleSignal(syscall.SIGUSR1); stop {
		t.Fatalf("expected daemon to continue on SIGUSR1")
	}
	if got := d.degraded.Current().String(); got != "STATELESS" {
		t.Fatalf("expected STATELESS after SIGUSR1, got %s", got)
	}
}

func TestHandleSignalSIGUSR2TogglesFaultMode(t *testing.T) {
	d := &Daemon{
		log:      zap.NewNop(),
		degraded: degraded.NewManager(),
	}
	if stop := d.handleSignal(syscall.SIGUSR2); stop {
		t.Fatalf("expected daemon to continue on SIGUSR2")
	}
	if got := d.degraded.Current().String(); got != "EMERGENCY" {
		t.Fatalf("expected EMERGENCY after SIGUSR2, got %s", got)
	}
	if stop := d.handleSignal(syscall.SIGUSR2); stop {
		t.Fatalf("expected daemon to continue on SIGUSR2")
	}
	if got := d.degraded.Current().String(); got != "FULL" {
		t.Fatalf("expected FULL after second SIGUSR2, got %s", got)
	}
}

type preflightTestStore struct{}

func (s *preflightTestStore) Save(*dpr.Record) error           { return nil }
func (s *preflightTestStore) ByID(string) (*dpr.Record, error) { return nil, nil }
func (s *preflightTestStore) RecentByAgent(string, int) ([]*dpr.Record, error) {
	return nil, nil
}
func (s *preflightTestStore) Recent(int) ([]*dpr.Record, error)                    { return nil, nil }
func (s *preflightTestStore) LastHash(string) (string, error)                      { return "", nil }
func (s *preflightTestStore) KnownAgents() ([]string, error)                       { return nil, nil }
func (s *preflightTestStore) VerifyChain(string) (*dpr.ChainBreak, error)          { return nil, nil }
func (s *preflightTestStore) UpdateSignature(string, string, string, string) error { return nil }
func (s *preflightTestStore) Close() error                                         { return nil }

type preflightWorkloadProvider struct {
	identity *principal.Identity
	err      error
}

func (p *preflightWorkloadProvider) Name() string                   { return "spiffe" }
func (p *preflightWorkloadProvider) Available(context.Context) bool { return true }
func (p *preflightWorkloadProvider) Identity(context.Context) (*principal.Identity, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.identity, nil
}

func strictPreflightIntegrityFixtures(t *testing.T) (manifestPath, baseDir, buildinfoPath string) {
	t.Helper()
	baseDir = t.TempDir()
	artifactPath := filepath.Join(baseDir, "policy.fixture")
	if err := os.WriteFile(artifactPath, []byte("strict preflight integrity fixture"), 0o644); err != nil {
		t.Fatalf("write fixture artifact: %v", err)
	}
	manifest, err := artifactverify.BuildManifestV1(baseDir, []string{artifactPath})
	if err != nil {
		t.Fatalf("build fixture manifest: %v", err)
	}
	rawManifest, err := artifactverify.MarshalManifestJSONPretty(manifest)
	if err != nil {
		t.Fatalf("marshal fixture manifest: %v", err)
	}
	manifestPath = filepath.Join(baseDir, "integrity-manifest.json")
	if err := os.WriteFile(manifestPath, append(rawManifest, '\n'), 0o644); err != nil {
		t.Fatalf("write fixture manifest: %v", err)
	}

	currentBuild, err := reprobuild.Current()
	if err != nil {
		t.Fatalf("load runtime buildinfo: %v", err)
	}
	rawBuild, err := json.MarshalIndent(currentBuild, "", "  ")
	if err != nil {
		t.Fatalf("marshal runtime buildinfo: %v", err)
	}
	buildinfoPath = filepath.Join(baseDir, "buildinfo.expected.json")
	if err := os.WriteFile(buildinfoPath, append(rawBuild, '\n'), 0o644); err != nil {
		t.Fatalf("write buildinfo expected: %v", err)
	}

	return manifestPath, baseDir, buildinfoPath
}

func newStrictPreflightDaemon(t *testing.T) *Daemon {
	t.Helper()
	manifestPath, baseDir, buildinfoPath := strictPreflightIntegrityFixtures(t)
	return &Daemon{
		cfg: Config{
			StrictPreflight:       true,
			IntegrityManifestPath: manifestPath,
			IntegrityBaseDir:      baseDir,
			BuildInfoExpectedPath: buildinfoPath,
		},
		wal:   &dpr.NullWAL{},
		store: &preflightTestStore{},
		log:   zap.NewNop(),
	}
}

func TestEnforceStartupPreflightFailsWithoutWorkloadIdentity(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	err := d.enforceStartupPreflight(&policy.Doc{}, nil)
	if err == nil || err.Error() != "startup preflight failed: identity gate (no workload identity provider configured)" {
		t.Fatalf("expected missing workload identity error, got %v", err)
	}
}

func TestEnforceStartupPreflightFailsWithoutProvenanceStore(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	d.store = nil
	err := d.enforceStartupPreflight(&policy.Doc{}, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err == nil || err.Error() != "startup preflight failed: provenance gate (wal/store must both be initialized)" {
		t.Fatalf("expected provenance gate error, got %v", err)
	}
}

func TestEnforceStartupPreflightFailsCredentialSequestrationWithoutBackend(t *testing.T) {
	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "false")

	d := newStrictPreflightDaemon(t)
	doc := &policy.Doc{
		Tools: map[string]policy.Tool{
			"stripe/refund": {Tags: []string{"credential:required"}},
		},
	}
	err := d.enforceStartupPreflight(doc, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err == nil || err.Error() != "startup preflight failed: credential sequestration gate (policy requires brokered credentials but no broker backend is configured)" {
		t.Fatalf("expected credential sequestration error, got %v", err)
	}
}

func TestHasCredentialSequestrationBackendAllowEnvFallbackFlag(t *testing.T) {
	t.Setenv("FARAMESH_CREDENTIAL_ALLOW_ENV_FALLBACK", "false")

	if !hasCredentialSequestrationBackend(Config{AllowEnvCredentialFallback: true}) {
		t.Fatalf("expected explicit AllowEnvCredentialFallback config to satisfy backend gate")
	}
	if hasCredentialSequestrationBackend(Config{}) {
		t.Fatalf("expected no backend when env fallback is disabled and no external backend is configured")
	}
}

func TestBuildCredentialRouterPrefersExternalDefaultBackend(t *testing.T) {
	router := buildCredentialRouter(Config{AWSSecretsRegion: "us-east-1"})
	resolved := router.ResolveRoute("stripe/refund")
	if resolved.Backend != "aws_secrets_manager" {
		t.Fatalf("expected wildcard route to prefer aws_secrets_manager backend, got %+v", resolved)
	}
	if router.FallbackBackendName() != "env" {
		t.Fatalf("expected env fallback backend, got %q", router.FallbackBackendName())
	}
}

func TestBuildCredentialRouterInvalidDefaultOverrideFallsBackToEnvRoute(t *testing.T) {
	t.Setenv("FARAMESH_CREDENTIAL_DEFAULT_BACKEND", "not-real")
	router := buildCredentialRouter(Config{AWSSecretsRegion: "us-east-1"})
	resolved := router.ResolveRoute("stripe/refund")
	if resolved.Backend != "env" {
		t.Fatalf("expected invalid override to fall back wildcard route to env, got %+v", resolved)
	}
}

func TestEnforceStartupPreflightFailsIDPRequirementWithoutProvider(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	doc := &policy.Doc{
		Rules: []policy.Rule{{Match: policy.Match{When: "principal.verified == true"}}},
	}
	err := d.enforceStartupPreflight(doc, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err == nil || err.Error() != "startup preflight failed: idp gate (policy references principal/delegation claims but no idp provider is configured)" {
		t.Fatalf("expected idp gate error, got %v", err)
	}
}

func TestEnforceStartupPreflightFailsDeferBackendRequirement(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	doc := &policy.Doc{
		Rules:         []policy.Rule{{Effect: "defer"}},
		DeferPriority: &policy.DeferPriorityConfig{Critical: &policy.DeferTier{Channel: "slack"}},
	}
	err := d.enforceStartupPreflight(doc, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err == nil || err.Error() != "startup preflight failed: defer backend gate (missing --slack-webhook)" {
		t.Fatalf("expected defer backend error, got %v", err)
	}
}

func TestEnforceStartupPreflightPassesWithRequiredInputs(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	d.cfg.IDPProvider = "default"
	d.cfg.VaultAddr = "http://vault.local"
	d.cfg.SlackWebhook = "https://hooks.slack.test/abc"

	doc := &policy.Doc{
		Rules: []policy.Rule{{Effect: "defer", Match: policy.Match{When: "principal.verified == true"}}},
		Tools: map[string]policy.Tool{
			"stripe/refund": {Tags: []string{"credential:required"}},
		},
		DeferPriority: &policy.DeferPriorityConfig{Critical: &policy.DeferTier{Channel: "slack"}},
	}

	err := d.enforceStartupPreflight(doc, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err != nil {
		t.Fatalf("expected preflight success, got %v", err)
	}
}

func TestBuildAdapterTLSConfigAutoGeneratesCertificate(t *testing.T) {
	d := &Daemon{
		cfg: Config{TLSAuto: true},
		log: zap.NewNop(),
	}
	cfg, err := d.buildAdapterTLSConfig()
	if err != nil {
		t.Fatalf("build adapter tls config: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected tls config when tls auto is enabled")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one generated certificate, got %d", len(cfg.Certificates))
	}
}

func TestPrincipalFromIDPIdentityMethodMapping(t *testing.T) {
	verified := &principalidp.VerifiedIdentity{Subject: "subject-1"}

	if got := principalFromIDPIdentity(verified, "ldap"); got == nil || got.Method != "ldap_bind" {
		t.Fatalf("expected ldap_bind method, got %+v", got)
	}
	if got := principalFromIDPIdentity(verified, "default"); got == nil || got.Method != "idp_local" {
		t.Fatalf("expected idp_local method, got %+v", got)
	}
}

func TestEnforceStartupPreflightFailsWithoutIntegrityManifest(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	d.cfg.IntegrityManifestPath = ""
	err := d.enforceStartupPreflight(&policy.Doc{}, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err == nil || err.Error() != "startup preflight failed: integrity gate (--integrity-manifest is required in strict mode)" {
		t.Fatalf("expected integrity manifest gate error, got %v", err)
	}
}

func TestEnforceStartupPreflightFailsBuildinfoMismatch(t *testing.T) {
	d := newStrictPreflightDaemon(t)
	badPath := filepath.Join(t.TempDir(), "buildinfo.bad.json")
	if err := os.WriteFile(badPath, []byte(`{"go_version":"go0.invalid"}`), 0o644); err != nil {
		t.Fatalf("write mismatched buildinfo: %v", err)
	}
	d.cfg.BuildInfoExpectedPath = badPath
	err := d.enforceStartupPreflight(&policy.Doc{}, &preflightWorkloadProvider{identity: &principal.Identity{ID: "spiffe://example.org/a", Verified: true, Method: "spiffe"}})
	if err == nil || !strings.Contains(err.Error(), "startup preflight failed: integrity gate (buildinfo mismatch:") {
		t.Fatalf("expected buildinfo mismatch error, got %v", err)
	}
}

func TestNewNormalizesNetworkHardeningMode(t *testing.T) {
	d, err := New(Config{NetworkHardeningMode: "  AUDIT  ", ProxyPort: 8080, Log: zap.NewNop()})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	if d.cfg.NetworkHardeningMode != "audit" {
		t.Fatalf("expected normalized network hardening mode audit, got %q", d.cfg.NetworkHardeningMode)
	}
}

func TestNewRejectsInvalidNetworkHardeningMode(t *testing.T) {
	_, err := New(Config{NetworkHardeningMode: "strict", Log: zap.NewNop()})
	if err == nil {
		t.Fatal("expected invalid network hardening mode error")
	}
	if !strings.Contains(err.Error(), "invalid network hardening mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRejectsHardeningModeWithoutProxyPort(t *testing.T) {
	_, err := New(Config{NetworkHardeningMode: "enforce", ProxyPort: 0, Log: zap.NewNop()})
	if err == nil {
		t.Fatal("expected hardening mode/proxy port validation error")
	}
	if !strings.Contains(err.Error(), "requires --proxy-port") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRejectsInferenceRoutesWithoutProxyForward(t *testing.T) {
	_, err := New(Config{
		ProxyPort:           8080,
		ProxyForward:        false,
		InferenceRoutesFile: "routes.json",
		Log:                 zap.NewNop(),
	})
	if err == nil {
		t.Fatal("expected inference routes/proxy-forward validation error")
	}
	if !strings.Contains(err.Error(), "inference routes require --proxy-forward") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewProxyForwardImpliesConnect(t *testing.T) {
	d, err := New(Config{ProxyPort: 8080, ProxyForward: true, Log: zap.NewNop()})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	if !d.cfg.ProxyConnect {
		t.Fatal("expected ProxyConnect to be enabled when ProxyForward is true")
	}
}

func TestNewDefaultsToMemoryDeferBackend(t *testing.T) {
	d, err := New(Config{Log: zap.NewNop()})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	if d.cfg.DeferBackend != "memory" {
		t.Fatalf("defer backend = %q, want memory", d.cfg.DeferBackend)
	}
}

func TestNewRejectsRedisDeferBackendWithoutRedisURL(t *testing.T) {
	_, err := New(Config{
		DeferBackend: "redis",
		Log:          zap.NewNop(),
	})
	if err == nil {
		t.Fatal("expected redis defer backend validation error")
	}
	if !strings.Contains(err.Error(), "requires --redis-url") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDefaultsToEnforceRuntimeMode(t *testing.T) {
	d, err := New(Config{Log: zap.NewNop()})
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	if d.cfg.RuntimeMode != core.RuntimeModeEnforce {
		t.Fatalf("runtime mode = %q, want enforce", d.cfg.RuntimeMode)
	}
}

func TestNewRejectsInvalidRuntimeMode(t *testing.T) {
	_, err := New(Config{RuntimeMode: core.RuntimeMode("observe"), Log: zap.NewNop()})
	if err == nil {
		t.Fatal("expected invalid runtime mode error")
	}
	if !strings.Contains(err.Error(), "invalid runtime mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadInferenceRoutesFromFileNormalizesFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	raw := `[
	  {
	    "host_pattern": " api.openai.com ",
	    "path_pattern": " /v1/* ",
	    "upstream": " https://upstream.example.com ",
	    "auth_type": " bearer ",
	    "auth_header": " authorization ",
	    "auth_token": " token ",
	    "auth_token_env": " OPENAI_TOKEN ",
	    "auth_broker_tool_id": " proxy/http ",
	    "auth_broker_operation": " invoke ",
	    "auth_broker_scope": " inference:chat ",
	    "model_rewrite": " gpt-4o-mini "
	  }
	]`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write routes file: %v", err)
	}

	routes, err := loadInferenceRoutesFromFile(path)
	if err != nil {
		t.Fatalf("load routes: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected one route, got %d", len(routes))
	}
	r := routes[0]
	if r.Name != "route-1" {
		t.Fatalf("expected generated route name route-1, got %q", r.Name)
	}
	if r.HostPattern != "api.openai.com" || r.PathPattern != "/v1/*" {
		t.Fatalf("expected trimmed host/path patterns, got host=%q path=%q", r.HostPattern, r.PathPattern)
	}
	if r.Upstream != "https://upstream.example.com" {
		t.Fatalf("expected trimmed upstream, got %q", r.Upstream)
	}
	if r.AuthType != "bearer" || r.AuthHeader != "authorization" {
		t.Fatalf("expected trimmed auth fields, got auth_type=%q auth_header=%q", r.AuthType, r.AuthHeader)
	}
	if r.AuthToken != "token" || r.AuthTokenEnv != "OPENAI_TOKEN" {
		t.Fatalf("expected trimmed auth token fields, got token=%q env=%q", r.AuthToken, r.AuthTokenEnv)
	}
	if r.AuthBrokerToolID != "proxy/http" || r.AuthBrokerOperation != "invoke" || r.AuthBrokerScope != "inference:chat" {
		t.Fatalf("expected trimmed broker auth fields, got tool=%q operation=%q scope=%q", r.AuthBrokerToolID, r.AuthBrokerOperation, r.AuthBrokerScope)
	}
	if r.ModelRewrite != "gpt-4o-mini" {
		t.Fatalf("expected trimmed model rewrite, got %q", r.ModelRewrite)
	}
}

func TestLoadInferenceRoutesFromFileRejectsEmptyUpstream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes-invalid.json")
	raw := `[{"name":"bad-route","host_pattern":"*","path_pattern":"*","upstream":"  "}]`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write routes file: %v", err)
	}

	_, err := loadInferenceRoutesFromFile(path)
	if err == nil {
		t.Fatal("expected empty upstream validation error")
	}
	if !strings.Contains(err.Error(), "empty upstream") {
		t.Fatalf("unexpected error: %v", err)
	}
}
