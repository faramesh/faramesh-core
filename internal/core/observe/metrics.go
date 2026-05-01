// Package observe provides governance-specific observability primitives.
// Exposes a Prometheus-compatible /metrics endpoint and an EventEmitter
// for structured event delivery (webhooks, OTel, logging).
//
// This implements Layer 9 (Observability Plane) from the Faramesh architecture spec.
package observe

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics collects governance decision metrics in a lock-free, allocation-free
// hot path. Counters use atomic int64; histograms use fixed-bucket arrays.
type Metrics struct {
	// Decision counters by effect.
	permits atomic.Int64
	denies  atomic.Int64
	defers  atomic.Int64
	shadows atomic.Int64

	// Deny reason counters.
	denyReasons sync.Map // string -> *atomic.Int64

	// Latency histogram (fixed buckets in microseconds).
	// Buckets: ≤100μs, ≤250μs, ≤500μs, ≤1ms, ≤5ms, ≤10ms, ≤50ms, +Inf
	latencyBuckets [8]atomic.Int64
	latencySum     atomic.Int64 // total latency in microseconds
	latencyCount   atomic.Int64

	// Active sessions gauge.
	activeSessions atomic.Int64

	// WAL write counters.
	walWrites atomic.Int64
	walErrors atomic.Int64

	// Context guard counters.
	contextChecks atomic.Int64
	contextFails  atomic.Int64

	// Post-condition scan counters.
	postScanTotal   atomic.Int64
	postScanRedacts atomic.Int64
	postScanDenies  atomic.Int64

	// Incident prevention counters by category and severity.
	incidentsPrevented sync.Map // "category:severity" -> *atomic.Int64
	incidentsTotal     atomic.Int64

	// Shadow mode incident exposure counter.
	shadowExposure atomic.Int64

	// Network hardening outcome counters.
	hardeningOutcomes sync.Map // hardeningMetricKey -> *atomic.Int64

	// Semantic drift counters.
	semanticDriftObserved  atomic.Int64
	semanticDriftTriggered atomic.Int64
	semanticDriftDenied    atomic.Int64
	semanticDriftSumMicro  atomic.Int64
	semanticDriftCount     atomic.Int64
	semanticDriftByProvider sync.Map // provider -> *atomic.Int64
	semanticDriftBuckets   [6]atomic.Int64

	// Async DPR queue (River or in-process worker): enqueue + background persist.
	dprEnqueueOK  atomic.Int64
	dprEnqueueErr atomic.Int64
	dprPersistOK  atomic.Int64
	dprPersistErr atomic.Int64

	hooksMu             sync.RWMutex
	crossSessionTracker CrossSessionTracker
	pieAnalyzer         RuleObserver
	pieAnalyzerConcrete *PIEAnalyzer
}

var semanticDriftBucketBoundaries = [5]float64{0.1, 0.25, 0.5, 0.75, 1.0}

type hardeningMetricKey struct {
	mode       string
	outcome    string
	reasonCode string
}

// Global default metrics instance.
var Default = NewMetrics()

// NewMetrics creates a metrics collector with safe default telemetry hooks.
func NewMetrics() *Metrics {
	m := &Metrics{}
	m.crossSessionTracker = noOpCrossSessionTracker{}
	m.pieAnalyzer = noOpRuleObserver{}
	m.pieAnalyzerConcrete = nil
	return m
}

// SetCrossSessionTracker sets the cross-session telemetry tracker.
func (m *Metrics) SetCrossSessionTracker(t CrossSessionTracker) {
	if t == nil {
		t = noOpCrossSessionTracker{}
	}
	m.hooksMu.Lock()
	m.crossSessionTracker = t
	m.hooksMu.Unlock()
}

// SetPIEAnalyzer sets the PIE rule observer hook.
func (m *Metrics) SetPIEAnalyzer(p RuleObserver) {
	if p == nil {
		p = noOpRuleObserver{}
	}
	m.hooksMu.Lock()
	m.pieAnalyzer = p
	if concrete, ok := p.(*PIEAnalyzer); ok {
		m.pieAnalyzerConcrete = concrete
	} else {
		m.pieAnalyzerConcrete = nil
	}
	m.hooksMu.Unlock()
}

// GetPIEAnalyzer returns the currently configured in-process PIE analyzer, if any.
func GetPIEAnalyzer() *PIEAnalyzer {
	Default.hooksMu.RLock()
	defer Default.hooksMu.RUnlock()
	return Default.pieAnalyzerConcrete
}

// GetCrossSessionFlowTracker returns the concrete FlowTracker when the default metrics
// hook is wired to NewCrossSessionFlowTracker; otherwise nil.
func GetCrossSessionFlowTracker() *FlowTracker {
	Default.hooksMu.RLock()
	t := Default.crossSessionTracker
	Default.hooksMu.RUnlock()
	return FlowTrackerFrom(t)
}

// RecordDecision records a governance decision.
func (m *Metrics) RecordDecision(effect string, reasonCode string, latency time.Duration) {
	switch strings.ToUpper(effect) {
	case "PERMIT":
		m.permits.Add(1)
	case "DENY":
		m.denies.Add(1)
		m.incrDenyReason(reasonCode)
	case "DEFER":
		m.defers.Add(1)
	case "SHADOW":
		m.shadows.Add(1)
	}
	m.recordLatency(latency)
}

func (m *Metrics) incrDenyReason(code string) {
	if code == "" {
		code = "unknown"
	}
	val, _ := m.denyReasons.LoadOrStore(code, &atomic.Int64{})
	val.(*atomic.Int64).Add(1)
}

// latency bucket boundaries in microseconds.
var bucketBoundaries = [7]int64{100, 250, 500, 1000, 5000, 10000, 50000}

func (m *Metrics) recordLatency(d time.Duration) {
	us := d.Microseconds()
	m.latencySum.Add(us)
	m.latencyCount.Add(1)
	for i, boundary := range bucketBoundaries {
		if us <= boundary {
			m.latencyBuckets[i].Add(1)
			return
		}
	}
	m.latencyBuckets[7].Add(1) // +Inf
}

// RecordWALWrite records a WAL write outcome.
func (m *Metrics) RecordWALWrite(success bool) {
	if success {
		m.walWrites.Add(1)
	} else {
		m.walErrors.Add(1)
	}
}

// RecordContextCheck records a context guard check outcome.
func (m *Metrics) RecordContextCheck(passed bool) {
	m.contextChecks.Add(1)
	if !passed {
		m.contextFails.Add(1)
	}
}

// RecordPostScan records a post-condition scan outcome.
func (m *Metrics) RecordPostScan(outcome string) {
	m.postScanTotal.Add(1)
	switch outcome {
	case "REDACTED":
		m.postScanRedacts.Add(1)
	case "DENIED":
		m.postScanDenies.Add(1)
	}
}

// RecordPermitAccess emits cross-session access telemetry synchronously.
// Any tracker error or panic is surfaced to the caller.
func (m *Metrics) RecordPermitAccess(evt AccessEvent) (err error) {
	m.hooksMu.RLock()
	t := m.crossSessionTracker
	m.hooksMu.RUnlock()
	if t == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cross-session tracker panic: %v", r)
		}
	}()
	if err := t.RecordAccess(evt); err != nil {
		return err
	}
	return nil
}

// ObserveRule emits per-rule observations synchronously.
// Any observer error or panic is surfaced to the caller.
func (m *Metrics) ObserveRule(obs RuleObservation) (err error) {
	m.hooksMu.RLock()
	p := m.pieAnalyzer
	m.hooksMu.RUnlock()
	if p == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rule observer panic: %v", r)
		}
	}()
	if err := p.ObserveRule(obs); err != nil {
		return err
	}
	return nil
}

// ObserveSemanticDrift records a semantic drift observation.
func (m *Metrics) ObserveSemanticDrift(obs SemanticDriftObservation) error {
	m.semanticDriftObserved.Add(1)
	if obs.Triggered {
		m.semanticDriftTriggered.Add(1)
	}
	if obs.Denied {
		m.semanticDriftDenied.Add(1)
	}
	provider := strings.TrimSpace(obs.ProviderID)
	if provider == "" {
		provider = "unknown"
	}
	val, _ := m.semanticDriftByProvider.LoadOrStore(provider, &atomic.Int64{})
	val.(*atomic.Int64).Add(1)

	distance := obs.Distance
	if distance < 0 {
		distance = 0
	}
	m.semanticDriftSumMicro.Add(int64(distance * 1_000_000))
	m.semanticDriftCount.Add(1)
	for i, boundary := range semanticDriftBucketBoundaries {
		if distance <= boundary {
			m.semanticDriftBuckets[i].Add(1)
			return nil
		}
	}
	m.semanticDriftBuckets[len(m.semanticDriftBuckets)-1].Add(1)
	return nil
}

// SetActiveSessions sets the active sessions gauge.
func (m *Metrics) SetActiveSessions(n int64) {
	m.activeSessions.Store(n)
}

// RecordIncidentPrevented records a prevented incident by category and severity.
func (m *Metrics) RecordIncidentPrevented(category, severity string) {
	key := category + ":" + severity
	val, _ := m.incidentsPrevented.LoadOrStore(key, &atomic.Int64{})
	val.(*atomic.Int64).Add(1)
	m.incidentsTotal.Add(1)
}

// TotalIncidentsPrevented returns the aggregate count (all category:severity keys).
func (m *Metrics) TotalIncidentsPrevented() int64 {
	return m.incidentsTotal.Load()
}

// RecordShadowExposure records an incident that would have occurred in shadow mode.
func (m *Metrics) RecordShadowExposure() {
	m.shadowExposure.Add(1)
}

// RecordHardeningOutcome records hardening-mode outcomes by mode/outcome/reason.
func (m *Metrics) RecordHardeningOutcome(mode, outcome, reasonCode string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "unknown"
	}
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	if outcome == "" {
		outcome = "unknown"
	}
	reasonCode = strings.TrimSpace(reasonCode)
	if reasonCode == "" {
		reasonCode = "unknown"
	}
	key := hardeningMetricKey{mode: mode, outcome: outcome, reasonCode: reasonCode}
	val, _ := m.hardeningOutcomes.LoadOrStore(key, &atomic.Int64{})
	val.(*atomic.Int64).Add(1)
}

// RecordDPREnqueue records whether an async DPR record was accepted by the queue
// (River insert or in-process channel send). Failure usually triggers synchronous fallback save.
func (m *Metrics) RecordDPREnqueue(success bool) {
	if success {
		m.dprEnqueueOK.Add(1)
	} else {
		m.dprEnqueueErr.Add(1)
	}
}

// RecordDPRAsyncPersist records background persist outcome from the async queue worker.
func (m *Metrics) RecordDPRAsyncPersist(success bool) {
	if success {
		m.dprPersistOK.Add(1)
	} else {
		m.dprPersistErr.Add(1)
	}
}

// IncidentsPreventedPer1K returns incidents prevented per 1000 governance calls.
func (m *Metrics) IncidentsPreventedPer1K() float64 {
	total := m.permits.Load() + m.denies.Load() + m.defers.Load() + m.shadows.Load()
	if total == 0 {
		return 0
	}
	return float64(m.incidentsTotal.Load()) / float64(total) * 1000
}

// Handler returns an http.Handler that serves Prometheus text format metrics.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var b strings.Builder

		// Decision counters.
		writeCounter(&b, "faramesh_decisions_total", "effect", "permit", m.permits.Load())
		writeCounter(&b, "faramesh_decisions_total", "effect", "deny", m.denies.Load())
		writeCounter(&b, "faramesh_decisions_total", "effect", "defer", m.defers.Load())
		writeCounter(&b, "faramesh_decisions_total", "effect", "shadow", m.shadows.Load())

		// Deny reasons.
		m.denyReasons.Range(func(key, value any) bool {
			code := key.(string)
			count := value.(*atomic.Int64).Load()
			writeCounter(&b, "faramesh_deny_reasons_total", "reason_code", code, count)
			return true
		})

		// Latency histogram.
		writeHistogram(&b, "faramesh_decision_latency_seconds", m)

		// WAL counters.
		writeCounter(&b, "faramesh_wal_writes_total", "status", "success", m.walWrites.Load())
		writeCounter(&b, "faramesh_wal_writes_total", "status", "error", m.walErrors.Load())

		// Context guard counters.
		writeCounter(&b, "faramesh_context_checks_total", "result", "pass", m.contextChecks.Load()-m.contextFails.Load())
		writeCounter(&b, "faramesh_context_checks_total", "result", "fail", m.contextFails.Load())

		// Post-condition scan counters.
		writeCounter(&b, "faramesh_postscan_total", "outcome", "pass", m.postScanTotal.Load()-m.postScanRedacts.Load()-m.postScanDenies.Load())
		writeCounter(&b, "faramesh_postscan_total", "outcome", "redacted", m.postScanRedacts.Load())
		writeCounter(&b, "faramesh_postscan_total", "outcome", "denied", m.postScanDenies.Load())

		// Active sessions gauge.
		writeGauge(&b, "faramesh_active_sessions", m.activeSessions.Load())

		// Incident prevention metrics.
		m.incidentsPrevented.Range(func(key, value any) bool {
			writeCounter(&b, "faramesh_incidents_prevented_total", "category_severity", key.(string), value.(*atomic.Int64).Load())
			return true
		})
		writeGauge(&b, "faramesh_incidents_prevented_per_1k_calls", int64(m.IncidentsPreventedPer1K()))
		writeGauge(&b, "faramesh_shadow_mode_incident_exposure", m.shadowExposure.Load())

		// Network hardening counters.
		m.hardeningOutcomes.Range(func(key, value any) bool {
			k := key.(hardeningMetricKey)
			count := value.(*atomic.Int64).Load()
			writeCounter3(&b, "faramesh_network_hardening_total", "mode", k.mode, "outcome", k.outcome, "reason_code", k.reasonCode, count)
			return true
		})

		// Semantic drift counters and distribution.
		writeCounter(&b, "faramesh_semantic_drift_total", "status", "observed", m.semanticDriftObserved.Load())
		writeCounter(&b, "faramesh_semantic_drift_total", "status", "triggered", m.semanticDriftTriggered.Load())
		writeCounter(&b, "faramesh_semantic_drift_total", "status", "denied", m.semanticDriftDenied.Load())
		m.semanticDriftByProvider.Range(func(key, value any) bool {
			writeCounter(&b, "faramesh_semantic_drift_by_provider_total", "provider", key.(string), value.(*atomic.Int64).Load())
			return true
		})
		for i, boundary := range semanticDriftBucketBoundaries {
			writeCounter(&b, "faramesh_semantic_drift_distance_bucket", "le", fmt.Sprintf("%.2f", boundary), m.semanticDriftBuckets[i].Load())
		}
		writeCounter(&b, "faramesh_semantic_drift_distance_bucket", "le", "+Inf", m.semanticDriftBuckets[len(m.semanticDriftBuckets)-1].Load())
		writeGauge(&b, "faramesh_semantic_drift_distance_sum_micro", m.semanticDriftSumMicro.Load())
		writeGauge(&b, "faramesh_semantic_drift_distance_count", m.semanticDriftCount.Load())

		// Async DPR queue (enqueue + worker persist).
		writeCounter(&b, "faramesh_dpr_async_enqueue_total", "status", "success", m.dprEnqueueOK.Load())
		writeCounter(&b, "faramesh_dpr_async_enqueue_total", "status", "error", m.dprEnqueueErr.Load())
		writeCounter(&b, "faramesh_dpr_async_persist_total", "status", "success", m.dprPersistOK.Load())
		writeCounter(&b, "faramesh_dpr_async_persist_total", "status", "error", m.dprPersistErr.Load())

		fmt.Fprint(w, b.String())
	})
}

// Snapshot returns a point-in-time copy of all metric values for display.
type Snapshot struct {
	Permits        int64
	Denies         int64
	Defers         int64
	Shadows        int64
	AvgLatencyUS   int64
	WALWrites      int64
	WALErrors      int64
	ActiveSessions int64
	DenyReasons    map[string]int64
}

// Snapshot returns a consistent metric snapshot.
func (m *Metrics) Snapshot() Snapshot {
	s := Snapshot{
		Permits:        m.permits.Load(),
		Denies:         m.denies.Load(),
		Defers:         m.defers.Load(),
		Shadows:        m.shadows.Load(),
		WALWrites:      m.walWrites.Load(),
		WALErrors:      m.walErrors.Load(),
		ActiveSessions: m.activeSessions.Load(),
		DenyReasons:    make(map[string]int64),
	}
	if count := m.latencyCount.Load(); count > 0 {
		s.AvgLatencyUS = m.latencySum.Load() / count
	}
	m.denyReasons.Range(func(key, value any) bool {
		s.DenyReasons[key.(string)] = value.(*atomic.Int64).Load()
		return true
	})
	return s
}

func writeCounter(b *strings.Builder, name, labelKey, labelVal string, val int64) {
	fmt.Fprintf(b, "%s{%s=%q} %d\n", name, labelKey, labelVal, val)
}

func writeCounter3(b *strings.Builder, name, k1, v1, k2, v2, k3, v3 string, val int64) {
	fmt.Fprintf(b, "%s{%s=%q,%s=%q,%s=%q} %d\n", name, k1, v1, k2, v2, k3, v3, val)
}

func writeGauge(b *strings.Builder, name string, val int64) {
	fmt.Fprintf(b, "%s %d\n", name, val)
}

func writeHistogram(b *strings.Builder, name string, m *Metrics) {
	labels := []string{"0.0001", "0.00025", "0.0005", "0.001", "0.005", "0.01", "0.05", "+Inf"}
	var cumulative int64
	for i, label := range labels {
		cumulative += m.latencyBuckets[i].Load()
		fmt.Fprintf(b, "%s_bucket{le=%q} %d\n", name, label, cumulative)
	}
	fmt.Fprintf(b, "%s_sum %f\n", name, float64(m.latencySum.Load())/1e6)
	fmt.Fprintf(b, "%s_count %d\n", name, m.latencyCount.Load())
}

// TopDenyReasons returns the top N deny reasons sorted by count.
func (m *Metrics) TopDenyReasons(n int) []DenyReasonCount {
	var all []DenyReasonCount
	m.denyReasons.Range(func(key, value any) bool {
		all = append(all, DenyReasonCount{
			Code:  key.(string),
			Count: value.(*atomic.Int64).Load(),
		})
		return true
	})
	sort.Slice(all, func(i, j int) bool { return all[i].Count > all[j].Count })
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// DenyReasonCount pairs a reason code with its count.
type DenyReasonCount struct {
	Code  string
	Count int64
}
