// Package observe — OpenTelemetry trace integration.
//
// Layer 9: Adds OTel spans to the governance pipeline. Each pipeline
// step gets a span, and trace context propagates across agent invocations.
package observe

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// SpanKind identifies the type of span.
type SpanKind int

const (
	SpanKindInternal SpanKind = iota
	SpanKindServer
	SpanKindClient
)

// SpanStatus represents the outcome of a span.
type SpanStatus int

const (
	SpanStatusUnset SpanStatus = iota
	SpanStatusOK
	SpanStatusError
)

// Span represents an OpenTelemetry-compatible span.
type Span struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentID   string            `json:"parent_span_id,omitempty"`
	Name       string            `json:"name"`
	Kind       SpanKind          `json:"kind"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time,omitempty"`
	Status     SpanStatus        `json:"status"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Events     []SpanEvent       `json:"events,omitempty"`
}

// SpanEvent is a timestamped annotation on a span.
type SpanEvent struct {
	Name       string            `json:"name"`
	Timestamp  time.Time         `json:"timestamp"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Tracer creates and manages spans for governance operations.
type Tracer struct {
	mu          sync.Mutex
	serviceName string
	exporter    SpanExporter
	spans       []*Span
	enabled     bool
}

// SpanExporter sends completed spans to a backend.
type SpanExporter interface {
	ExportSpans(ctx context.Context, spans []*Span) error
	Shutdown(ctx context.Context) error
}

// TracerConfig configures the tracer.
type TracerConfig struct {
	ServiceName string
	Exporter    SpanExporter
	Enabled     bool
}

// NewTracer creates a governance tracer.
func NewTracer(cfg TracerConfig) *Tracer {
	return &Tracer{
		serviceName: cfg.ServiceName,
		exporter:    cfg.Exporter,
		enabled:     cfg.Enabled,
	}
}

// traceKey is the context key for trace propagation.
type traceKey struct{}

// TraceContext carries trace information through the pipeline.
type TraceContext struct {
	TraceID string
	SpanID  string
	AgentID string
}

// WithTrace attaches trace context to a Go context.
func WithTrace(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, traceKey{}, tc)
}

// TraceFrom extracts trace context from a Go context.
func TraceFrom(ctx context.Context) (TraceContext, bool) {
	tc, ok := ctx.Value(traceKey{}).(TraceContext)
	return tc, ok
}

// StartSpan begins a new span. Returns the span and a context with the span attached.
func (t *Tracer) StartSpan(ctx context.Context, name string, kind SpanKind) (*Span, context.Context) {
	if !t.enabled {
		return &Span{Name: name}, ctx
	}

	span := &Span{
		TraceID:    generateID(),
		SpanID:     generateID(),
		Name:       name,
		Kind:       kind,
		StartTime:  time.Now(),
		Attributes: make(map[string]string),
	}

	// Inherit trace context from parent.
	if tc, ok := TraceFrom(ctx); ok {
		span.TraceID = tc.TraceID
		span.ParentID = tc.SpanID
	}

	// Attach this span's context.
	newCtx := WithTrace(ctx, TraceContext{
		TraceID: span.TraceID,
		SpanID:  span.SpanID,
	})

	return span, newCtx
}

// EndSpan completes a span and queues it for export.
func (t *Tracer) EndSpan(span *Span, status SpanStatus) {
	if !t.enabled || span == nil {
		return
	}
	span.EndTime = time.Now()
	span.Status = status

	t.mu.Lock()
	t.spans = append(t.spans, span)
	t.mu.Unlock()
}

// AddEvent adds a timestamped event to a span.
func AddEvent(span *Span, name string, attrs map[string]string) {
	if span == nil {
		return
	}
	span.Events = append(span.Events, SpanEvent{
		Name:       name,
		Timestamp:  time.Now(),
		Attributes: attrs,
	})
}

// SetAttribute sets a key-value attribute on a span.
func SetAttribute(span *Span, key, value string) {
	if span == nil || span.Attributes == nil {
		return
	}
	span.Attributes[key] = value
}

// Flush exports accumulated spans.
func (t *Tracer) Flush(ctx context.Context) error {
	if !t.enabled || t.exporter == nil {
		return nil
	}

	t.mu.Lock()
	spans := t.spans
	t.spans = nil
	t.mu.Unlock()

	if len(spans) == 0 {
		return nil
	}
	return t.exporter.ExportSpans(ctx, spans)
}

// Shutdown flushes and closes the tracer.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if err := t.Flush(ctx); err != nil {
		return err
	}
	if t.exporter != nil {
		return t.exporter.Shutdown(ctx)
	}
	return nil
}

// StdoutExporter exports spans to stdout (for development).
type StdoutExporter struct{}

func (e *StdoutExporter) ExportSpans(_ context.Context, _ []*Span) error {
	// In production, would serialize spans to stdout in OTLP JSON format.
	return nil
}

func (e *StdoutExporter) Shutdown(_ context.Context) error { return nil }

// generateID produces a unique span/trace ID.
// In production, uses crypto/rand for 16-byte hex IDs.
func generateID() string {
	// Use time-based for now; production uses crypto/rand.
	return fmt.Sprintf("%016x", time.Now().UnixNano())
}

// ── Pipeline Span Helpers ──

// StartGovernSpan starts a span for a govern() call.
func (t *Tracer) StartGovernSpan(ctx context.Context, agentID, toolID string) (*Span, context.Context) {
	span, ctx := t.StartSpan(ctx, "faramesh.govern", SpanKindServer)
	SetAttribute(span, "faramesh.agent_id", agentID)
	SetAttribute(span, "faramesh.tool_id", toolID)
	SetAttribute(span, "service.name", t.serviceName)
	return span, ctx
}

// StartPolicyEvalSpan starts a span for policy evaluation.
func (t *Tracer) StartPolicyEvalSpan(ctx context.Context, ruleCount int) (*Span, context.Context) {
	span, ctx := t.StartSpan(ctx, "faramesh.policy_eval", SpanKindInternal)
	SetAttribute(span, "faramesh.rule_count", fmt.Sprintf("%d", ruleCount))
	return span, ctx
}

// StartDPRWriteSpan starts a span for DPR record persistence.
func (t *Tracer) StartDPRWriteSpan(ctx context.Context, recordID string) (*Span, context.Context) {
	span, ctx := t.StartSpan(ctx, "faramesh.dpr_write", SpanKindClient)
	SetAttribute(span, "faramesh.dpr_record_id", recordID)
	return span, ctx
}

// StartDeferSpan starts a span for an ongoing DEFER workflow.
func (t *Tracer) StartDeferSpan(ctx context.Context, token string) (*Span, context.Context) {
	span, ctx := t.StartSpan(ctx, "faramesh.defer", SpanKindInternal)
	SetAttribute(span, "faramesh.defer_token", token)
	return span, ctx
}
