package observe

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	lognoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/credentials"

	loggrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	loghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	metricgrpc "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	metrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	tracegrpc "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	tracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

type OTLPConfig struct {
	Enabled        bool
	Endpoint       string
	Protocol       string
	Insecure       bool
	ServiceName    string
	ServiceVersion string
	TracesEnabled  bool
	MetricsEnabled bool
	LogsEnabled    bool
}

type otlpRuntime struct {
	tracerProvider *sdktrace.TracerProvider
	loggerProvider *sdklog.LoggerProvider
	meterProvider  *sdkmetric.MeterProvider

	tracer trace.Tracer
	logger otellog.Logger
	meter  metric.Meter

	decisionCounter metric.Int64Counter
	decisionLatency metric.Float64Histogram
	postscanCounter metric.Int64Counter
	proxyDuration   metric.Float64Histogram
	mcpDuration     metric.Float64Histogram

	enabled bool
}

var (
	otlpMu      sync.RWMutex
	otlpCurrent *otlpRuntime
)

func InitOTLP(ctx context.Context, cfg OTLPConfig) error {
	if !cfg.Enabled {
		ShutdownOTLP(ctx)
		return nil
	}

	protocol := strings.ToLower(strings.TrimSpace(cfg.Protocol))
	if protocol == "" {
		protocol = "grpc"
	}
	if protocol != "grpc" && protocol != "http" {
		return fmt.Errorf("invalid OTLP protocol %q (supported: grpc|http)", cfg.Protocol)
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		if protocol == "http" {
			endpoint = "localhost:4318"
		} else {
			endpoint = "localhost:4317"
		}
	}
	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "faramesh"
	}
	serviceVersion := strings.TrimSpace(cfg.ServiceVersion)
	if serviceVersion == "" {
		serviceVersion = "dev"
	}

	res, _ := resource.New(
		ctx,
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("service.version", serviceVersion),
			attribute.String("service.namespace", "faramesh"),
		),
	)

	r := &otlpRuntime{enabled: true}

	if cfg.TracesEnabled {
		tp, err := newOTLPTracerProvider(ctx, endpoint, protocol, cfg.Insecure, res)
		if err != nil {
			_ = r.Shutdown(ctx)
			return err
		}
		r.tracerProvider = tp
		r.tracer = tp.Tracer("faramesh")
	} else {
		r.tracer = tracenoop.NewTracerProvider().Tracer("faramesh")
	}

	if cfg.LogsEnabled {
		lp, err := newOTLPLoggerProvider(ctx, endpoint, protocol, cfg.Insecure, res)
		if err != nil {
			_ = r.Shutdown(ctx)
			return err
		}
		r.loggerProvider = lp
		r.logger = lp.Logger("faramesh")
	} else {
		r.logger = lognoop.NewLoggerProvider().Logger("faramesh")
	}

	if cfg.MetricsEnabled {
		mp, err := newOTLPMeterProvider(ctx, endpoint, protocol, cfg.Insecure, res)
		if err != nil {
			_ = r.Shutdown(ctx)
			return err
		}
		r.meterProvider = mp
		r.meter = mp.Meter("faramesh")
	} else {
		r.meter = metricnoop.NewMeterProvider().Meter("faramesh")
	}

	r.decisionCounter, _ = r.meter.Int64Counter("faramesh.governance.decisions")
	r.decisionLatency, _ = r.meter.Float64Histogram("faramesh.governance.decision.duration_ms")
	r.postscanCounter, _ = r.meter.Int64Counter("faramesh.governance.postscan")
	r.proxyDuration, _ = r.meter.Float64Histogram("faramesh.proxy.forward.duration_ms")
	r.mcpDuration, _ = r.meter.Float64Histogram("faramesh.mcp.stream.duration_ms")

	setGlobalOTLPProviders(r)

	otlpMu.Lock()
	old := otlpCurrent
	otlpCurrent = r
	otlpMu.Unlock()

	if old != nil {
		_ = old.Shutdown(ctx)
	}
	return nil
}

func ShutdownOTLP(ctx context.Context) {
	setGlobalNoopProviders()
	otlpMu.Lock()
	cur := otlpCurrent
	otlpCurrent = nil
	otlpMu.Unlock()
	if cur != nil {
		_ = cur.Shutdown(ctx)
	}
}

func (r *otlpRuntime) Shutdown(ctx context.Context) error {
	var firstErr error
	if r.tracerProvider != nil {
		if err := r.tracerProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if r.loggerProvider != nil {
		if err := r.loggerProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if r.meterProvider != nil {
		if err := r.meterProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func StartOTLPSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	otlpMu.RLock()
	r := otlpCurrent
	otlpMu.RUnlock()
	if r == nil || !r.enabled {
		return ctx, nil
	}
	ctx, span := r.tracer.Start(ctx, name)
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	return ctx, span
}

func EndOTLPSpan(span trace.Span, err error, attrs ...attribute.KeyValue) {
	if span == nil {
		return
	}
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	if err != nil {
		span.RecordError(err)
	}
	span.End()
}

func RecordDecisionOTLP(ctx context.Context, effect, reasonCode string, latency time.Duration) {
	otlpMu.RLock()
	r := otlpCurrent
	otlpMu.RUnlock()
	if r == nil || !r.enabled {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("effect", strings.ToUpper(strings.TrimSpace(effect))),
		attribute.String("reason_code", strings.TrimSpace(reasonCode)),
	)
	r.decisionCounter.Add(ctx, 1, attrs)
	if r.decisionLatency != nil {
		r.decisionLatency.Record(ctx, float64(latency)/float64(time.Millisecond), attrs)
	}
}

func RecordPostScanOTLP(ctx context.Context, outcome string) {
	otlpMu.RLock()
	r := otlpCurrent
	otlpMu.RUnlock()
	if r == nil || !r.enabled {
		return
	}
	r.postscanCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", strings.ToUpper(strings.TrimSpace(outcome)))))
}

func RecordProxyForwardOTLP(ctx context.Context, method string, statusCode int, duration time.Duration) {
	otlpMu.RLock()
	r := otlpCurrent
	otlpMu.RUnlock()
	if r == nil || !r.enabled {
		return
	}
	r.proxyDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("http.method", strings.ToUpper(strings.TrimSpace(method))),
		attribute.Int("http.status_code", statusCode),
	))
}

func RecordMCPStreamOTLP(ctx context.Context, toolID string, statusCode int, duration time.Duration) {
	otlpMu.RLock()
	r := otlpCurrent
	otlpMu.RUnlock()
	if r == nil || !r.enabled {
		return
	}
	r.mcpDuration.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(
		attribute.String("tool_id", strings.TrimSpace(toolID)),
		attribute.Int("http.status_code", statusCode),
	))
}

func EmitGovernanceOTLPLog(ctx context.Context, event, message string) {
	otlpMu.RLock()
	r := otlpCurrent
	otlpMu.RUnlock()
	if r == nil || !r.enabled {
		return
	}
	now := time.Now()
	rec := otellog.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetSeverityText("INFO")
	rec.SetBody(otellog.StringValue(message))
	rec.AddAttributes(
		otellog.String("event.name", strings.TrimSpace(event)),
		otellog.String("log.schema", GovernanceLogSchema),
		otellog.String("log.schema_version", GovernanceLogSchemaVersion),
	)
	r.logger.Emit(ctx, rec)
}

func setGlobalOTLPProviders(r *otlpRuntime) {
	tp := trace.TracerProvider(tracenoop.NewTracerProvider())
	mp := metric.MeterProvider(metricnoop.NewMeterProvider())
	lp := otellog.LoggerProvider(lognoop.NewLoggerProvider())

	if r != nil {
		if r.tracerProvider != nil {
			tp = r.tracerProvider
		}
		if r.meterProvider != nil {
			mp = r.meterProvider
		}
		if r.loggerProvider != nil {
			lp = r.loggerProvider
		}
	}

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	logglobal.SetLoggerProvider(lp)
}

func setGlobalNoopProviders() {
	setGlobalOTLPProviders(nil)
}

func newOTLPTracerProvider(ctx context.Context, endpoint, protocol string, insecure bool, res *resource.Resource) (*sdktrace.TracerProvider, error) {
	if protocol == "http" {
		opts := []tracehttp.Option{tracehttp.WithEndpoint(endpoint)}
		if insecure {
			opts = append(opts, tracehttp.WithInsecure())
		}
		exporter, err := tracehttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("otlp trace http exporter: %w", err)
		}
		return sdktrace.NewTracerProvider(
			sdktrace.WithResource(res),
			sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
		), nil
	}
	opts := []tracegrpc.Option{tracegrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, tracegrpc.WithInsecure())
	} else {
		opts = append(opts, tracegrpc.WithTLSCredentials(credentials.NewTLS(nil)))
	}
	exporter, err := tracegrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp trace grpc exporter: %w", err)
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
	), nil
}

func newOTLPLoggerProvider(ctx context.Context, endpoint, protocol string, insecure bool, res *resource.Resource) (*sdklog.LoggerProvider, error) {
	if protocol == "http" {
		opts := []loghttp.Option{loghttp.WithEndpoint(endpoint)}
		if insecure {
			opts = append(opts, loghttp.WithInsecure())
		}
		exporter, err := loghttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("otlp log http exporter: %w", err)
		}
		return sdklog.NewLoggerProvider(
			sdklog.WithResource(res),
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		), nil
	}
	opts := []loggrpc.Option{loggrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, loggrpc.WithInsecure())
	}
	exporter, err := loggrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp log grpc exporter: %w", err)
	}
	return sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	), nil
}

func newOTLPMeterProvider(ctx context.Context, endpoint, protocol string, insecure bool, res *resource.Resource) (*sdkmetric.MeterProvider, error) {
	if protocol == "http" {
		opts := []metrichttp.Option{metrichttp.WithEndpoint(endpoint)}
		if insecure {
			opts = append(opts, metrichttp.WithInsecure())
		}
		exporter, err := metrichttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("otlp metric http exporter: %w", err)
		}
		reader := sdkmetric.NewPeriodicReader(exporter)
		return sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(reader),
		), nil
	}
	opts := []metricgrpc.Option{metricgrpc.WithEndpoint(endpoint)}
	if insecure {
		opts = append(opts, metricgrpc.WithInsecure())
	}
	exporter, err := metricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp metric grpc exporter: %w", err)
	}
	reader := sdkmetric.NewPeriodicReader(exporter)
	return sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	), nil
}
