package observe

import (
	"context"
	"testing"

	otellog "go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

func TestInitOTLP_InvalidProtocolDoesNotSwapRuntime(t *testing.T) {
	ctx := context.Background()
	ShutdownOTLP(ctx)
	t.Cleanup(func() { ShutdownOTLP(ctx) })

	sentinel := &otlpRuntime{
		enabled: true,
		tracer:  trace.Tracer(tracenoop.NewTracerProvider().Tracer("test")),
		logger:  otellog.Logger(lognoop.NewLoggerProvider().Logger("test")),
		meter:   metric.Meter(metricnoop.NewMeterProvider().Meter("test")),
	}
	otlpMu.Lock()
	otlpCurrent = sentinel
	otlpMu.Unlock()

	err := InitOTLP(ctx, OTLPConfig{Enabled: true, Protocol: "invalid"})
	if err == nil {
		t.Fatal("expected invalid protocol error")
	}

	otlpMu.RLock()
	cur := otlpCurrent
	otlpMu.RUnlock()
	if cur != sentinel {
		t.Fatal("runtime should remain unchanged on init failure")
	}
}

func TestShutdownOTLP_ClearsCurrentRuntime(t *testing.T) {
	ctx := context.Background()
	ShutdownOTLP(ctx)

	otlpMu.Lock()
	otlpCurrent = &otlpRuntime{enabled: true}
	otlpMu.Unlock()

	ShutdownOTLP(ctx)

	otlpMu.RLock()
	cur := otlpCurrent
	otlpMu.RUnlock()
	if cur != nil {
		t.Fatal("expected runtime to be cleared")
	}
}
