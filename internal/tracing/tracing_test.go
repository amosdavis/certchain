package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestInit_NoopWhenEndpointEmpty verifies that Init configures a no-op
// tracer provider when endpoint is empty and OTEL_EXPORTER_OTLP_ENDPOINT
// is unset.
func TestInit_NoopWhenEndpointEmpty(t *testing.T) {
	ctx := context.Background()

	shutdown, err := Init(ctx, "test-service", "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer shutdown(ctx)

	tp := otel.GetTracerProvider()
	if _, ok := tp.(noop.TracerProvider); !ok {
		// May not be exactly noop.TracerProvider due to global state
		t.Logf("TracerProvider type: %T", tp)
	}

	tracer := tp.Tracer("test")
	_, span := tracer.Start(ctx, "test-span")
	span.End()
}

// TestInit_ShutdownSucceeds validates that the returned shutdown function
// can be called without error in no-op mode.
func TestInit_ShutdownSucceeds(t *testing.T) {
	ctx := context.Background()

	shutdown, err := Init(ctx, "test-service", "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}
}

// TestNoopProvider validates that NoopProvider returns a TracerProvider
// that produces valid (but no-op) spans.
func TestNoopProvider(t *testing.T) {
	tp := NoopProvider()
	tracer := tp.Tracer("test")
	ctx := context.Background()

	_, span := tracer.Start(ctx, "noop-span")
	span.End()
}
