package tracing

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Init initializes OpenTelemetry tracing for the given service.
// It returns a shutdown function that must be called before application exit
// and an error if initialization fails.
//
// The endpoint parameter specifies the OTLP/HTTP collector URL. When endpoint
// is empty, Init checks the OTEL_EXPORTER_OTLP_ENDPOINT environment variable.
// If both are empty, Init configures a no-op tracer provider so tests and
// local runs do not require a collector (CM-38).
//
// W3C tracecontext propagation is configured as the global propagator.
func Init(ctx context.Context, serviceName, endpoint string) (shutdown func(context.Context) error, err error) {
	// Resolve endpoint: parameter takes precedence, then env var.
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}

	// No-op mode when endpoint is absent (local dev / tests).
	if endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		return func(context.Context) error { return nil }, nil
	}

	// Build resource with service.name.
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	// OTLP/HTTP exporter.
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // Default to insecure; production should configure TLS via env.
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	// Tracer provider with batch span processor.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Set globals.
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	shutdown = func(ctx context.Context) error {
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown tracer provider: %w", err)
		}
		return nil
	}

	return shutdown, nil
}

// NoopProvider returns a no-op TracerProvider for use in tests or local
// contexts where distributed tracing is not needed.
func NoopProvider() trace.TracerProvider {
	return noop.NewTracerProvider()
}
