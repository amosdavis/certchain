// Package tracing provides OpenTelemetry initialization for certchain binaries.
//
// The Init function sets up OTLP/HTTP export with W3C tracecontext propagation
// and returns a shutdown callback. When the endpoint is empty and no OTEL env
// override exists, Init returns a no-op tracer provider so local development
// and tests do not require a collector.
package tracing
