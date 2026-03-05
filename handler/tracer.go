package handler

import "go.opentelemetry.io/otel"

// tracer is the package-level OpenTelemetry tracer for all handler instrumentation.
var tracer = otel.Tracer("heimdall/handler")
