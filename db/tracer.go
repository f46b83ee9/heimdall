package db

import "go.opentelemetry.io/otel"

// tracer is the package-level OpenTelemetry tracer for all db instrumentation.
var tracer = otel.Tracer("heimdall/db")
