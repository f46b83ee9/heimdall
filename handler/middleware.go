package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// propagationHeader implements otel TextMapCarrier for http.Header.
type propagationHeader struct {
	h http.Header
}

func (p propagationHeader) Get(key string) string { return p.h.Get(key) }
func (p propagationHeader) Set(key, value string) { p.h.Set(key, value) }
func (p propagationHeader) Keys() []string {
	keys := make([]string, 0, len(p.h))
	for k := range p.h {
		keys = append(keys, k)
	}
	return keys
}

// TracingMiddleware extracts traceparent, starts a root span, and attaches
// trace_id and span_id to all slog logs.
func TracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		propagator := otel.GetTextMapPropagator()

		// Extract trace context from incoming headers
		ctx := propagator.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))

		// Start root span
		ctx, span := tracer.Start(ctx, c.Request.Method+" "+c.FullPath(),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		spanCtx := span.SpanContext()
		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", c.Request.URL.Path),
			attribute.String("http.user_agent", c.Request.UserAgent()),
		)

		// Attach trace context to slog
		slog.InfoContext(ctx, "request started",
			"trace_id", spanCtx.TraceID().String(),
			"span_id", spanCtx.SpanID().String(),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
		)

		start := time.Now()
		c.Request = c.Request.WithContext(ctx)
		c.Next()

		duration := time.Since(start)
		status := c.Writer.Status()

		slog.InfoContext(ctx, "request completed",
			"trace_id", spanCtx.TraceID().String(),
			"span_id", spanCtx.SpanID().String(),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"duration_ms", duration.Milliseconds(),
		)

		span.SetAttributes(attribute.Int("http.status_code", status))
	}
}
