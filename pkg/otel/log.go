package otel

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// OTelHandler is a slog.Handler that adds trace_id and span_id to logs.
// It wraps an existing handler (like slog.JSONHandler or slog.TextHandler).
type OTelHandler struct {
	slog.Handler
}

// NewOTelHandler creates a new OTelHandler wrapping the provided handler.
func NewOTelHandler(h slog.Handler) *OTelHandler {
	return &OTelHandler{Handler: h}
}

// Handle extracts trace context from the ctx and adds it as attributes
// before calling the underlying handler's Handle method.
func (h *OTelHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx == nil {
		return h.Handler.Handle(ctx, r)
	}

	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return h.Handler.Handle(ctx, r)
	}

	// Add trace_id and span_id to the record
	spanCtx := span.SpanContext()
	r.AddAttrs(
		slog.String("trace_id", spanCtx.TraceID().String()),
		slog.String("span_id", spanCtx.SpanID().String()),
	)

	return h.Handler.Handle(ctx, r)
}

// WithAttrs returns a new OTelHandler wrapping the handler with the given attributes.
func (h *OTelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return NewOTelHandler(h.Handler.WithAttrs(attrs))
}

// WithGroup returns a new OTelHandler wrapping the handler with the given group name.
func (h *OTelHandler) WithGroup(name string) slog.Handler {
	return NewOTelHandler(h.Handler.WithGroup(name))
}
