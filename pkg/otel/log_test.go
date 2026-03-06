package otel

// protects: Invariant[Observability] - Trace IDs must be attached to slog records for correlation.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestObservability_LogCorrelation(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, nil)
	h := NewOTelHandler(base)
	logger := slog.New(h)

	t.Run("Verification without active span", func(t *testing.T) {
		buf.Reset()
		logger.Info("test message")

		var m map[string]interface{}
		json.Unmarshal(buf.Bytes(), &m)
		if _, ok := m["trace_id"]; ok {
			t.Error("expected no trace_id")
		}
	})

	t.Run("Verification with active trace", func(t *testing.T) {
		buf.Reset()
		tp := sdktrace.NewTracerProvider()
		tracer := tp.Tracer("test")
		ctx, span := tracer.Start(context.Background(), "test")
		defer span.End()

		logger.InfoContext(ctx, "test message")

		var m map[string]interface{}
		json.Unmarshal(buf.Bytes(), &m)
		if _, ok := m["trace_id"]; !ok {
			t.Error("expected trace_id")
		}
		if _, ok := m["span_id"]; !ok {
			t.Error("expected span_id")
		}
	})

	t.Run("Handler metadata preservation", func(t *testing.T) {
		h2 := h.WithAttrs([]slog.Attr{slog.String("foo", "bar")})
		h2 = h2.WithGroup("mygroup")
		if h2 == nil {
			t.Fatal("expected non-nil handler")
		}
	})
}
