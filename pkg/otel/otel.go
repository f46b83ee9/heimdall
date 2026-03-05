// Package otel provides OpenTelemetry SDK initialization for Heimdall.
package otel

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Provider wraps the OTel trace and meter providers and provides a clean shutdown.
type Provider struct {
	tp             *sdktrace.TracerProvider
	mp             *sdkmetric.MeterProvider
	MetricsHandler http.Handler
}

// Init initializes the OpenTelemetry trace and meter providers.
// Metrics (Prometheus) are always enabled. Tracing is conditional on the enabled flag.
func Init(ctx context.Context, serviceName, otlpEndpoint string, enabled bool) (*Provider, error) {
	// Create a dedicated Prometheus registry for Heimdall metrics
	reg := prometheus.NewRegistry()

	// Create the OTel Prometheus exporter, backed by our registry
	promExp, err := promexporter.New(promexporter.WithRegisterer(reg))
	if err != nil {
		return nil, fmt.Errorf("creating Prometheus exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTel resource: %w", err)
	}

	// Initialize meter provider (always active for Prometheus metrics)
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(promExp),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)

	metricsHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	if !enabled {
		return &Provider{
			mp:             mp,
			MetricsHandler: metricsHandler,
		}, nil
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	// Set global providers
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{
		tp:             tp,
		mp:             mp,
		MetricsHandler: metricsHandler,
	}, nil
}

// Shutdown flushes and shuts down the trace and meter providers.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.mp != nil {
		if err := p.mp.Shutdown(ctx); err != nil {
			return fmt.Errorf("meter provider shutdown: %w", err)
		}
	}
	if p.tp == nil {
		return nil
	}
	return p.tp.Shutdown(ctx)
}
