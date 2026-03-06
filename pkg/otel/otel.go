// Package otel provides OpenTelemetry SDK initialization for Heimdall.
package otel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"github.com/f46b83ee9/heimdall/config"
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
	"google.golang.org/grpc/credentials"
)

// Provider wraps the OTel trace and meter providers and provides a clean shutdown.
type Provider struct {
	tp             *sdktrace.TracerProvider
	mp             *sdkmetric.MeterProvider
	MetricsHandler http.Handler
}

// Init initializes the OpenTelemetry trace and meter providers.
// Metrics (Prometheus) are always enabled. Tracing is conditional on the enabled flag.
func Init(ctx context.Context, cfg config.TelemetryConfig) (*Provider, error) {
	// Create a dedicated Prometheus registry for Heimdall metrics
	reg := prometheus.NewRegistry()

	// Create the OTel Prometheus exporter, backed by our registry
	promExp, err := promexporter.New(promexporter.WithRegisterer(reg))
	if err != nil {
		return nil, fmt.Errorf("creating Prometheus exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
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

	if !cfg.Enabled {
		return &Provider{
			mp:             mp,
			MetricsHandler: metricsHandler,
		}, nil
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
	}

	// Configure Authentication
	switch cfg.Auth.Type {
	case config.AuthTypeMTLS:
		tlsCfg, err := newOTelTLSConfig(cfg.Auth, cfg.InsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	default:
		// Auth Headers
		headers := make(map[string]string)
		switch cfg.Auth.Type {
		case config.AuthTypeBasic:
			auth := base64.StdEncoding.EncodeToString([]byte(cfg.Auth.Username + ":" + cfg.Auth.Password))
			headers["Authorization"] = "Basic " + auth
		case config.AuthTypeBearer:
			headers["Authorization"] = "Bearer " + cfg.Auth.Token
		case config.AuthTypeAPIKey:
			header := cfg.Auth.APIKeyHeader
			if header == "" {
				header = "X-API-Key"
			}
			headers[header] = cfg.Auth.APIKey
		}
		if len(headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(headers))
		}

		// TLS Toggle
		if cfg.InsecureSkipVerify {
			tlsCfg := &tls.Config{InsecureSkipVerify: true}
			opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
		} else {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
	}

	exporter, err := otlptracegrpc.New(ctx, opts...)
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

// newOTelTLSConfig creates a tls.Config for the OTel gRPC exporter.
func newOTelTLSConfig(cfg config.AuthConfig, skipVerify bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading OTel client certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify,
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading OTel CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse OTel CA certificate from %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
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
