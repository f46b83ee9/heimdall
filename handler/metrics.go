package handler

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metrics holds all Prometheus metrics for Heimdall.
type Metrics struct {
	requestsTotal    metric.Int64Counter
	requestDuration  metric.Float64Histogram
	opaEvalTotal     metric.Int64Counter
	opaEvalDuration  metric.Float64Histogram
	upstreamTotal    metric.Int64Counter
	upstreamDuration metric.Float64Histogram
	bundleRebuilds   metric.Int64Counter
	activeTenants    metric.Int64UpDownCounter

	// Fan-Out Concurrency Saturation
	fanoutActive  metric.Int64UpDownCounter
	fanoutDropped metric.Int64Counter

	// Tenant Cache Performance
	tenantCacheHits   metric.Int64Counter
	tenantCacheMisses metric.Int64Counter
}

// NewMetrics registers all Heimdall metrics with the OTel meter provider.
func NewMetrics() (*Metrics, error) {
	meter := otel.Meter("heimdall")
	m := &Metrics{}
	var err error

	m.requestsTotal, err = meter.Int64Counter("heimdall_requests_total",
		metric.WithDescription("Total number of HTTP requests processed"),
	)
	if err != nil {
		return nil, err
	}

	m.requestDuration, err = meter.Float64Histogram("heimdall_request_duration_seconds",
		metric.WithDescription("HTTP request duration in seconds"),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
	)
	if err != nil {
		return nil, err
	}

	m.opaEvalTotal, err = meter.Int64Counter("heimdall_opa_evaluations_total",
		metric.WithDescription("Total number of OPA policy evaluations"),
	)
	if err != nil {
		return nil, err
	}

	m.opaEvalDuration, err = meter.Float64Histogram("heimdall_opa_evaluation_duration_seconds",
		metric.WithDescription("OPA evaluation duration in seconds"),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1),
	)
	if err != nil {
		return nil, err
	}

	m.upstreamTotal, err = meter.Int64Counter("heimdall_upstream_requests_total",
		metric.WithDescription("Total number of upstream Mimir requests"),
	)
	if err != nil {
		return nil, err
	}

	m.upstreamDuration, err = meter.Float64Histogram("heimdall_upstream_request_duration_seconds",
		metric.WithDescription("Upstream Mimir request duration in seconds"),
		metric.WithExplicitBucketBoundaries(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
	)
	if err != nil {
		return nil, err
	}

	m.bundleRebuilds, err = meter.Int64Counter("heimdall_bundle_rebuilds_total",
		metric.WithDescription("Total number of OPA bundle rebuilds"),
	)
	if err != nil {
		return nil, err
	}

	m.activeTenants, err = meter.Int64UpDownCounter("heimdall_active_tenants",
		metric.WithDescription("Number of active tenants"),
	)
	if err != nil {
		return nil, err
	}

	m.fanoutActive, err = meter.Int64UpDownCounter("heimdall_fanout_active_goroutines",
		metric.WithDescription("Number of active fan-out dispatch goroutines currently executing"),
	)
	if err != nil {
		return nil, err
	}

	m.fanoutDropped, err = meter.Int64Counter("heimdall_fanout_dropped_requests_total",
		metric.WithDescription("Number of upstream requests declined due to maximum concurrency limit reached"),
	)
	if err != nil {
		return nil, err
	}

	m.tenantCacheHits, err = meter.Int64Counter("heimdall_tenant_cache_hits_total",
		metric.WithDescription("Number of cache hits when auto-resolving tenants"),
	)
	if err != nil {
		return nil, err
	}

	m.tenantCacheMisses, err = meter.Int64Counter("heimdall_tenant_cache_misses_total",
		metric.WithDescription("Number of cache misses when auto-resolving tenants"),
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// MetricsMiddleware records request count and duration for every HTTP request.
func MetricsMiddleware(m *Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())
		method := c.Request.Method
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		attrs := metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("path", path),
			attribute.String("status", status),
		)

		m.requestsTotal.Add(c.Request.Context(), 1, attrs)
		m.requestDuration.Record(c.Request.Context(), duration, attrs)
	}
}
