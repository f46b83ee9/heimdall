package handler

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// CachedTenantLister adds an in-memory TTL cache to an underlying TenantLister
// and reports cache hits and misses via the metrics engine.
type CachedTenantLister struct {
	underlying TenantLister
	metrics    *Metrics
	ttl        time.Duration

	mu        sync.RWMutex
	cachedIDs []string
	expiresAt time.Time
}

// NewCachedTenantLister wraps a TenantLister with a TTL cache and metrics tracking.
func NewCachedTenantLister(underlying TenantLister, ttl time.Duration, metrics *Metrics) *CachedTenantLister {
	return &CachedTenantLister{
		underlying: underlying,
		metrics:    metrics,
		ttl:        ttl,
	}
}

// ListTenantIDs returns tenant IDs from the cache if still valid; otherwise
// refreshes from the underlying lister.
func (c *CachedTenantLister) ListTenantIDs(ctx context.Context) ([]string, error) {
	ctx, span := otel.Tracer("heimdall").Start(ctx, "handler.ListTenantIDs")
	defer span.End()

	c.mu.RLock()
	if c.cachedIDs != nil && time.Now().Before(c.expiresAt) {
		ids := c.cachedIDs // Return existing read-lock reference copy
		c.mu.RUnlock()

		span.SetAttributes(attribute.Bool("cache_hit", true))
		if c.metrics != nil {
			c.metrics.tenantCacheHits.Add(ctx, 1)
		}
		return ids, nil
	}
	c.mu.RUnlock()

	span.SetAttributes(attribute.Bool("cache_hit", false))

	// Cache miss: lock for write and fetch
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double check inside lock in case another goroutine refreshed it
	if c.cachedIDs != nil && time.Now().Before(c.expiresAt) {
		if c.metrics != nil {
			c.metrics.tenantCacheHits.Add(ctx, 1)
		}
		return c.cachedIDs, nil
	}

	if c.metrics != nil {
		c.metrics.tenantCacheMisses.Add(ctx, 1)
	}

	ids, err := c.underlying.ListTenantIDs(ctx)
	if err != nil {
		return nil, err
	}

	c.cachedIDs = ids
	c.expiresAt = time.Now().Add(c.ttl)

	return ids, nil
}
