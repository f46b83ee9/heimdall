package handler

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type mockLister struct {
	ids []string
	err error
}

func (m *mockLister) ListTenantIDs(ctx context.Context) ([]string, error) {
	return m.ids, m.err
}

func TestCachedTenantLister(t *testing.T) {
	metrics, _ := NewMetrics()
	underlying := &mockLister{ids: []string{"t1", "t2"}}
	ttl := 100 * time.Millisecond
	c := NewCachedTenantLister(underlying, ttl, metrics)

	t.Run("Initial fetch (miss)", func(t *testing.T) {
		ids, err := c.ListTenantIDs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 2 {
			t.Errorf("expected 2 ids, got %d", len(ids))
		}
	})

	t.Run("Cached fetch (hit)", func(t *testing.T) {
		// Change underlying, should still return cached
		underlying.ids = []string{"t3"}
		ids, err := c.ListTenantIDs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 2 || ids[0] != "t1" {
			t.Errorf("expected cached ids [t1, t2], got %v", ids)
		}
	})

	t.Run("Underlying error", func(t *testing.T) {
		// Force expiration
		c.mu.Lock()
		c.expiresAt = time.Now().Add(-1 * time.Second)
		c.mu.Unlock()

		underlying.err = fmt.Errorf("db fail")
		_, err := c.ListTenantIDs(context.Background())
		if err == nil {
			t.Error("expected error from underlying lister")
		}
	})

	t.Run("Expiration and refresh", func(t *testing.T) {
		underlying.err = nil
		underlying.ids = []string{"t4"}

		// Wait for TTL
		time.Sleep(150 * time.Millisecond)

		ids, err := c.ListTenantIDs(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ids) != 1 || ids[0] != "t4" {
			t.Errorf("expected refreshed id [t4], got %v", ids)
		}
	})
}
