package handler

import (
	"context"
	"testing"
)

func TestMetrics_Methods(t *testing.T) {
	m, err := NewMetrics()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	t.Run("RecordBundleRebuild", func(t *testing.T) {
		m.RecordBundleRebuild(ctx)
	})

	t.Run("UpdateActiveTenants", func(t *testing.T) {
		m.UpdateActiveTenants(ctx, 42)
	})
}
