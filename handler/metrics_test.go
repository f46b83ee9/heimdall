package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMetrics_Exhaustive(t *testing.T) {
	m, err := NewMetrics()
	if err != nil {
		t.Fatalf("failed to create metrics: %v", err)
	}

	ctx := context.Background()

	t.Run("RecordBundleRebuild", func(t *testing.T) {
		m.RecordBundleRebuild(ctx)
	})

	t.Run("UpdateActiveTenants", func(t *testing.T) {
		m.UpdateActiveTenants(ctx, 5)
	})

	t.Run("Middleware", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(MetricsMiddleware(m))
		r.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})
		r.GET("/not_found_test", func(c *gin.Context) {
			// No handler
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/test", nil)
		r.ServeHTTP(w, req)

		w2 := httptest.NewRecorder()
		req2 := httptest.NewRequest("GET", "/unknown", nil)
		r.ServeHTTP(w2, req2)
	})

	t.Run("Nil guards", func(t *testing.T) {
		var nm *Metrics
		nm.RecordBundleRebuild(ctx)
		nm.UpdateActiveTenants(ctx, 1)
	})
}
