package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestHealthHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup DB for readyz
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	h := &Handler{db: db}

	t.Run("Healthz", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.handleHealthz()(c)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Readyz Healthy", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.handleReadyz()(c)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Readyz Unhealthy (Closed DB)", func(t *testing.T) {
		// Create a handler with a closed DB to trigger ping error
		sqlDB, _ := db.DB()
		sqlDB.Close()

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h.handleReadyz()(c)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", w.Code)
		}
	})

	t.Run("Readyz No DB", func(t *testing.T) {
		h2 := &Handler{db: nil}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		h2.handleReadyz()(c)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 (bypass), got %d", w.Code)
		}
	})
}
