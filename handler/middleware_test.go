package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMiddleware_Tracing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(TracingMiddleware())
	r.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("got %d, want 200", w.Code)
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()
	identity := &Identity{UserID: "alice"}

	ctx = SetIdentity(ctx, identity)
	got, ok := GetIdentity(ctx)
	if !ok || got.UserID != "alice" {
		t.Errorf("GetIdentity failed")
	}

	// Ensure MustGetIdentity doesn't panic if identity is set
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), identity))
	MustGetIdentity(c)
}
