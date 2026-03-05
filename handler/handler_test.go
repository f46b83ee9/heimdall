package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetAndGetIdentity(t *testing.T) {
	id := &Identity{UserID: "alice", Groups: []string{"devs", "admins"}}
	ctx := SetIdentity(context.Background(), id)

	got, ok := GetIdentity(ctx)
	if !ok {
		t.Fatal("expected identity in context")
	}
	if got.UserID != "alice" {
		t.Errorf("expected alice, got %s", got.UserID)
	}
	if len(got.Groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(got.Groups))
	}
}

func TestGetIdentity_Missing(t *testing.T) {
	_, ok := GetIdentity(context.Background())
	if ok {
		t.Fatal("expected no identity in empty context")
	}
}

func TestMustGetIdentity_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		MustGetIdentity(c) // should panic
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)
}

func TestMustGetIdentity_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "bob", Groups: []string{"ops"}}))
		id := MustGetIdentity(c)
		c.JSON(http.StatusOK, gin.H{"user": id.UserID})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRespondError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/err", func(c *gin.Context) {
		RespondError(c, http.StatusForbidden, "access_denied", "not allowed")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/err", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Code != "access_denied" {
		t.Errorf("expected 'access_denied', got %q", resp.Code)
	}
	if resp.Error != "not allowed" {
		t.Errorf("expected 'not allowed', got %q", resp.Error)
	}
}

func TestPanicRecoveryMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PanicRecoveryMiddleware())
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}

	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if resp.Code != "internal_error" {
		t.Errorf("expected 'internal_error', got %q", resp.Code)
	}
}

func TestIsReadAction(t *testing.T) {
	if !isReadAction("read") {
		t.Error("expected read to be a read action")
	}
	if isReadAction("write") {
		t.Error("expected write to not be a read action")
	}
}

func TestIsWriteAction(t *testing.T) {
	if !isWriteAction("write") {
		t.Error("expected write to be a write action")
	}
	if !isWriteAction("rules:write") {
		t.Error("expected rules:write to be a write action")
	}
	if isWriteAction("read") {
		t.Error("expected read to not be a write action")
	}
}

func TestIsResponseFilterAction(t *testing.T) {
	if !isResponseFilterAction("rules:read") {
		t.Error("expected rules:read to be a response filter action")
	}
	if !isResponseFilterAction("alerts:read") {
		t.Error("expected alerts:read to be a response filter action")
	}
	if isResponseFilterAction("read") {
		t.Error("expected read to not be a response filter action")
	}
}
