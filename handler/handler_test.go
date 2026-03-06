package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/gin-gonic/gin"
)

// local mock to avoid confusion with gateway_test.go function
type testMockOPA struct {
	allow bool
	err   error
}

func (m *testMockOPA) Evaluate(ctx context.Context, input OPAInput) (*OPAResult, error) {
	return &OPAResult{Allow: m.allow}, m.err
}

func TestNewHandler(t *testing.T) {
	fe := &FanOutEngine{}
	h := NewHandler(&config.Config{}, fe, nil)
	if h.fanOut != fe {
		t.Error("NewHandler failed to set fanOut")
	}
}

func TestAuthorization_Gateway_Dispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	mockOPA := &testMockOPA{allow: true}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 10 * time.Second}, nil, nil)
	h := NewHandler(&config.Config{}, fe, nil)

	t.Run("Successful dispatch with identity", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("X-Scope-OrgID", "tenant1")

		identity := &Identity{UserID: "alice", Groups: []string{"admin"}}
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), identity))

		body, status, groups, handled := h.authorizeAndDispatch(c, ActionRead, false)
		if handled {
			t.Error("expected handled to be false for successful dispatch")
		}
		if status != http.StatusOK {
			t.Errorf("expected 200, got %d", status)
		}
		if string(body) != `{"status":"success"}` {
			t.Errorf("got body %q", string(body))
		}
		if len(groups) != 1 || groups[0].TenantIDs[0] != "tenant1" {
			t.Error("expected 1 filter group for tenant1")
		}
	})

	t.Run("Access denied by OPA", func(t *testing.T) {
		mockOPA.allow = false
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("X-Scope-OrgID", "tenant1")
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice"}))

		_, _, _, handled := h.authorizeAndDispatch(c, ActionRead, false)
		if !handled {
			t.Error("expected handled to be true for denied request")
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})

	t.Run("OPA evaluation failure returns 500", func(t *testing.T) {
		mockOPA.err = errors.New("OPA down")
		defer func() { mockOPA.err = nil }()

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Request.Header.Set("X-Scope-OrgID", "t1")
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice"}))

		_, status, _, handled := h.authorizeAndDispatch(c, ActionRead, false)
		if !handled {
			t.Error("expected handled to be true for OPA error")
		}
		if status != http.StatusInternalServerError {
			t.Errorf("expected 500, got %d", status)
		}
	})
}

func TestAuthorization_Gateway_WriteActions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockOPA := &testMockOPA{allow: false}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 10 * time.Second}, nil, nil)
	h := NewHandler(&config.Config{}, fe, nil)

	t.Run("Write middleware denies access", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/api/v1/push", strings.NewReader("metrics"))
		c.Request.Header.Set("X-Scope-OrgID", "t1")
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice"}))

		h.handleWrite(ActionWrite)(c)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})
}

func TestRewriting_Gateway_ResponseFiltering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"groups":[]}}`))
	}))
	defer server.Close()

	mockOPA := &testMockOPA{allow: true}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 10 * time.Second}, nil, nil)
	h := NewHandler(&config.Config{}, fe, nil)

	t.Run("Rules filtering success", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/api/v1/rules", nil)
		c.Request.Header.Set("X-Scope-OrgID", "t1")
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice"}))

		h.handleResponseFilter(ActionRulesRead)(c)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Alerts filtering success", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/api/v1/alerts", nil)
		c.Request.Header.Set("X-Scope-OrgID", "t1")
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice"}))

		h.handleResponseFilter(ActionAlertsRead)(c)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Upstream error during filtering", func(t *testing.T) {
		h.fanOut = NewFanOutEngine(mockOPA, config.MimirConfig{URL: "http://invalid"}, config.FanOutConfig{MaxConcurrency: 10}, nil, nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/api/v1/rules", nil)
		c.Request.Header.Set("X-Scope-OrgID", "t1")
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice"}))

		h.handleResponseFilter(ActionRulesRead)(c)
		if w.Code != http.StatusBadGateway {
			t.Errorf("expected 502, got %d", w.Code)
		}
	})
}

func TestAvailability_Gateway_PanicRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(PanicRecoveryMiddleware())
	r.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/panic", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestAvailability_Gateway_HealthAndStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fe := NewFanOutEngine(nil, config.MimirConfig{}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 10 * time.Second}, nil, nil)
	h := NewHandler(&config.Config{}, fe, nil)

	t.Run("Buildinfo success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"version":"1.0"}`))
		}))
		defer server.Close()
		h.fanOut = NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 10 * time.Second}, nil, nil)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/api/v1/status/buildinfo", nil)
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "admin"}))

		h.handleStatusBuildinfo()(c)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Buildinfo upstream error", func(t *testing.T) {
		h.fanOut = NewFanOutEngine(nil, config.MimirConfig{URL: "http://invalid"}, config.FanOutConfig{MaxConcurrency: 10}, nil, nil)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/api/v1/status/buildinfo", nil)
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "admin"}))

		h.handleStatusBuildinfo()(c)
		if w.Code != http.StatusBadGateway {
			t.Errorf("expected 502, got %d", w.Code)
		}
	})
}
