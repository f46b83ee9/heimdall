package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/gin-gonic/gin"
)

// mockTenantLister implements TenantLister for testing.
type mockTenantLister struct {
	tenantIDs []string
	err       error
}

func (m *mockTenantLister) ListTenantIDs(_ context.Context) ([]string, error) {
	return m.tenantIDs, m.err
}

// Test_AutoResolveTenants_ReadWithoutHeader verifies that when X-Scope-OrgID is
// absent on a read request and a TenantLister is configured, Heimdall auto-resolves
// to all known tenants and lets OPA filter to accessible ones.
// Invariant: accessible_tenants originates only from OPA (#6).
func Test_AutoResolveTenants_ReadWithoutHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Mock OPA: allow tenant-a, deny tenant-b
	opaClient, cleanup := mockOPAClient(t, map[string]OPAResult{
		"tenant-a": {Allow: true, EffectiveFilters: []string{}},
		"tenant-b": {Allow: false},
	})
	defer cleanup()

	// Mock upstream Mimir
	mimir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer mimir.Close()

	fanOutCfg := config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}
	fe := NewFanOutEngine(opaClient, config.MimirConfig{URL: mimir.URL, Timeout: 1 * time.Second}, fanOutCfg, nil, nil)

	cfg := config.Config{}
	h := NewHandler(&cfg, fe, nil)
	h.WithTenantLister(&mockTenantLister{tenantIDs: []string{"tenant-a", "tenant-b"}})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice", Groups: []string{"devs"}}))
		c.Next()
	})
	r.GET("/api/v1/query", h.handleQuery(ActionRead))

	// Request WITHOUT X-Scope-OrgID header
	req := httptest.NewRequest("GET", "/api/v1/query?query=up", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Should succeed (OPA allowed tenant-a, filtered out tenant-b)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// Test_AutoResolveTenants_HeaderTakesPrecedence verifies that when X-Scope-OrgID
// IS present, TenantLister is NOT called (header takes precedence).
func Test_AutoResolveTenants_HeaderTakesPrecedence(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Mock OPA: only allow tenant-x
	opaClient, cleanup := mockOPAClient(t, map[string]OPAResult{
		"tenant-x": {Allow: true, EffectiveFilters: []string{}},
	})
	defer cleanup()

	mimir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer mimir.Close()

	fanOutCfg := config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}
	fe := NewFanOutEngine(opaClient, config.MimirConfig{URL: mimir.URL, Timeout: 1 * time.Second}, fanOutCfg, nil, nil)

	cfg := config.Config{}
	h := NewHandler(&cfg, fe, nil)

	// TenantLister returns different tenants — should NOT be called
	h.WithTenantLister(&mockTenantLister{tenantIDs: []string{"tenant-a", "tenant-b"}})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice", Groups: []string{"devs"}}))
		c.Next()
	})
	r.GET("/api/v1/query", h.handleQuery(ActionRead))

	// Request WITH explicit X-Scope-OrgID
	req := httptest.NewRequest("GET", "/api/v1/query?query=up", nil)
	req.Header.Set("X-Scope-OrgID", "tenant-x")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// Test_AutoResolveTenants_NoListerReturns400 verifies backward compatibility:
// when no TenantLister is configured and no header is present, return 400.
func Test_AutoResolveTenants_NoListerReturns400(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := config.Config{}
	h := NewHandler(&cfg, nil, nil)
	// No WithTenantLister call

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice", Groups: []string{}}))
		c.Next()
	})
	r.GET("/api/v1/query", h.handleQuery(ActionRead))

	req := httptest.NewRequest("GET", "/api/v1/query?query=up", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.Code != "missing_tenant" {
		t.Fatalf("Expected 'missing_tenant' code, got: %s", errResp.Code)
	}
}

// Test_AutoResolveTenants_WriteStillRequiresHeader verifies that write actions
// ALWAYS require X-Scope-OrgID, even if TenantLister is configured.
func Test_AutoResolveTenants_WriteStillRequiresHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := config.Config{}
	h := NewHandler(&cfg, nil, nil)
	h.WithTenantLister(&mockTenantLister{tenantIDs: []string{"tenant-a"}})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice", Groups: []string{}}))
		c.Next()
	})
	r.POST("/api/v1/push", h.handleWrite(ActionWrite))

	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	// No X-Scope-OrgID header
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for write without header, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.Code != "missing_tenant" {
		t.Fatalf("Expected 'missing_tenant' code, got: %s", errResp.Code)
	}
}

// Test_AutoResolveTenants_ListerErrorReturns500 verifies that when TenantLister
// returns an error, the handler returns 500 with appropriate error code.
func Test_AutoResolveTenants_ListerErrorReturns500(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := config.Config{}
	h := NewHandler(&cfg, nil, nil)
	h.WithTenantLister(&mockTenantLister{err: fmt.Errorf("database unavailable")})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice", Groups: []string{}}))
		c.Next()
	})
	r.GET("/api/v1/query", h.handleQuery(ActionRead))

	req := httptest.NewRequest("GET", "/api/v1/query?query=up", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.Code != "tenant_resolution_error" {
		t.Fatalf("Expected 'tenant_resolution_error' code, got: %s", errResp.Code)
	}
}

// Test_AutoResolveTenants_AllDeniedReturns403 verifies that when auto-resolve
// lists tenants but OPA denies all of them, the response is 403.
func Test_AutoResolveTenants_AllDeniedReturns403(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Mock OPA: deny all tenants
	opaClient, cleanup := mockOPAClient(t, map[string]OPAResult{
		"tenant-a": {Allow: false},
		"tenant-b": {Allow: false},
	})
	defer cleanup()

	fanOutCfg := config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}
	fe := NewFanOutEngine(opaClient, config.MimirConfig{URL: "http://unused", Timeout: 1 * time.Second}, fanOutCfg, nil, nil)

	cfg := config.Config{}
	h := NewHandler(&cfg, fe, nil)
	h.WithTenantLister(&mockTenantLister{tenantIDs: []string{"tenant-a", "tenant-b"}})

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "alice", Groups: []string{"devs"}}))
		c.Next()
	})
	r.GET("/api/v1/query", h.handleQuery(ActionRead))

	req := httptest.NewRequest("GET", "/api/v1/query?query=up", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}
	if errResp.Code != "access_denied" {
		t.Fatalf("Expected 'access_denied' code, got: %s", errResp.Code)
	}
}
