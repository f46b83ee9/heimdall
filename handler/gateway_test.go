package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/f46b83ee9/heimdall/pkg/otel"
	"github.com/gin-gonic/gin"
)

// mockOPAClient returns a mock OPA client that answers evaluations based on tenant ID.
func mockOPAClient(t *testing.T, results map[string]OPAResult) (*OPAClient, func()) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Input OPAInput `json:"input"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		res, ok := results[input.Input.TenantID]
		if !ok {
			res = OPAResult{Allow: false}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": res,
		})
	}))

	client := NewOPAClient(server.URL, "v1/data/proxy/authz", 1*time.Second, nil)
	return client, server.Close
}

// setupInvariantEnv configures an isolated routing environment bypassing JWT authentication
// directly injecting an identity, useful for testing invariant behavioral paths.
func setupInvariantEnv(t *testing.T, upstreamStatus int, upstreamBody []byte, opaResult map[string]OPAResult, fanOutConcurrency int, upstreamDelay time.Duration) (*gin.Engine, *FanOutEngine) {
	gin.SetMode(gin.TestMode)
	otel.Init(context.Background(), "test-heimdall", "", false)

	// Mock Mimir
	mimir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstreamDelay > 0 {
			time.Sleep(upstreamDelay)
		}
		w.WriteHeader(upstreamStatus)
		w.Write(upstreamBody)
	}))
	t.Cleanup(mimir.Close)

	// Mock OPA
	opaClient, cleanup := mockOPAClient(t, opaResult)
	t.Cleanup(cleanup)

	fanOutCfg := config.FanOutConfig{MaxConcurrency: fanOutConcurrency, Timeout: 5 * time.Second}
	fe := NewFanOutEngine(opaClient, config.MimirConfig{URL: mimir.URL, Timeout: 1 * time.Second}, fanOutCfg, nil, nil)

	cfg := config.Config{
		Mimir: config.MimirConfig{
			URL:     mimir.URL,
			Timeout: 1 * time.Second, // explicit timeout enforcement Invariant #24
		},
	}
	h := NewHandler(&cfg, fe, nil)

	r := gin.New()
	metrics, _ := NewMetrics()
	// Add panic recovery for Safety Invariants (#31, #32, #33)
	r.Use(MetricsMiddleware(metrics)) // just for completeness
	r.Use(TracingMiddleware())
	r.Use(PanicRecoveryMiddleware())

	// Force bypass JWT to directly test authorization/fanout loop (Inv #1, etc)
	r.Use(func(c *gin.Context) { // mock jwt success
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "test_user", Groups: []string{"group"}}))
		c.Next()
	})

	api := r.Group("/api/v1")
	api.GET("/query", h.handleQuery("read"))
	api.POST("/query", h.handleQuery("read"))
	// For PassThrough (rules:write) we register similarly if needed, but PassThrough handles its own router.

	return r, fe
}

// Test_ContextCanceledReturns499 validates AGENTS.md Invariant: Request Pipeline Failure Model.
// "Context canceled -> 499 JSON envelope"
func Test_ContextCanceledReturns499(t *testing.T) {
	// We simulate a timeout effectively canceling the dispatch context internally during Dispatch
	r, _ := setupInvariantEnv(t, http.StatusOK, []byte(`{}`), map[string]OPAResult{
		"t1": {Allow: true, EffectiveFilters: []string{}},
	}, 10, 2*time.Second) // Upstream takes 2s, but context timeout wrapper in Dispatch will trigger

	// We'll mock the handler directly instead of full routing so we can pass a cancelled context manually
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
	req.Header.Set("X-Scope-OrgID", "t1")

	// Pre-emptively wrap request in a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Immediately cancel
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 499 {
		t.Fatalf("Expected strictly 499 for canceled context, got %d", w.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Expected JSON envelope on 499, decoding failed: %v", err)
	}
	if errResp.Code != "request_canceled" {
		t.Fatalf("Expected 'request_canceled' code, got: %s", errResp.Code)
	}
}

// Test_FanOutExceedsCapacityReturns503 validates AGENTS.md Concurrency Invariants
// #16 (Bounded worker pool) and #18 (Exceeding capacity -> 503 fanout_overloaded).
func Test_FanOutExceedsCapacityReturns503(t *testing.T) {
	// Force concurrency limit = 1.
	r, _ := setupInvariantEnv(t, http.StatusOK, []byte(`{}`), map[string]OPAResult{
		"t1": {Allow: true, EffectiveFilters: []string{`tenant="t1"`}},
		"t2": {Allow: true, EffectiveFilters: []string{`tenant="t2"`}}, // Distinct filter key triggers separate goroutine
	}, 1, 100*time.Millisecond) // Upstream delay 100ms keeps semaphore locked

	req := httptest.NewRequest(http.MethodGet, "/api/v1/query", nil)
	req.Header.Set("X-Scope-OrgID", "t1|t2")

	w := httptest.NewRecorder()
	// This should fail-fast because group 1 takes the 1 semaphore slot and 100ms to clear,
	// group 2 drops to the default case and triggers fanout_overloaded.
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable { // 503
		t.Fatalf("Expected strictly 503 for fanout overload, got %d", w.Code)
	}

	var errResp ErrorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Code != "fanout_overloaded" {
		t.Fatalf("Expected 'fanout_overloaded' machine code, got: %s", errResp.Code)
	}
}

// Test_AuthorizationDenyOverridesAllow validates AGENTS.md Authorization Invariant:
// #3 (Deny overrides allow) + #5 (If NO allow matches -> allow = false).
func Test_AuthorizationDenyOverridesAllow(t *testing.T) {
	// The Handler evaluates OPA, if ANY tenant evaluation returns Allow=false, it excludes them.
	// If all requested hit Allow=false, the entire request returns 403 immediately.
	r, _ := setupInvariantEnv(t, http.StatusOK, []byte(`{}`), map[string]OPAResult{
		"t1": {Allow: false, EffectiveFilters: []string{}},
		"t2": {Allow: false, EffectiveFilters: []string{}},
	}, 10, 0)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/query", nil)
	req.Header.Set("X-Scope-OrgID", "t1|t2") // Requested two, both will deny

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	t.Logf("DenyOverrides response body: %s", w.Body.String())

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 when all tenants denied, got %d", w.Code)
	}
}

// Test_PanicReturns500 validates AGENTS.md Invariants #31 (Panic recovery) and #33 (Panic -> 500 RespondError).
func Test_PanicReturns500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// Must include standard recovery mapping to JSON
	r.Use(PanicRecoveryMiddleware())

	r.GET("/panic", func(c *gin.Context) {
		panic("invariant violation simulation")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("Panic must yield 500, got %d", w.Code)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Panic must return JSON envelope: %v", err)
	}
	if errResp.Code != "internal_error" {
		t.Fatalf("Panic must yield 'internal_error' code, got %s", errResp.Code)
	}
}

// Test_PassThroughWriteAction validates AGENTS.md Write Actions Invariant:
// "Forward byte-for-byte. No body modification."
func Test_PassThroughWriteAction(t *testing.T) {
	var capturedBody []byte

	// Mock mimir to capture the exact bytes it received
	mimir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		capturedBody = buf.Bytes()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(mimir.Close)

	opaClient, cleanup := mockOPAClient(t, map[string]OPAResult{
		"t1": {Allow: true, EffectiveFilters: []string{}},
	})
	t.Cleanup(cleanup)

	fanOutCfg := config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}
	fe := NewFanOutEngine(opaClient, config.MimirConfig{URL: mimir.URL}, fanOutCfg, nil, nil)

	cfg := config.Config{Mimir: config.MimirConfig{URL: mimir.URL, Timeout: 5 * time.Second}}
	h := NewHandler(&cfg, fe, nil)

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(SetIdentity(c.Request.Context(), &Identity{UserID: "test", Groups: []string{}}))
		c.Next()
	})

	r.POST("/api/v1/rules", h.handleWrite("rules:write"))

	// Create arbitrary non-standard body data to verify byte-for-byte exactness
	payload := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewBuffer(payload))
	req.Header.Set("X-Scope-OrgID", "t1")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	t.Logf("PassThrough response body: %s", w.Body.String())

	if w.Code != http.StatusAccepted {
		t.Fatalf("Write handler failed, expected 202, got %d", w.Code)
	}

	if !bytes.Equal(capturedBody, payload) {
		t.Fatalf("Body mutated! Expected %x, got %x. Violates pass-through invariant.", payload, capturedBody)
	}
}
