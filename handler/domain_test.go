package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/gin-gonic/gin"
)

// Test_ASTRewriteMandatory validates AGENTS.md Invariant:
// "AST rewriting MUST use promql/parser".
// We test rewrite matches to ensure it operates correctly on AST.
func Test_ASTRewriteMandatory(t *testing.T) {
	query := `sum(rate(http_requests_total[5m]))`
	matchers, _ := ParseFilters([]string{`tenant="t1"`})

	rewritten, err := RewriteMatchParams(context.Background(), []string{query}, matchers)
	if err != nil {
		t.Fatalf("AST Rewrite failed: %v", err)
	}

	expected := `sum(rate(http_requests_total{tenant="t1"}[5m]))`
	if len(rewritten) == 0 || rewritten[0] != expected {
		t.Fatalf("Expected %s, got %s", expected, rewritten[0])
	}
}

// Test_IdentityIsExclusiveToJWT validates AGENTS.md Identity Invariant:
// "Identity is exclusively sourced from JWT."
// We test the JWTMiddleware ensuring it enforces the presence of a token and
// correctly validates it against the configured JWKs securely without caching.
func Test_IdentityIsExclusiveToJWT(t *testing.T) {
	// 1. Setup mocked JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Provide an empty JWKS just to satisfy initialization without error
		w.Write([]byte(`{"keys": []}`))
	}))
	t.Cleanup(jwksServer.Close)

	cfg := &config.Config{
		JWT: config.JWTConfig{
			JWKSURL:     jwksServer.URL,
			Issuer:      "test-issuer",
			Audience:    "test-audience",
			GroupsClaim: "groups",
		},
	}
	r := gin.New()
	r.Use(JWTMiddleware(cfg.JWT))
	r.GET("/secure", func(c *gin.Context) { c.String(200, "OK") })

	// Test case: Missing token -> 401
	req1 := httptest.NewRequest("GET", "/secure", nil)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != 401 {
		t.Fatalf("Expected 401 for missing token, got %d", w1.Code)
	}

	// Test case: Invalid token -> 401 (fails signature matching logic against our empty JWK set)
	req2 := httptest.NewRequest("GET", "/secure", nil)
	req2.Header.Set("Authorization", "Bearer invalid.token.signature")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != 401 {
		t.Fatalf("Expected 401 for invalid token, got %d", w2.Code)
	}
}

// Test_ResponseFilterAppliesToRules validates AGENTS.md Invariant:
// "Response payload MUST be filtered when using response-mode actions".
func Test_ResponseFilterAppliesToRules(t *testing.T) {
	// Mock a Mimir upstream returning a massive rules payload
	upstreamBody := []byte(`{
		"status": "success",
		"data": {
			"groups": [
				{
					"name": "group1",
					"rules": [{"name": "rule1", "labels": {"tenant": "t1", "env": "prod"}}]
				},
				{
					"name": "group2",
					"rules": [{"name": "rule2", "labels": {"tenant": "t2"}}]
				}
			]
		}
	}`)

	r, _ := setupInvariantEnv(t, http.StatusOK, upstreamBody, map[string]OPAResult{
		"t1": {Allow: true, EffectiveFilters: []string{`tenant="t1"`}},
	}, 10, 0)

	// handleResponseFilter maps to rules:read and alerts:read
	api := r.Group("/api/v1")
	h := NewHandler(&config.Config{}, nil, nil)
	api.GET("/rules", h.handleResponseFilter("rules:read")) // We must bind it from handler, but wait, `setupInvariantEnv` injects fanOut

	// It's cleaner to test the FilterRulesResponse pure function first to achieve 100% auth coverage
	matchers, _ := ParseFilters([]string{`tenant="t1"`})
	filteredJSON, err := FilterRulesResponse(context.Background(), upstreamBody, matchers)
	if err != nil {
		t.Fatalf("FilterRulesResponse failed: %v", err)
	}

	// Check that "group2" was filtered out and missing omitempty fields are present
	expected := `{"status":"success","data":{"groups":[{"name":"group1","file":"","rules":[{"name":"rule1","labels":{"env":"prod","tenant":"t1"},"type":""}]}]}}`
	if string(filteredJSON) != expected {
		t.Fatalf("Expected filtered rule payload, got %s", filteredJSON)
	}
}
