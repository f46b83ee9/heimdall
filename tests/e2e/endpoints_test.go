//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestE2EEndpoints verifies Heimdall's endpoint-level behaviors:
//
//   - Health probes (/healthz, /readyz)
//   - POST query method
//   - Multi-tenant federation (full and partial access)
//   - Rules/Alerts endpoint proxying and authorization
//   - Error response format
func TestE2EEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	infra := setupInfra(t)
	seedDatabase(t, infra.store)
	seedTestMetrics(t, infra.mimirHost)

	waitForMimirSeries(t, infra.mimirHost, "acme", "up", 1, 60*time.Second)
	waitForMimirSeries(t, infra.mimirHost, "globex", "up", 1, 60*time.Second)

	infra.startHeimdall(t)
	infra.startOPA(t)
	waitForOPABundle(t, infra.opaHost, 30*time.Second)

	// --- Health probes (no auth required) ---

	t.Run("Health/healthz_returns_200", func(t *testing.T) {
		resp, err := http.Get(infra.heimdallHost + "/healthz")
		if err != nil {
			t.Fatalf("healthz request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["status"] != "ok" {
			t.Errorf("expected status 'ok', got %q", result["status"])
		}
	})

	t.Run("Health/readyz_returns_200", func(t *testing.T) {
		resp, err := http.Get(infra.heimdallHost + "/readyz")
		if err != nil {
			t.Fatalf("readyz request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]string
		json.NewDecoder(resp.Body).Decode(&result)
		if result["status"] != "ready" {
			t.Errorf("expected status 'ready', got %q", result["status"])
		}
	})

	// --- POST query method ---

	t.Run("Query/post_query_works", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})

		// POST form-encoded query
		form := url.Values{}
		form.Set("query", "up")

		req, err := http.NewRequest(http.MethodPost, infra.heimdallHost+"/api/v1/query", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Scope-OrgID", "acme")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST query failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		var qr promQueryResponse
		if err := json.Unmarshal(body, &qr); err != nil {
			t.Fatalf("parsing response: %v", err)
		}
		if qr.Status != "success" {
			t.Errorf("expected status 'success', got %q", qr.Status)
		}
	})

	// --- Multi-tenant federation ---

	t.Run("MultiTenant/admin_native_federation", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})
		status, resp := queryHeimdall(t, infra.heimdallHost, token, "acme|globex", "up")
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, resp.RawBody)
		}
		t.Logf("multi-tenant response: %s", resp.RawBody)
		if len(resp.Data.Result) < 2 {
			t.Errorf("expected at least 2 results from federation, got %d", len(resp.Data.Result))
		}
	})

	t.Run("MultiTenant/alice_partial_access_acme_globex", func(t *testing.T) {
		// Alice has read access to acme but NOT globex.
		// Querying acme|globex should return only acme results (globex denied by OPA).
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})

		status, resp := queryHeimdall(t, infra.heimdallHost, token, "acme|globex", "up")
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", status, resp.RawBody)
		}

		t.Logf("alice acme|globex response: %s", resp.RawBody)

		// Alice should get results from acme only (with env="prod" filter)
		// globex results should be filtered out by OPA denial
		if resp.Status != "success" {
			t.Errorf("expected success status, got %s", resp.Status)
		}

		// Verify we got results (acme is allowed)
		if len(resp.Data.Result) == 0 {
			t.Error("expected at least 1 result from acme, got 0")
		}

		// Verify no globex results leaked through
		for _, r := range resp.Data.Result {
			var series struct {
				Metric map[string]string `json:"metric"`
			}
			if err := json.Unmarshal(r, &series); err == nil {
				for _, v := range series.Metric {
					if strings.Contains(strings.ToLower(v), "globex") {
						t.Errorf("globex data leaked through to alice: %s", string(r))
					}
				}
			}
		}
	})

	// --- Rules/Alerts endpoint proxying ---

	t.Run("Rules/admin_can_query_rules", func(t *testing.T) {
		// Admin queries /api/v1/rules → should get a valid rules response
		// (may be empty if no recording/alerting rules are configured in Mimir,
		// but the endpoint should still proxy and return 200 with valid JSON)
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})

		status, body := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/rules", token, "acme")
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", status, string(body))
		}

		var rulesResp struct {
			Status string `json:"status"`
			Data   struct {
				Groups []json.RawMessage `json:"groups"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &rulesResp); err != nil {
			t.Fatalf("parsing rules response: %v: %s", err, string(body))
		}

		if rulesResp.Status != "success" {
			t.Errorf("expected status 'success', got %q", rulesResp.Status)
		}

		t.Logf("admin rules response: %s", string(body))
	})

	t.Run("Rules/bob_denied_on_rules", func(t *testing.T) {
		// Bob is denied on acme → /api/v1/rules should return 403
		token := infra.jwks.makeJWT(t, "bob", nil)

		status, body := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/rules", token, "acme")
		if status != http.StatusForbidden {
			t.Errorf("expected 403, got %d: %s", status, string(body))
		}
	})

	t.Run("Alerts/admin_can_query_alerts", func(t *testing.T) {
		// Admin queries /api/v1/alerts → should get a valid alerts response
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})

		status, body := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/alerts", token, "acme")
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", status, string(body))
		}

		var alertsResp struct {
			Status string `json:"status"`
			Data   struct {
				Alerts []json.RawMessage `json:"alerts"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &alertsResp); err != nil {
			t.Fatalf("parsing alerts response: %v: %s", err, string(body))
		}

		if alertsResp.Status != "success" {
			t.Errorf("expected status 'success', got %q", alertsResp.Status)
		}

		t.Logf("admin alerts response: %s", string(body))
	})

	t.Run("Alerts/bob_denied_on_alerts", func(t *testing.T) {
		// Bob is denied on acme → /api/v1/alerts should return 403
		token := infra.jwks.makeJWT(t, "bob", nil)

		status, body := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/alerts", token, "acme")
		if status != http.StatusForbidden {
			t.Errorf("expected 403, got %d: %s", status, string(body))
		}
	})

	// --- Error response format ---

	t.Run("ErrorFormat/json_envelope", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "bob", nil)
		status, body := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/query?query=up", token, "acme")
		if status != 403 {
			t.Fatalf("expected 403, got %d", status)
		}

		var errResp struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("error response is not valid JSON: %s", string(body))
		}
		if errResp.Code == "" {
			t.Errorf("error response missing 'code' field: %s", string(body))
		}
		if errResp.Error == "" {
			t.Errorf("error response missing 'error' field: %s", string(body))
		}
	})
}
