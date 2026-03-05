//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestE2EAutoResolveTenants verifies the auto-resolve behavior when X-Scope-OrgID
// is absent on read requests. Heimdall should automatically resolve to all known
// tenants and let OPA filter to only the accessible ones.
//
// Invariant: accessible_tenants originates only from OPA (#6).
func TestE2EAutoResolveTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// Uses the same infrastructure as other E2E tests.
	// This test is designed to run independently.
	infra := setupInfra(t)
	seedDatabase(t, infra.store)
	seedTestMetrics(t, infra.mimirHost)

	// Wait for Mimir data availability
	waitForMimirSeries(t, infra.mimirHost, "acme", "up", 1, 60*time.Second)
	waitForMimirSeries(t, infra.mimirHost, "globex", "up", 1, 60*time.Second)

	// Start Heimdall + OPA
	infra.startHeimdall(t)
	infra.startOPA(t)
	waitForOPABundle(t, infra.opaHost, 30*time.Second)

	t.Run("AutoResolve/admin_no_header_returns_all_tenants", func(t *testing.T) {
		// Admin has wildcard access to all tenants.
		// Without X-Scope-OrgID, Heimdall should auto-resolve to acme + globex,
		// OPA allows both, and the response merges results from both tenants.
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})

		status, body := queryHeimdallNoTenant(t, infra.heimdallHost, token, "up")
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", status, string(body))
		}

		var resp promQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("parsing response: %v", err)
		}

		t.Logf("admin auto-resolve response: %s", string(body))

		// Should have results from both tenants (at least 2 series: acme/up + globex/up)
		if len(resp.Data.Result) < 2 {
			t.Errorf("expected at least 2 results from auto-resolve, got %d", len(resp.Data.Result))
		}
	})

	t.Run("AutoResolve/alice_no_header_returns_only_allowed_tenants", func(t *testing.T) {
		// Alice has read access to acme only (with env="prod" filter).
		// Without X-Scope-OrgID, Heimdall should auto-resolve to acme + globex,
		// OPA allows acme but denies globex, so only acme results are returned.
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})

		status, body := queryHeimdallNoTenant(t, infra.heimdallHost, token, "up")
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", status, string(body))
		}

		var resp promQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("parsing response: %v", err)
		}

		t.Logf("alice auto-resolve response: %s", string(body))

		// Alice should get results from acme only (env="prod" filter applied)
		if resp.Status != "success" {
			t.Errorf("expected success status, got %s", resp.Status)
		}
	})

	t.Run("AutoResolve/bob_no_header_all_denied_returns_403", func(t *testing.T) {
		// Bob is explicitly denied on acme, and has no allow policy for globex.
		// With auto-resolve, OPA should deny both tenants → 403.
		token := infra.jwks.makeJWT(t, "bob", nil)

		status, body := queryHeimdallNoTenant(t, infra.heimdallHost, token, "up")
		if status != http.StatusForbidden {
			t.Errorf("expected 403, got %d: %s", status, string(body))
		}

		var errResp struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if err := json.Unmarshal(body, &errResp); err != nil {
			t.Fatalf("parsing error response: %v", err)
		}
		if errResp.Code != "access_denied" {
			t.Errorf("expected 'access_denied' code, got: %s", errResp.Code)
		}
	})

	t.Run("AutoResolve/write_without_header_still_returns_400", func(t *testing.T) {
		// Writes ALWAYS require explicit X-Scope-OrgID, even with auto-resolve.
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})

		req, err := http.NewRequest(http.MethodPost, infra.heimdallHost+"/api/v1/push", nil)
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		// No X-Scope-OrgID

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("executing request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 400 for write without header, got %d: %s", resp.StatusCode, string(body))
		}
	})
}
