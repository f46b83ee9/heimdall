//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

// TestE2EAuthNAuthZ verifies Heimdall's authentication and authorization:
//
//   - Authentication: missing/invalid JWT tokens → 401
//   - Read authorization: per-tenant allow/deny, filter injection
//   - Write authorization: push allowed/denied based on policy
func TestE2EAuthNAuthZ(t *testing.T) {
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

	// --- Authentication ---

	t.Run("AuthN/missing_token_returns_401", func(t *testing.T) {
		status, _ := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/query?query=up", "", "acme")
		if status != 401 {
			t.Errorf("expected 401, got %d", status)
		}
	})

	t.Run("AuthN/invalid_token_returns_401", func(t *testing.T) {
		status, _ := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/query?query=up", "invalid-token", "acme")
		if status != 401 {
			t.Errorf("expected 401, got %d", status)
		}
	})

	// --- Read Authorization ---

	t.Run("ReadAuthZ/alice_can_read_acme_with_filters", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})
		status, resp := queryHeimdall(t, infra.heimdallHost, token, "acme", "up")
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, resp.RawBody)
		}
		t.Logf("alice query response: %s", resp.RawBody)
	})

	t.Run("ReadAuthZ/bob_cannot_read_acme", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "bob", nil)
		status, resp := queryHeimdall(t, infra.heimdallHost, token, "acme", "up")
		if status != 403 {
			t.Errorf("expected 403, got %d: %s", status, resp.RawBody)
		}
	})

	t.Run("ReadAuthZ/admin_can_read_all_tenants", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})
		status, resp := queryHeimdall(t, infra.heimdallHost, token, "acme", "up")
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, resp.RawBody)
		}
		t.Logf("admin acme query: %s", resp.RawBody)

		status2, resp2 := queryHeimdall(t, infra.heimdallHost, token, "globex", "up")
		if status2 != 200 {
			t.Fatalf("expected 200 for globex, got %d: %s", status2, resp2.RawBody)
		}
		t.Logf("admin globex query: %s", resp2.RawBody)
	})

	t.Run("ReadAuthZ/alice_denied_on_wrong_tenant", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})
		status, resp := queryHeimdall(t, infra.heimdallHost, token, "globex", "up")
		if status != 403 {
			t.Errorf("expected 403 for alice on globex, got %d: %s", status, resp.RawBody)
		}
	})

	t.Run("ReadAuthZ/alice_filters_are_injected", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})
		status, resp := queryHeimdall(t, infra.heimdallHost, token, "acme", "test_metric")
		if status != 200 {
			t.Fatalf("expected 200, got %d: %s", status, resp.RawBody)
		}
		t.Logf("alice filtered query response: %s", resp.RawBody)
	})

	t.Run("ReadAuthZ/missing_tenant_auto_resolves", func(t *testing.T) {
		// With auto-resolve enabled, missing X-Scope-OrgID on read requests
		// resolves to all known tenants (OPA filters to accessible ones).
		// Alice has access to acme → should return 200 with acme results.
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})
		status, _ := httpGetWithAuth(t, infra.heimdallHost+"/api/v1/query?query=up", token, "")
		if status != 200 {
			t.Errorf("expected 200 (auto-resolve), got %d", status)
		}
	})

	// --- Write Authorization ---

	t.Run("WriteAuthZ/admin_push_returns_success", func(t *testing.T) {
		token := infra.jwks.makeJWT(t, "admin", []string{"admins"})

		// Build a valid remote write request
		now := time.Now().UnixMilli()
		writeReq := &prompb.WriteRequest{
			Timeseries: []prompb.TimeSeries{
				{
					Labels: []prompb.Label{
						{Name: "__name__", Value: "e2e_write_test"},
						{Name: "env", Value: "test"},
					},
					Samples: []prompb.Sample{
						{Value: 1, Timestamp: now},
					},
				},
			},
		}

		data, err := proto.Marshal(writeReq)
		if err != nil {
			t.Fatalf("marshaling write request: %v", err)
		}
		compressed := snappy.Encode(nil, data)

		req, err := http.NewRequest(http.MethodPost, infra.heimdallHost+"/api/v1/push", bytes.NewReader(compressed))
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Scope-OrgID", "acme")
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Content-Encoding", "snappy")
		req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// Mimir returns 200 or 204 on success
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("expected 200 or 204, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("WriteAuthZ/bob_push_returns_403", func(t *testing.T) {
		// Bob has a deny policy on acme — write should be forbidden
		token := infra.jwks.makeJWT(t, "bob", nil)

		req, err := http.NewRequest(http.MethodPost, infra.heimdallHost+"/api/v1/push", bytes.NewReader([]byte("dummy")))
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Scope-OrgID", "acme")
		req.Header.Set("Content-Type", "application/x-protobuf")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d: %s", resp.StatusCode, string(body))
		}

		var errResp struct {
			Code string `json:"code"`
		}
		json.Unmarshal(body, &errResp)
		if errResp.Code != "access_denied" {
			t.Errorf("expected code 'access_denied', got %q", errResp.Code)
		}
	})

	t.Run("WriteAuthZ/alice_push_acme_returns_403", func(t *testing.T) {
		// Alice has read access to acme but NOT write — push should be forbidden
		token := infra.jwks.makeJWT(t, "alice", []string{"developers"})

		req, err := http.NewRequest(http.MethodPost, infra.heimdallHost+"/api/v1/push", bytes.NewReader([]byte("dummy")))
		if err != nil {
			t.Fatalf("creating request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Scope-OrgID", "acme")
		req.Header.Set("Content-Type", "application/x-protobuf")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("push request failed: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d: %s", resp.StatusCode, string(body))
		}
	})
}
