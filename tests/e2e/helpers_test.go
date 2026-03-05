//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

// queryHeimdall sends a query to Heimdall's query endpoint.
func queryHeimdall(t *testing.T, heimdallURL, token, tenant, query string) (int, *promQueryResponse) {
	t.Helper()

	url := fmt.Sprintf("%s/api/v1/query?query=%s", heimdallURL, query)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Scope-OrgID", tenant)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("executing query: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	var qr promQueryResponse
	json.Unmarshal(body, &qr) // best-effort parse
	qr.RawBody = string(body)

	return resp.StatusCode, &qr
}

// promQueryResponse wraps a Prometheus-style query response.
type promQueryResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string            `json:"resultType"`
		Result     []json.RawMessage `json:"result"`
	} `json:"data"`
	Error   string `json:"error,omitempty"`
	Code    string `json:"code,omitempty"`
	RawBody string `json:"-"`
}

// httpGetWithAuth makes an authenticated GET request.
func httpGetWithAuth(t *testing.T, url, token, tenant string) (int, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Scope-OrgID", tenant)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	return resp.StatusCode, body
}

// queryHeimdallNoTenant sends a query to Heimdall WITHOUT the X-Scope-OrgID header.
func queryHeimdallNoTenant(t *testing.T, heimdallURL, token, query string) (int, []byte) {
	t.Helper()

	url := fmt.Sprintf("%s/api/v1/query?query=%s", heimdallURL, query)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	// Deliberately NOT setting X-Scope-OrgID

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("executing query: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}

	return resp.StatusCode, body
}

// pushToHeimdall builds and sends a remote write request through Heimdall.
func pushToHeimdall(t *testing.T, heimdallURL, token, tenant, metric string, value float64) (int, []byte) {
	t.Helper()

	now := time.Now().UnixMilli()
	writeReq := &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{
			{
				Labels: []prompb.Label{
					{Name: "__name__", Value: metric},
				},
				Samples: []prompb.Sample{
					{Value: value, Timestamp: now},
				},
			},
		},
	}

	data, err := proto.Marshal(writeReq)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/push", heimdallURL),
		bytes.NewReader(snappy.Encode(nil, data)))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Scope-OrgID", tenant)
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, body
}

// waitForOPABundle polls OPA's data API until the proxy policies are loaded.
func waitForOPABundle(t *testing.T, opaHost string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 1 * time.Second

	for time.Now().Before(deadline) {
		url := fmt.Sprintf("%s/v1/data/proxy/authz", opaHost)
		resp, err := http.Get(url)
		if err != nil {
			t.Logf("waitForOPABundle: request error: %v", err)
			time.Sleep(interval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Logf("waitForOPABundle: status %d", resp.StatusCode)
			time.Sleep(interval)
			continue
		}

		// Check if the result contains actual policy data
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err == nil {
			if r, ok := result["result"]; ok && r != nil {
				t.Logf("waitForOPABundle: bundle loaded ✓ (result keys present)")
				return
			}
		}

		t.Logf("waitForOPABundle: waiting... (response: %s)", string(body))
		time.Sleep(interval)
	}

	t.Fatalf("waitForOPABundle: timed out waiting for OPA to load the bundle")
}
