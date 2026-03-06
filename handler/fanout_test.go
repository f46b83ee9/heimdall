package handler

// protects: Invariant[Isolation] - Users only see data for authorized tenants.
// protects: Invariant[Rewriting] - Queries are correctly rewritten with tenant matchers.
// protects: Invariant[Concurrency] - Upstream requests are bounded by concurrency limits.
// protects: Invariant[Availability] - Timeouts and upstream errors are handled gracefully.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/prometheus/prometheus/model/labels"
)

// MockOPA is a reusable mock for OPA client
type MockOPA struct {
	Result *OPAResult
	Err    error
}

func (m *MockOPA) Evaluate(ctx context.Context, input OPAInput) (*OPAResult, error) {
	return m.Result, m.Err
}

// --- Isolation & Authorization Invariants ---

func TestIsolation_FanOut_MultiTenantSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up"},"value":[1625000000,"1"]}]}}`))
	}))
	defer server.Close()

	mockOPA := &MockOPA{Result: &OPAResult{Allow: true}}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}, nil, nil)

	t.Run("Dispatch success", func(t *testing.T) {
		groups := []filterGroup{
			{FilterKey: "G1", TenantIDs: []string{"t1"}, Matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "team", "dev")}},
		}
		req := httptest.NewRequest("GET", "/api/v1/query?query=up", nil)
		body, status, err := fe.Dispatch(context.Background(), groups, req, ActionRead)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("expected 200, got %d", status)
		}
		if !strings.Contains(string(body), "success") {
			t.Errorf("invalid body: %s", string(body))
		}
	})

	t.Run("Write action pass-through", func(t *testing.T) {
		groups := []filterGroup{{FilterKey: "A", TenantIDs: []string{"t1"}}}
		req := httptest.NewRequest("POST", "/api/v1/push", strings.NewReader("metrics_data"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		body, status, err := fe.Dispatch(context.Background(), groups, req, ActionWrite)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("expected 200, got %d", status)
		}
		if string(body) == "" {
			t.Error("expected non-empty body")
		}
	})

	t.Run("Empty groups denied", func(t *testing.T) {
		_, status, _ := fe.Dispatch(context.Background(), nil, httptest.NewRequest("GET", "/", nil), ActionRead)
		if status != http.StatusForbidden {
			t.Errorf("expected 403, got %d", status)
		}
	})
}

// --- Rewriting Invariants ---

func TestRewriting_FanOut_RequestManipulation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			if r.Form.Get("query") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	fe := NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}, nil, nil)

	t.Run("POST read action re-encoding", func(t *testing.T) {
		group := filterGroup{FilterKey: "G1", TenantIDs: []string{"t1"}}
		req := httptest.NewRequest("POST", "/api/v1/query", strings.NewReader("query=up"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ParseForm()

		body, status, err := fe.dispatchSingle(context.Background(), group, req, ActionRead)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if status != http.StatusOK {
			t.Errorf("expected 200, got %d (body: %s)", status, string(body))
		}
	})

	t.Run("Match[] parameter rewrite", func(t *testing.T) {
		group := filterGroup{
			Matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "team", "dev")},
		}
		req := httptest.NewRequest("GET", "/api/v1/series?match[]={job=\"node\"}", nil)
		req.ParseForm()
		_, status, err := fe.dispatchSingle(context.Background(), group, req, ActionRead)
		if err != nil {
			t.Fatal(err)
		}
		if status != http.StatusOK {
			t.Errorf("expected 200, got %d", status)
		}
	})

	t.Run("Rewrite Query Error", func(t *testing.T) {
		group := filterGroup{Matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "a", "b")}}
		req := httptest.NewRequest("GET", "/test?query=up{invalid!!", nil)
		req.ParseForm()
		_, _, err := fe.dispatchSingle(context.Background(), group, req, ActionRead)
		if err == nil || !strings.Contains(err.Error(), "rewriting query") {
			t.Errorf("expected rewriting error, got %v", err)
		}
	})
}

// --- Concurrency Invariants ---

func TestConcurrency_FanOut_BoundedRequests(t *testing.T) {
	var mu sync.Mutex
	maxReached := 0
	current := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current++
		if current > maxReached {
			maxReached = current
		}
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		current--
		mu.Unlock()
	}))
	defer server.Close()

	metrics, _ := NewMetrics()
	fe := NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 2, Timeout: 5 * time.Second}, nil, metrics)

	groups := []filterGroup{
		{FilterKey: "1", TenantIDs: []string{"t1"}},
		{FilterKey: "2", TenantIDs: []string{"t2"}},
		{FilterKey: "3", TenantIDs: []string{"t3"}},
	}

	fe.Dispatch(context.Background(), groups, httptest.NewRequest("GET", "/", nil), ActionRead)

	if maxReached > 2 {
		t.Errorf("max concurrency reached %d > 2", maxReached)
	}
}

func TestConcurrency_FanOut_Backpressure(t *testing.T) {
	fe := NewFanOutEngine(nil, config.MimirConfig{}, config.FanOutConfig{MaxConcurrency: 1, Timeout: 10 * time.Second}, nil, nil)

	t.Run("Semaphore saturation returns 503", func(t *testing.T) {
		fe.sem <- struct{}{}
		defer func() { <-fe.sem }()

		req := httptest.NewRequest("GET", "/test", nil)
		_, status, _ := fe.Dispatch(context.Background(), []filterGroup{{}}, req, ActionRead)
		if status != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", status)
		}
	})
}

// --- Availability Invariants ---

func TestAvailability_FanOut_ErrorHandling(t *testing.T) {
	mockOPA := &testMockOPA{allow: true}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}, nil, nil)

	t.Run("Context timeout reached", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		feSlow := NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 10 * time.Millisecond}, nil, nil)
		req := httptest.NewRequest("GET", "/test", nil)
		_, status, _ := feSlow.Dispatch(context.Background(), []filterGroup{{FilterKey: "A"}}, req, ActionRead)
		if status != http.StatusGatewayTimeout {
			t.Errorf("expected 504, got %d", status)
		}
	})

	t.Run("Upstream host unreachable", func(t *testing.T) {
		feBad := NewFanOutEngine(nil, config.MimirConfig{URL: "http://invalid-host-123"}, config.FanOutConfig{MaxConcurrency: 10, Timeout: 5 * time.Second}, nil, nil)
		_, status, _ := feBad.Dispatch(context.Background(), []filterGroup{{}}, httptest.NewRequest("GET", "/test", nil), ActionRead)
		if status != http.StatusBadGateway {
			t.Errorf("expected 502, got %d", status)
		}
	})

	t.Run("Malformed request data", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", strings.NewReader("%"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_, status, _ := fe.Dispatch(context.Background(), []filterGroup{{}}, req, ActionRead)
		if status != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", status)
		}
	})

	t.Run("Upstream non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer server.Close()
		fe := NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{MaxConcurrency: 10}, nil, nil)
		_, status, _ := fe.dispatchSingle(context.Background(), filterGroup{}, httptest.NewRequest("GET", "/", nil), ActionRead)
		if status != http.StatusForbidden {
			t.Errorf("expected 403, got %d", status)
		}
	})
}

// --- Consistency Invariants ---

func TestConsistency_ResponseMerging_Detailed(t *testing.T) {
	t.Run("Matrix results concatenation", func(t *testing.T) {
		r1 := `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"id":"1"},"values":[[1, "1"]]}]}}`
		r2 := `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"id":"2"},"values":[[2, "2"]]}]}}`
		results := []upstreamResult{
			{Body: []byte(r1), Status: http.StatusOK},
			{Body: []byte(r2), Status: http.StatusOK},
		}
		merged, err := mergeResults(results)
		if err != nil {
			t.Fatal(err)
		}
		var resp struct {
			Data struct {
				Result []interface{} `json:"result"`
			} `json:"data"`
		}
		json.Unmarshal(merged, &resp)
		if len(resp.Data.Result) != 2 {
			t.Errorf("expected 2 results, got %d", len(resp.Data.Result))
		}
	})

	t.Run("Fallback on parsing failure", func(t *testing.T) {
		results := []upstreamResult{
			{Body: []byte(`invalid json`), Status: http.StatusOK},
			{Body: []byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`), Status: http.StatusOK},
		}
		out, _ := mergeResults(results)
		if string(out) != "invalid json" {
			t.Errorf("expected pass through of first result on inner error, got %s", string(out))
		}
	})
}
