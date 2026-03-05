package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMergeResults_SingleResult(t *testing.T) {
	input := []upstreamResult{
		{GroupIndex: 0, Body: []byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"env":"prod"},"value":[1,"42"]}]}}`)},
	}
	got, err := mergeResults(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Single result should be returned as-is
	if string(got) != string(input[0].Body) {
		t.Errorf("expected unchanged body")
	}
}

func TestMergeResults_MultipleResults(t *testing.T) {
	input := []upstreamResult{
		{GroupIndex: 0, Body: []byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"tenant":"acme"},"value":[1,"1"]}]}}`)},
		{GroupIndex: 1, Body: []byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"tenant":"globex"},"value":[1,"2"]}]}}`)},
	}
	got, err := mergeResults(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string            `json:"resultType"`
			Result     []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(got, &resp); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if resp.Status != "success" {
		t.Errorf("expected success, got %s", resp.Status)
	}
	if resp.Data.ResultType != "vector" {
		t.Errorf("expected vector, got %s", resp.Data.ResultType)
	}
	if len(resp.Data.Result) != 2 {
		t.Errorf("expected 2 results, got %d", len(resp.Data.Result))
	}
}

func TestMergeResults_NonPromFormat(t *testing.T) {
	input := []upstreamResult{
		{GroupIndex: 0, Body: []byte(`not json`)},
		{GroupIndex: 1, Body: []byte(`also not json`)},
	}
	got, err := mergeResults(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to first result
	if string(got) != "not json" {
		t.Errorf("expected first body fallback, got %s", got)
	}
}

func TestOPAClient_Evaluate_MockServer(t *testing.T) {
	// Mock OPA server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/proxy/authz" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)

		input, ok := body["input"].(map[string]interface{})
		if !ok {
			t.Fatal("expected input in request body")
		}

		userID := input["user_id"].(string)

		// Simulate policy evaluation
		allow := userID == "alice"
		resp := map[string]interface{}{
			"result": map[string]interface{}{
				"allow":              allow,
				"effective_filters":  []string{`env="prod"`},
				"accessible_tenants": []string{"acme"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewOPAClient(server.URL, "v1/data/proxy/authz", 5e9, nil)

	// Test allowed user
	t.Run("allowed_user", func(t *testing.T) {
		result, err := client.Evaluate(context.Background(), OPAInput{
			UserID:   "alice",
			Groups:   []string{"devs"},
			TenantID: "acme",
			Resource: "metrics",
			Action:   "read",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allow {
			t.Error("expected alice to be allowed")
		}
		if len(result.EffectiveFilters) != 1 {
			t.Errorf("expected 1 filter, got %d", len(result.EffectiveFilters))
		}
	})

	// Test denied user
	t.Run("denied_user", func(t *testing.T) {
		result, err := client.Evaluate(context.Background(), OPAInput{
			UserID:   "bob",
			Groups:   []string{"viewers"},
			TenantID: "acme",
			Resource: "metrics",
			Action:   "read",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allow {
			t.Error("expected bob to be denied")
		}
	})
}

func TestOPAClient_Evaluate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := NewOPAClient(server.URL, "v1/data/proxy/authz", 5e9, nil)
	_, err := client.Evaluate(context.Background(), OPAInput{UserID: "alice"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestOPAClient_Evaluate_InvalidResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewOPAClient(server.URL, "v1/data/proxy/authz", 5e9, nil)
	_, err := client.Evaluate(context.Background(), OPAInput{UserID: "alice"})
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
}
