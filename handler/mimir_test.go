package handler

// protects: Invariant[Authorization] - ForwardWrite and AuthorizeWrite must enforce OPA policies.
// protects: Invariant[Availability] - Dynamic URL resolution must handle microservice topology.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/f46b83ee9/heimdall/config"
)

func TestAvailability_Mimir_URLResolution(t *testing.T) {
	fe := NewFanOutEngine(nil, config.MimirConfig{
		URL:             "http://global:8080",
		WriteURL:        "http://write:8080",
		ReadURL:         "http://read:8080",
		RulerURL:        "http://ruler:8080",
		AlertmanagerURL: "http://alert:8080",
	}, config.FanOutConfig{}, nil, nil)

	tests := []struct {
		action Action
		path   string
		want   string
	}{
		{ActionWrite, "/api/v1/push", "http://write:8080/api/v1/push"},
		{ActionRead, "/api/v1/query", "http://read:8080/api/v1/query"},
		{ActionRulesRead, "/api/v1/rules", "http://ruler:8080/api/v1/rules"},
		{ActionRulesWrite, "/api/v1/rules", "http://ruler:8080/api/v1/rules"},
		{ActionAlertsRead, "/alerts", "http://alert:8080/alerts"},
		{ActionRead, "/path", "http://read:8080/path"},   // ReadURL override
		{ActionWrite, "/push", "http://write:8080/push"}, // WriteURL override
	}

	for _, tt := range tests {
		got := fe.resolveUpstreamURL(tt.path, tt.action)
		if got != tt.want {
			t.Errorf("resolveUpstreamURL(%v, %v) = %q, want %q", tt.path, tt.action, got, tt.want)
		}
	}

	t.Run("isResponseFilterAction Helper", func(t *testing.T) {
		if !isResponseFilterAction(ActionRulesRead) {
			t.Error("expected true for RulesRead")
		}
		if isResponseFilterAction(ActionRead) {
			t.Error("expected false for Read")
		}
	})
}

func TestAuthorization_Mimir_AccessControl(t *testing.T) {
	mockOPA := &MockOPA{Result: &OPAResult{Allow: true}}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{}, config.FanOutConfig{}, nil, nil)

	identity := &Identity{UserID: "alice"}

	t.Run("AuthorizeWrite Single tenant allowed", func(t *testing.T) {
		denied, err := fe.AuthorizeWrite(context.Background(), identity, []string{"t1"}, ActionWrite)
		if err != nil || denied != "" {
			t.Errorf("expected success, got %s, %v", denied, err)
		}
	})

	t.Run("AuthorizeWrite One tenant denied", func(t *testing.T) {
		mockOPA.Result = &OPAResult{Allow: false}
		denied, err := fe.AuthorizeWrite(context.Background(), identity, []string{"t1", "t2"}, ActionWrite)
		if err != nil || denied != "t1" {
			t.Errorf("expected t1 denied, got %s, %v", denied, err)
		}
	})

	t.Run("AuthorizeWrite OPA evaluation error", func(t *testing.T) {
		mockOPA.Err = context.Canceled
		_, err := fe.AuthorizeWrite(context.Background(), identity, []string{"t1"}, ActionWrite)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("ForwardWrite Host unreachable", func(t *testing.T) {
		feBad := NewFanOutEngine(nil, config.MimirConfig{URL: "http://mono:8080"}, config.FanOutConfig{}, nil, nil)
		req := httptest.NewRequest("POST", "/api/v1/push", nil)
		_, _, err := feBad.ForwardWrite(context.Background(), []string{"t1"}, req)
		if err == nil {
			t.Error("expected network error")
		}
	})

	t.Run("ForwardWrite Query parameter handling", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "a=b" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		feOK := NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{}, server.Client().Transport, nil)
		req := httptest.NewRequest("POST", "/api/v1/push?a=b", nil)
		_, status, err := feOK.ForwardWrite(context.Background(), []string{"t1"}, req)
		if err != nil || status != http.StatusOK {
			t.Errorf("failed: status %d, err %v", status, err)
		}
	})

	t.Run("ForwardWrite Upstream read error", func(t *testing.T) {
		fe := &FanOutEngine{
			httpClient: &http.Client{Transport: &mockErrorBodyTransport{}},
		}
		req := httptest.NewRequest("POST", "/push", nil)
		_, _, err := fe.ForwardWrite(context.Background(), []string{"t1"}, req)
		if err == nil || !strings.Contains(err.Error(), "reading upstream response") {
			t.Errorf("expected read error, got %v", err)
		}
	})
}
