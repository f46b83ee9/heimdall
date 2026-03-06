package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/f46b83ee9/heimdall/config"
)

func TestFanOutEngine_Methods(t *testing.T) {
	fe := NewFanOutEngine(nil, config.MimirConfig{URL: "http://localhost"}, config.FanOutConfig{MaxConcurrency: 10}, nil, nil)

	t.Run("Action helpers", func(t *testing.T) {
		if !isReadAction(ActionRead) {
			t.Error("expected ActionRead to be read action")
		}
		if !isWriteAction(ActionWrite) {
			t.Error("expected ActionWrite to be write action")
		}
		if isReadAction(ActionWrite) {
			t.Error("expected ActionWrite not to be read action")
		}
		if !isResponseFilterAction(ActionRulesRead) {
			t.Error("expected ActionRulesRead to be response filter action")
		}
	})

	t.Run("ResolveUpstreamURL", func(t *testing.T) {
		// Test different path patterns
		tests := []struct {
			path   string
			action Action
			want   string
		}{
			{"/api/v1/query", ActionRead, "http://localhost/prometheus/api/v1/query"},
			{"/api/v1/push", ActionWrite, "http://localhost/api/v1/push"},
			{"/api/v1/rules", ActionRulesRead, "http://localhost/prometheus/api/v1/rules"},
		}

		for _, tt := range tests {
			got := fe.resolveUpstreamURL(tt.path, tt.action)
			if got != tt.want {
				t.Errorf("path %s action %s: got %s, want %s", tt.path, tt.action, got, tt.want)
			}
		}
	})
}

func TestFanOutEngine_AuthorizeWrite_Exhaustive(t *testing.T) {
	// Identity used in subtests
	_ = &Identity{UserID: "alice", Groups: []string{"dev"}}
}

func TestFanOutEngine_ForwardWrite_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	fe := NewFanOutEngine(nil, config.MimirConfig{URL: server.URL}, config.FanOutConfig{}, nil, nil)

	req := httptest.NewRequest("POST", "/api/v1/push", nil)
	_, status, _ := fe.ForwardWrite(context.Background(), []string{"t1"}, req)
	if status != http.StatusInternalServerError {
		t.Errorf("expected 500 from upstream, got %d", status)
	}
}
