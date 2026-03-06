package handler

// protects: Invariant[Availability] - Handle OPA request/response errors safely.
// protects: Invariant[Policy] - Ensure metrics are collected for OPA evaluations.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type errorRoundTripper struct{}

func (e *errorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("network error")
}

type bodyErrorReader struct{}

func (b *bodyErrorReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func TestAuthorization_OPA_Evaluation(t *testing.T) {
	metrics, _ := NewMetrics()

	t.Run("Exhaustive response cases", func(t *testing.T) {
		tests := []struct {
			name       string
			respStatus int
			respBody   interface{}
			rawBody    []byte
			rt         http.RoundTripper
			wantErr    string
		}{
			{
				name:       "success",
				respStatus: http.StatusOK,
				respBody: OPAResponse{
					Result: OPAResult{Allow: true, EffectiveFilters: []string{`env="prod"`}},
				},
			},
			{
				name:    "network error",
				rt:      &errorRoundTripper{},
				wantErr: "OPA request failed: Post \"http://localhost/v1/data/proxy/authz\": network error",
			},
			{
				name:       "non-200 status",
				respStatus: http.StatusForbidden,
				rawBody:    []byte("access denied"),
				wantErr:    "OPA returned status 403: access denied",
			},
			{
				name:       "malformed json response",
				respStatus: http.StatusOK,
				rawBody:    []byte(`{invalid json`),
				wantErr:    "parsing OPA response: invalid character 'i' looking for beginning of object key string",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var ts *httptest.Server
				if tt.rt == nil {
					ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.WriteHeader(tt.respStatus)
						if tt.rawBody != nil {
							w.Write(tt.rawBody)
						} else {
							json.NewEncoder(w).Encode(tt.respBody)
						}
					}))
					defer ts.Close()
				}

				baseURL := "http://localhost"
				if ts != nil {
					baseURL = ts.URL
				}

				client := NewOPAClient(baseURL, "v1/data/proxy/authz", 1*time.Second, tt.rt, metrics)
				res, err := client.Evaluate(context.Background(), OPAInput{UserID: "alice"})

				if tt.wantErr != "" {
					if err == nil {
						t.Fatalf("expected error %q, got nil", tt.wantErr)
					}
					if err.Error() != tt.wantErr {
						t.Errorf("got error %q, want %q", err.Error(), tt.wantErr)
					}
					return
				}

				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.respStatus == http.StatusOK && !res.Allow {
					t.Error("expected allow=true")
				}
			})
		}
	})

	t.Run("Invalid request configuration", func(t *testing.T) {
		client := NewOPAClient(" ://invalid", "authz", 1*time.Second, nil, nil)
		_, err := client.Evaluate(context.Background(), OPAInput{})
		if err == nil || !contains(err.Error(), "creating OPA request") {
			t.Errorf("expected error building request, got %v", err)
		}
	})

	t.Run("Body Read Error", func(t *testing.T) {
		client := &opaClient{
			baseURL:    "http://localhost",
			policyPath: "authz",
			httpClient: &http.Client{
				Transport: &mockErrorBodyTransport{},
			},
		}

		_, err := client.Evaluate(context.Background(), OPAInput{})
		if err == nil || !contains(err.Error(), "reading OPA response") {
			t.Errorf("expected read error, got %v", err)
		}
	})
}

type mockErrorBodyTransport struct{}

func (m *mockErrorBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(&bodyErrorReader{}),
	}, nil
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
