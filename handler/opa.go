package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
)

// OPAInput is the input document sent to OPA for evaluation.
type OPAInput struct {
	UserID   string   `json:"user_id"`
	Groups   []string `json:"groups"`
	TenantID string   `json:"tenant_id"`
	Resource string   `json:"resource"`
	Action   Action   `json:"action"`
}

// OPAResult is the result from OPA policy evaluation.
type OPAResult struct {
	Allow             bool     `json:"allow"`
	EffectiveFilters  []string `json:"effective_filters"`
	AccessibleTenants []string `json:"accessible_tenants"`
}

// OPAResponse wraps the OPA REST API response.
type OPAResponse struct {
	Result OPAResult `json:"result"`
}

// OPAClient defines the interface for communicating with the OPA REST API.
type OPAClient interface {
	Evaluate(ctx context.Context, input OPAInput) (*OPAResult, error)
}

// opaClient implements OPAClient.
type opaClient struct {
	baseURL    string
	policyPath string
	httpClient *http.Client
	metrics    *Metrics
}

// NewOPAClient creates a new OPA client.
// If transport is non-nil, it is used for authentication injection.
func NewOPAClient(baseURL, policyPath string, timeout time.Duration, transport http.RoundTripper, metrics *Metrics) OPAClient {
	client := &http.Client{
		Timeout:   timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
	if transport != nil {
		client.Transport = transport
	}
	return &opaClient{
		baseURL:    baseURL,
		policyPath: policyPath,
		httpClient: client,
		metrics:    metrics,
	}
}

// Evaluate sends an input to OPA and returns the authorization result.
// OPA is called exactly once per tenant per request (invariant #1).
func (c *opaClient) Evaluate(ctx context.Context, input OPAInput) (*OPAResult, error) {
	ctx, span := tracer.Start(ctx, "opa.Evaluate")
	defer span.End()

	span.SetAttributes(
		attribute.String("opa.user_id", input.UserID),
		attribute.String("opa.tenant_id", input.TenantID),
		attribute.String("opa.action", string(input.Action)),
	)

	// Build request body
	reqBody := map[string]interface{}{
		"input": input,
	}
	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("marshaling OPA input: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/%s", c.baseURL, c.policyPath)

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("creating OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute
	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start).Seconds()

	if c.metrics != nil {
		c.metrics.opaEvalTotal.Add(ctx, 1)
		c.metrics.opaEvalDuration.Record(ctx, duration)
	}

	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("reading OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(respBody))
		span.RecordError(err)
		return nil, err
	}

	// Parse response
	var opaResp OPAResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("parsing OPA response: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("opa.allow", opaResp.Result.Allow),
		attribute.Int("opa.filters_count", len(opaResp.Result.EffectiveFilters)),
	)

	return &opaResp.Result, nil
}
