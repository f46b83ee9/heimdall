package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
)

// tenantResult holds the OPA evaluation result for a single tenant.
type tenantResult struct {
	TenantID         string
	Allow            bool
	EffectiveFilters []string
}

// filterGroup represents a group of tenants that share identical filter signatures,
// enabling Mimir native federation.
type filterGroup struct {
	FilterKey string
	TenantIDs []string
	Filters   []string
	Matchers  []*labels.Matcher
}

// upstreamResult holds the response from an upstream Mimir request.
type upstreamResult struct {
	GroupIndex int
	Body       []byte
	Status     int
}

// FanOutEngine orchestrates multi-tenant fan-out with bounded concurrency.
type FanOutEngine struct {
	opaClient  OPAClient
	mimirCfg   config.MimirConfig
	httpClient *http.Client
	sem        chan struct{} // Global semaphore for bounded concurrency limits
	timeout    time.Duration // Explicit context timeout for dispatch
	metrics    *Metrics
}

// NewFanOutEngine creates a new FanOutEngine with the given configuration.
func NewFanOutEngine(opaClient OPAClient, cfg config.MimirConfig, fanOutCfg config.FanOutConfig, transport http.RoundTripper, metrics *Metrics) *FanOutEngine {
	// Initialize global semaphore
	sem := make(chan struct{}, fanOutCfg.MaxConcurrency)
	client := &http.Client{
		// The http.Client timeout acts as an absolute fallback
		Timeout:   cfg.Timeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
	if transport != nil {
		client.Transport = transport
	}
	// URL overrides allow microservices topology
	return &FanOutEngine{
		opaClient:  opaClient,
		mimirCfg:   cfg,
		sem:        sem,
		timeout:    fanOutCfg.Timeout,
		httpClient: client,
		metrics:    metrics,
	}
}

// isReadAction returns true for actions that require query rewriting.
func isReadAction(action Action) bool {
	return action == ActionRead
}

// isWriteAction returns true for pass-through write actions.
func isWriteAction(action Action) bool {
	switch action {
	case ActionWrite, ActionRulesWrite, ActionAlertsWrite:
		return true
	}
	return false
}

// isResponseFilterAction returns true for actions requiring response-mode filtering.
func isResponseFilterAction(action Action) bool {
	switch action {
	case ActionRulesRead, ActionAlertsRead:
		return true
	}
	return false
}

// AuthorizeWrite evaluates OPA for each tenant for write actions.
// Returns the denied tenant ID and error, or empty string and nil on success.
func (fe *FanOutEngine) AuthorizeWrite(ctx context.Context, identity *Identity, tenantIDs []string, action Action) (string, error) {
	ctx, span := tracer.Start(ctx, "fanout.AuthorizeWrite")
	defer span.End()

	for _, tid := range tenantIDs {
		opaInput := OPAInput{
			UserID:   identity.UserID,
			Groups:   identity.Groups,
			TenantID: tid,
			Resource: "metrics",
			Action:   action,
		}

		result, err := fe.opaClient.Evaluate(ctx, opaInput)
		if err != nil {
			span.RecordError(err)
			return tid, fmt.Errorf("OPA evaluation for tenant %s: %w", tid, err)
		}

		if !result.Allow {
			return tid, nil
		}
	}

	return "", nil
}

// resolveUpstreamURL determines the upstream endpoint dynamically using requested overrides.
func (fe *FanOutEngine) resolveUpstreamURL(path string, action Action) string {
	var baseURL string
	var isOverride bool

	// 1. Select the base URL depending on configured overrides
	switch action {
	case ActionWrite:
		if fe.mimirCfg.WriteURL != "" {
			baseURL = fe.mimirCfg.WriteURL
			isOverride = true
		}
	case ActionRead:
		if fe.mimirCfg.ReadURL != "" {
			baseURL = fe.mimirCfg.ReadURL
			isOverride = true
		}
	case ActionRulesRead, ActionRulesWrite:
		if fe.mimirCfg.RulerURL != "" {
			baseURL = fe.mimirCfg.RulerURL
			isOverride = true
		}
	case ActionAlertsRead:
		if fe.mimirCfg.AlertmanagerURL != "" {
			baseURL = fe.mimirCfg.AlertmanagerURL
			isOverride = true
		}
	}

	// Fallback to global URL
	if baseURL == "" {
		baseURL = fe.mimirCfg.URL
	}

	// 2. Normalize by trimming trailing slashes only.
	baseURL = strings.TrimRight(baseURL, "/")

	// 3. Provide exact mapping directly from the configured URL if it's an explicit override.
	if isOverride {
		return baseURL + path
	}

	// 4. Default monolithic Mimir behavior: append /prometheus for everything except write requests
	if action == ActionWrite && path == "/api/v1/push" {
		return baseURL + path
	}

	return baseURL + "/prometheus" + path
}

// ForwardWrite forwards a write request byte-for-byte to the upstream Mimir.
// No body inspection, no PromQL parsing, no filter injection — authorize only.
func (fe *FanOutEngine) ForwardWrite(ctx context.Context, tenantIDs []string, originalReq *http.Request) ([]byte, int, error) {
	ctx, span := tracer.Start(ctx, "fanout.ForwardWrite")
	defer span.End()

	orgID := strings.Join(tenantIDs, "|")
	upstreamURL := fe.resolveUpstreamURL(originalReq.URL.Path, ActionWrite)

	if originalReq.URL.RawQuery != "" {
		upstreamURL += "?" + originalReq.URL.RawQuery
	}

	req, err := http.NewRequestWithContext(ctx, originalReq.Method, upstreamURL, originalReq.Body)
	if err != nil {
		span.RecordError(err)
		return nil, 0, fmt.Errorf("creating upstream request: %w", err)
	}

	req.Header.Set("X-Scope-OrgID", orgID)
	req.Header.Set("Content-Type", originalReq.Header.Get("Content-Type"))

	// Propagate trace context
	otel.GetTextMapPropagator().Inject(ctx, propagationHeader{req.Header})

	resp, err := fe.httpClient.Do(req)
	if err != nil {
		span.RecordError(err)
		return nil, 0, fmt.Errorf("upstream write request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		span.RecordError(err)
		return nil, resp.StatusCode, fmt.Errorf("reading upstream response: %w", err)
	}

	return body, resp.StatusCode, nil
}
