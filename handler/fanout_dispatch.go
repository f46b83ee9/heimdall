package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/errgroup"
)

// Dispatch sends parallel upstream requests to Mimir for each filter group,
// using bounded concurrency. Returns merged response body.
func (fe *FanOutEngine) Dispatch(ctx context.Context, groups []filterGroup, originalReq *http.Request, action Action) ([]byte, int, error) {
	ctx, span := tracer.Start(ctx, "fanout.Dispatch")
	defer span.End()

	if len(groups) == 0 {
		return nil, http.StatusForbidden, nil
	}

	// Apply explicit timeout to the dispatch (Invariant #20)
	ctx, cancel := context.WithTimeout(ctx, fe.timeout)
	defer cancel()

	results := make([]upstreamResult, len(groups))
	g, ctx := errgroup.WithContext(ctx)

	for i, group := range groups {

		// Global Backpressure (Invariant #21)
		// Non-blocking try-acquire from semaphore channel
		select {
		case <-ctx.Done():
			span.RecordError(ctx.Err())
			return nil, http.StatusGatewayTimeout, fmt.Errorf("dispatch context done: %w", ctx.Err())
		case fe.sem <- struct{}{}:
			// Acquired successfully
			if fe.metrics != nil {
				fe.metrics.fanoutActive.Add(ctx, 1)
			}
		default:
			// Capacity exceeded, fail fast with 503
			if fe.metrics != nil {
				fe.metrics.fanoutDropped.Add(ctx, 1)
			}
			err := fmt.Errorf("fanout_overloaded: maximum concurrency reached")
			span.RecordError(err)
			return nil, http.StatusServiceUnavailable, err
		}

		g.Go(func() error {
			// Ensure semaphore is released when finished
			defer func() {
				<-fe.sem
				if fe.metrics != nil {
					fe.metrics.fanoutActive.Add(ctx, -1)
				}
			}()

			body, status, err := fe.dispatchSingle(ctx, group, originalReq, action)
			if err != nil {
				return fmt.Errorf("upstream request for group %d: %w", i, err)
			}
			results[i] = upstreamResult{
				GroupIndex: i,
				Body:       body,
				Status:     status,
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		span.RecordError(err)

		// Preserve 503 error if originated from ctx.Done() inside goroutine
		if ctx.Err() != nil {
			return nil, http.StatusGatewayTimeout, err
		}
		return nil, http.StatusBadGateway, err
	}

	// Merge results deterministically
	merged, err := mergeResults(results)
	if err != nil {
		span.RecordError(err)
		return nil, http.StatusInternalServerError, fmt.Errorf("merging responses: %w", err)
	}

	return merged, http.StatusOK, nil
}

// dispatchSingle sends a single upstream request to Mimir.
func (fe *FanOutEngine) dispatchSingle(ctx context.Context, group filterGroup, originalReq *http.Request, action Action) ([]byte, int, error) {
	upstreamURL := fe.resolveUpstreamURL(originalReq.URL.Path, action)

	ctx, span := tracer.Start(ctx, "fanout.DispatchSingle")
	defer span.End()

	// Build X-Scope-OrgID (pipe-separated for native federation)
	orgID := strings.Join(group.TenantIDs, "|")
	span.SetAttributes(
		attribute.String("mimir.org_id", orgID),
		attribute.String("mimir.filter_key", group.FilterKey),
	)

	// Clone the original request
	// upstreamURL already built

	// For read actions, rewrite the query
	var body io.Reader

	// Pre-parse the form to handle URL-encoded POST bodies
	if err := originalReq.ParseForm(); err != nil {
		return nil, 0, fmt.Errorf("parsing form data: %w", err)
	}

	query := originalReq.Form

	if isReadAction(action) && len(group.Matchers) > 0 {
		// Rewrite query parameter
		if q := query.Get("query"); q != "" {
			rewritten, err := RewriteQuery(ctx, q, group.Matchers)
			if err != nil {
				return nil, 0, fmt.Errorf("rewriting query: %w", err)
			}
			query.Set("query", rewritten)
		}

		// Rewrite match[] parameters
		if matchParams := query["match[]"]; len(matchParams) > 0 {
			rewritten, err := RewriteMatchParams(ctx, matchParams, group.Matchers)
			if err != nil {
				return nil, 0, fmt.Errorf("rewriting match params: %w", err)
			}
			query.Del("match[]")
			for _, m := range rewritten {
				query.Add("match[]", m)
			}
		}
	}

	// For write actions, forward body byte-for-byte
	if isWriteAction(action) {
		body = originalReq.Body
	} else if originalReq.Method == http.MethodPost {
		// Re-encode body if it was a POST read action (e.g. /api/v1/query)
		formBody := query.Encode()
		body = strings.NewReader(formBody)
		// Important: we also must not use the query string in the URL for POST requests,
		// because Mimir expects them in the body.
		// So we empty `query` out, we only encoded it into `body`.
		query = nil
	}

	reqURL := upstreamURL
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, originalReq.Method, reqURL, body)
	if err != nil {
		return nil, 0, fmt.Errorf("creating upstream request: %w", err)
	}

	// Set headers
	req.Header.Set("X-Scope-OrgID", orgID)
	req.Header.Set("Content-Type", originalReq.Header.Get("Content-Type"))

	// Propagate trace context
	otel.GetTextMapPropagator().Inject(ctx, propagationHeader{req.Header})

	start := time.Now()
	resp, err := fe.httpClient.Do(req)
	duration := time.Since(start).Seconds()

	if err != nil {
		span.RecordError(err)

		// Record failed request metrics
		if fe.metrics != nil {
			attrs := metric.WithAttributes(
				attribute.String("method", req.Method),
				attribute.String("path", req.URL.Path),
				attribute.String("status", "error"),
			)
			fe.metrics.upstreamTotal.Add(ctx, 1, attrs)
			fe.metrics.upstreamDuration.Record(ctx, duration, attrs)
		}

		return nil, 0, fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if fe.metrics != nil {
		attrs := metric.WithAttributes(
			attribute.String("method", req.Method),
			attribute.String("path", req.URL.Path),
			attribute.String("status", strconv.Itoa(resp.StatusCode)),
		)
		fe.metrics.upstreamTotal.Add(ctx, 1, attrs)
		fe.metrics.upstreamDuration.Record(ctx, duration, attrs)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		span.RecordError(err)
		return nil, resp.StatusCode, fmt.Errorf("reading upstream response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		slog.WarnContext(ctx, "upstream returned non-200",
			"status", resp.StatusCode,
			"org_id", orgID,
		)
	}

	return respBody, resp.StatusCode, nil
}

// mergeResults merges upstream responses deterministically.
// Results are ordered by group index (which is already sorted by filter key).
func mergeResults(results []upstreamResult) ([]byte, error) {
	if len(results) == 1 {
		return results[0].Body, nil
	}

	// For Prometheus-style responses, merge the data arrays
	type promResponse struct {
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}

	// Attempt to merge as Prometheus instant/range query results
	var merged struct {
		Status string      `json:"status"`
		Data   interface{} `json:"data"`
	}
	merged.Status = "success"

	// Simple concatenation of result arrays for matrix/vector data
	type queryData struct {
		ResultType string            `json:"resultType"`
		Result     []json.RawMessage `json:"result"`
	}

	var allResults []json.RawMessage
	var resultType string

	for _, r := range results {
		var pr promResponse
		if err := json.Unmarshal(r.Body, &pr); err != nil {
			// If we can't parse, just return the first result
			return results[0].Body, nil
		}

		var qd queryData
		if err := json.Unmarshal(pr.Data, &qd); err != nil {
			// Not a standard query response, return first result
			return results[0].Body, nil
		}

		if resultType == "" {
			resultType = qd.ResultType
		}
		allResults = append(allResults, qd.Result...)
	}

	// Sort results deterministically by JSON content
	sort.Slice(allResults, func(i, j int) bool {
		return string(allResults[i]) < string(allResults[j])
	})

	merged.Data = queryData{
		ResultType: resultType,
		Result:     allResults,
	}

	return json.Marshal(merged)
}
