package handler

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"go.opentelemetry.io/otel/attribute"
)

// RewriteQuery parses a PromQL query, injects label matchers into every
// VectorSelector in the AST, and returns the re-rendered query string.
// This is the ONLY way to inject filters — never use regex or string replacement.
func RewriteQuery(ctx context.Context, query string, matchers []*labels.Matcher) (string, error) {
	ctx, span := tracer.Start(ctx, "rewrite.Query")
	defer span.End()

	span.SetAttributes(
		attribute.String("rewrite.original_query", query),
		attribute.Int("rewrite.matchers_count", len(matchers)),
	)

	if len(matchers) == 0 {
		return query, nil
	}

	expr, err := parser.ParseExpr(query)
	if err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("parsing PromQL query: %w", err)
	}

	// Walk the AST and inject matchers into every VectorSelector
	if err := injectMatchers(expr, matchers); err != nil {
		span.RecordError(err)
		return "", fmt.Errorf("injecting matchers: %w", err)
	}

	rewritten := expr.String()
	span.SetAttributes(attribute.String("rewrite.result_query", rewritten))

	return rewritten, nil
}

// injectMatchers walks the PromQL AST and injects the provided matchers into
// all VectorSelector nodes it encounters.
func injectMatchers(node parser.Node, matchers []*labels.Matcher) error {
	var walkErr error
	parser.Inspect(node, func(n parser.Node, path []parser.Node) error {
		if walkErr != nil {
			return nil // fast return on error
		}
		switch v := n.(type) {
		case *parser.VectorSelector:
			v.LabelMatchers = mergeMatchers(v.LabelMatchers, matchers)
		}
		return nil
	})
	return walkErr
}

// RewriteMatchParams rewrites a list of match[] parameters (used by /api/v1/series).
func RewriteMatchParams(ctx context.Context, matchParams []string, matchers []*labels.Matcher) ([]string, error) {
	result := make([]string, 0, len(matchParams))
	for _, m := range matchParams {
		rewritten, err := RewriteQuery(ctx, m, matchers)
		if err != nil {
			return nil, fmt.Errorf("rewriting match param %q: %w", m, err)
		}
		result = append(result, rewritten)
	}
	return result, nil
}

// mergeMatchers merges enforced matchers into existing matchers,
// avoiding duplicates based on name + type + value.
func mergeMatchers(existing []*labels.Matcher, enforced []*labels.Matcher) []*labels.Matcher {
	result := make([]*labels.Matcher, 0, len(existing)+len(enforced))
	result = append(result, existing...)

	for _, em := range enforced {
		if !hasMatcherDuplicate(existing, em) {
			result = append(result, em)
		}
	}

	return result
}

// hasMatcherDuplicate checks if any existing matcher has the same name, type, and value.
func hasMatcherDuplicate(existing []*labels.Matcher, m *labels.Matcher) bool {
	for _, e := range existing {
		if e.Name == m.Name && e.Type == m.Type && e.Value == m.Value {
			return true
		}
	}
	return false
}

// ParseFilters parses filter strings (e.g., `env="prod"`) into label matchers.
func ParseFilters(filters []string) ([]*labels.Matcher, error) {
	matchers := make([]*labels.Matcher, 0, len(filters))
	for _, f := range filters {
		ms, err := parser.ParseMetricSelector("{" + f + "}")
		if err != nil {
			return nil, fmt.Errorf("parsing filter %q: %w", f, err)
		}
		for _, m := range ms {
			if m.Name != labels.MetricName {
				matchers = append(matchers, m)
			}
		}
	}
	return matchers, nil
}

// NormalizeFilters deduplicates, sorts, and serializes filters deterministically
// for use as a canonical grouping key in fan-out.
func NormalizeFilters(filters []string) string {
	if len(filters) == 0 {
		return ""
	}

	// Deduplicate
	seen := make(map[string]struct{})
	unique := make([]string, 0, len(filters))
	for _, f := range filters {
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			unique = append(unique, f)
		}
	}

	// Sort lexicographically
	sort.Strings(unique)

	// Deterministic serialization
	return strings.Join(unique, "|")
}
