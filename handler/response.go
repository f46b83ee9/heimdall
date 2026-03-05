package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/prometheus/model/labels"
	"go.opentelemetry.io/otel/attribute"
)

// RulesResponse represents the Prometheus /api/v1/rules response.
type RulesResponse struct {
	Status string    `json:"status"`
	Data   RulesData `json:"data"`
}

// RulesData holds the groups from a rules response.
type RulesData struct {
	Groups []RuleGroup `json:"groups"`
}

// RuleGroup represents a group of rules.
type RuleGroup struct {
	Name  string `json:"name"`
	File  string `json:"file"`
	Rules []Rule `json:"rules"`
}

// Rule represents a single rule within a group.
type Rule struct {
	Name        string            `json:"name"`
	Query       string            `json:"query,omitempty"`
	Duration    float64           `json:"duration,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	State       string            `json:"state,omitempty"`
	Health      string            `json:"health,omitempty"`
	Type        string            `json:"type"`

	// Additional fields preserved as raw JSON
	Alerts json.RawMessage `json:"alerts,omitempty"`
}

// AlertsResponse represents the Prometheus /api/v1/alerts response.
type AlertsResponse struct {
	Status string     `json:"status"`
	Data   AlertsData `json:"data"`
}

// AlertsData holds the alerts from an alerts response.
type AlertsData struct {
	Alerts []Alert `json:"alerts"`
}

// Alert represents a single alert.
type Alert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations,omitempty"`
	State       string            `json:"state"`
	ActiveAt    string            `json:"activeAt,omitempty"`
	Value       string            `json:"value,omitempty"`
}

// FilterRulesResponse filters a /api/v1/rules response, keeping only rules
// whose labels match ALL enforced matchers. Empty groups are removed.
// If matchers is nil or empty, the body is returned unchanged (bypass fast path).
func FilterRulesResponse(ctx context.Context, body []byte, matchers []*labels.Matcher) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "filter.Rules")
	defer span.End()

	if len(matchers) == 0 {
		span.SetAttributes(attribute.Bool("filter.bypass", true))
		return body, nil
	}

	var resp RulesResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("parsing rules response: %w", err)
	}

	totalRules := 0
	keptRules := 0

	filteredGroups := make([]RuleGroup, 0, len(resp.Data.Groups))
	for _, group := range resp.Data.Groups {
		filteredRules := make([]Rule, 0, len(group.Rules))
		for _, rule := range group.Rules {
			totalRules++
			if MatchLabels(rule.Labels, matchers) {
				filteredRules = append(filteredRules, rule)
				keptRules++
			}
		}

		// Only keep non-empty groups
		if len(filteredRules) > 0 {
			group.Rules = filteredRules
			filteredGroups = append(filteredGroups, group)
		}
	}

	resp.Data.Groups = filteredGroups

	span.SetAttributes(
		attribute.Int("filter.total_rules", totalRules),
		attribute.Int("filter.kept_rules", keptRules),
	)

	result, err := json.Marshal(resp)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("marshaling filtered rules response: %w", err)
	}

	return result, nil
}

// FilterAlertsResponse filters a /api/v1/alerts response, keeping only alerts
// whose labels match ALL enforced matchers.
// If matchers is nil or empty, the body is returned unchanged (bypass fast path).
func FilterAlertsResponse(ctx context.Context, body []byte, matchers []*labels.Matcher) ([]byte, error) {
	ctx, span := tracer.Start(ctx, "filter.Alerts")
	defer span.End()

	if len(matchers) == 0 {
		span.SetAttributes(attribute.Bool("filter.bypass", true))
		return body, nil
	}

	var resp AlertsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("parsing alerts response: %w", err)
	}

	filteredAlerts := make([]Alert, 0, len(resp.Data.Alerts))
	for _, alert := range resp.Data.Alerts {
		if MatchLabels(alert.Labels, matchers) {
			filteredAlerts = append(filteredAlerts, alert)
		}
	}

	span.SetAttributes(
		attribute.Int("filter.total_alerts", len(resp.Data.Alerts)),
		attribute.Int("filter.kept_alerts", len(filteredAlerts)),
	)

	resp.Data.Alerts = filteredAlerts

	result, err := json.Marshal(resp)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("marshaling filtered alerts response: %w", err)
	}

	return result, nil
}

// MatchLabels checks if ALL enforced matchers match against the given label set.
func MatchLabels(ruleLabels map[string]string, enforced []*labels.Matcher) bool {
	for _, m := range enforced {
		val := ruleLabels[m.Name]
		if !m.Matches(val) {
			return false
		}
	}
	return true
}
