package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func TestFilterRulesResponse(t *testing.T) {
	ctx := context.Background()

	rulesJSON := `{
		"status": "success",
		"data": {
			"groups": [
				{
					"name": "test-group",
					"file": "rules.yml",
					"rules": [
						{"name": "prod-alert", "labels": {"env": "prod", "severity": "critical"}, "type": "alerting"},
						{"name": "staging-alert", "labels": {"env": "staging", "severity": "warning"}, "type": "alerting"},
						{"name": "dev-alert", "labels": {"env": "dev"}, "type": "alerting"}
					]
				},
				{
					"name": "empty-after-filter",
					"file": "other.yml",
					"rules": [
						{"name": "staging-only", "labels": {"env": "staging"}, "type": "alerting"}
					]
				}
			]
		}
	}`

	tests := []struct {
		name        string
		matchers    []*labels.Matcher
		wantGroups  int
		wantRulesG0 int // rules in first group
	}{
		{
			name:        "no matchers bypasses filter",
			matchers:    nil,
			wantGroups:  2,
			wantRulesG0: 3,
		},
		{
			name:        "filter by env=prod",
			matchers:    []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")},
			wantGroups:  1,
			wantRulesG0: 1,
		},
		{
			name:        "filter by env=staging keeps both groups",
			matchers:    []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "staging")},
			wantGroups:  2,
			wantRulesG0: 1,
		},
		{
			name:        "filter that matches nothing",
			matchers:    []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "nonexistent")},
			wantGroups:  0,
			wantRulesG0: 0,
		},
		{
			name:        "negative matcher includes missing labels (empty string != local)",
			matchers:    []*labels.Matcher{labels.MustNewMatcher(labels.MatchNotEqual, "env", "local")},
			wantGroups:  2,
			wantRulesG0: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FilterRulesResponse(ctx, []byte(rulesJSON), tt.matchers)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var resp RulesResponse
			if err := json.Unmarshal(result, &resp); err != nil {
				t.Fatalf("unmarshaling result: %v", err)
			}

			if len(resp.Data.Groups) != tt.wantGroups {
				t.Errorf("got %d groups, want %d", len(resp.Data.Groups), tt.wantGroups)
			}

			if tt.wantGroups > 0 && len(resp.Data.Groups[0].Rules) != tt.wantRulesG0 {
				t.Errorf("group[0]: got %d rules, want %d", len(resp.Data.Groups[0].Rules), tt.wantRulesG0)
			}
		})
	}
}

func TestFilterAlertsResponse(t *testing.T) {
	ctx := context.Background()

	alertsJSON := `{
		"status": "success",
		"data": {
			"alerts": [
				{"labels": {"alertname": "HighLatency", "env": "prod"}, "state": "firing"},
				{"labels": {"alertname": "HighMemory", "env": "staging"}, "state": "firing"},
				{"labels": {"alertname": "DiskFull", "env": "prod", "severity": "critical"}, "state": "pending"}
			]
		}
	}`

	tests := []struct {
		name       string
		matchers   []*labels.Matcher
		wantAlerts int
	}{
		{
			name:       "no matchers bypasses",
			matchers:   nil,
			wantAlerts: 3,
		},
		{
			name:       "filter by env=prod",
			matchers:   []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")},
			wantAlerts: 2,
		},
		{
			name:       "filter by severity=critical",
			matchers:   []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "severity", "critical")},
			wantAlerts: 1,
		},
		{
			name:       "no matches returns empty",
			matchers:   []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "none")},
			wantAlerts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FilterAlertsResponse(ctx, []byte(alertsJSON), tt.matchers)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var resp AlertsResponse
			if err := json.Unmarshal(result, &resp); err != nil {
				t.Fatalf("unmarshaling result: %v", err)
			}

			if len(resp.Data.Alerts) != tt.wantAlerts {
				t.Errorf("got %d alerts, want %d", len(resp.Data.Alerts), tt.wantAlerts)
			}
		})
	}
}

func TestFilterRulesResponse_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	matchers := []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")}

	_, err := FilterRulesResponse(ctx, []byte("invalid json"), matchers)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFilterAlertsResponse_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	matchers := []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")}

	_, err := FilterAlertsResponse(ctx, []byte("invalid json"), matchers)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
