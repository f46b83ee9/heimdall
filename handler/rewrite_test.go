package handler

import (
	"context"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func TestRewriting_PromQL_Injection(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		query    string
		matchers []*labels.Matcher
		want     string
		wantErr  bool
	}{
		{
			name:     "no matchers returns original",
			query:    "up",
			matchers: nil,
			want:     "up",
		},
		{
			name:  "injects single label matcher",
			query: "up",
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
			},
			want: `up{env="prod"}`,
		},
		{
			name:  "injects multiple matchers",
			query: "http_requests_total",
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
				labels.MustNewMatcher(labels.MatchEqual, "namespace", "default"),
			},
			want: `http_requests_total{env="prod",namespace="default"}`,
		},
		{
			name:  "preserves existing matchers",
			query: `up{job="prometheus"}`,
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
			},
			want: `up{env="prod",job="prometheus"}`,
		},
		{
			name:  "skips duplicate matchers",
			query: `up{env="prod"}`,
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
			},
			want: `up{env="prod"}`,
		},
		{
			name:  "works with aggregation expressions",
			query: `sum(rate(http_requests_total[5m]))`,
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
			},
			want: `sum(rate(http_requests_total{env="prod"}[5m]))`,
		},
		{
			name:     "invalid PromQL returns error",
			query:    "invalid{{{",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "a", "b")},
			wantErr:  true,
		},
		{
			name:     "binary expression",
			query:    "up + down",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `up{id="1"} + down{id="1"}`,
		},
		{
			name:     "subquery",
			query:    "up[5m:1m]",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `up{id="1"}[5m:1m]`,
		},
		{
			name:     "call",
			query:    "absent(up)",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `absent(up{id="1"})`,
		},
		{
			name:     "matrix selector",
			query:    "rate(up[5m])",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `rate(up{id="1"}[5m])`,
		},
		{
			name:     "offset",
			query:    "up offset 5m",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `up{id="1"} offset 5m`,
		},
		{
			name:     "paren expression",
			query:    "(up)",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `(up{id="1"})`,
		},
		{
			name:     "aggregation",
			query:    "sum(up) by (job)",
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `sum by (job) (up{id="1"})`,
		},
		{
			name:     "complex aggregation",
			query:    `sum by (env) (rate(http_requests_total{status="200"}[5m]))`,
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "id", "1")},
			want:     `sum by (env) (rate(http_requests_total{id="1",status="200"}[5m]))`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RewriteQuery(ctx, tt.query, tt.matchers)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRewriting_FilterParsing(t *testing.T) {
	tests := []struct {
		name    string
		filters []string
		want    int // number of matchers
		wantErr bool
	}{
		{
			name:    "empty filters",
			filters: nil,
			want:    0,
		},
		{
			name:    "single equality filter",
			filters: []string{`env="prod"`},
			want:    1,
		},
		{
			name:    "multiple filters",
			filters: []string{`env="prod"`, `namespace="default"`},
			want:    2,
		},
		{
			name:    "regex filter",
			filters: []string{`env=~"prod|staging"`},
			want:    1,
		},
		{
			name:    "invalid filter returns error",
			filters: []string{"invalid-no-value"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFilters(tt.filters)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.want {
				t.Errorf("got %d matchers, want %d", len(got), tt.want)
			}
		})
	}

	// Test skipping __name__ (Rule 112)
	t.Run("skipping __name__ label", func(t *testing.T) {
		filters := []string{`__name__="up"`, `env="prod"`}
		matchers, err := ParseFilters(filters)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(matchers) != 1 {
			t.Errorf("expected 1 matcher (skipping __name__), got %d", len(matchers))
		}
	})
}

func TestRewriting_FilterNormalization(t *testing.T) {
	tests := []struct {
		name    string
		filters []string
		want    string
	}{
		{
			name:    "empty filters",
			filters: nil,
			want:    "",
		},
		{
			name:    "single filter",
			filters: []string{`env="prod"`},
			want:    `env="prod"`,
		},
		{
			name:    "already sorted",
			filters: []string{`a="1"`, `b="2"`},
			want:    `a="1"|b="2"`,
		},
		{
			name:    "sorts alphabetically",
			filters: []string{`z="3"`, `a="1"`, `m="2"`},
			want:    `a="1"|m="2"|z="3"`,
		},
		{
			name:    "deduplicates",
			filters: []string{`env="prod"`, `env="prod"`, `ns="default"`},
			want:    `env="prod"|ns="default"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeFilters(tt.filters)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRewriting_MatchParams_Error(t *testing.T) {
	ctx := context.Background()
	_, err := RewriteMatchParams(ctx, []string{"invalid{"}, []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "a", "b")})
	if err == nil {
		t.Error("expected error for invalid match param")
	}
}

func TestRewriting_LabelMatching(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		matchers []*labels.Matcher
		want     bool
	}{
		{
			name:     "no matchers always matches",
			labels:   map[string]string{"env": "prod"},
			matchers: nil,
			want:     true,
		},
		{
			name:     "equality match",
			labels:   map[string]string{"env": "prod"},
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")},
			want:     true,
		},
		{
			name:     "equality no match",
			labels:   map[string]string{"env": "staging"},
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")},
			want:     false,
		},
		{
			name:     "missing label fails for equality",
			labels:   map[string]string{},
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchEqual, "env", "prod")},
			want:     false,
		},
		{
			name:     "not-equal with missing label passes",
			labels:   map[string]string{},
			matchers: []*labels.Matcher{labels.MustNewMatcher(labels.MatchNotEqual, "env", "prod")},
			want:     true,
		},
		{
			name:   "multiple matchers all must match",
			labels: map[string]string{"env": "prod", "ns": "default"},
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
				labels.MustNewMatcher(labels.MatchEqual, "ns", "default"),
			},
			want: true,
		},
		{
			name:   "one of multiple matchers fails",
			labels: map[string]string{"env": "prod", "ns": "kube-system"},
			matchers: []*labels.Matcher{
				labels.MustNewMatcher(labels.MatchEqual, "env", "prod"),
				labels.MustNewMatcher(labels.MatchEqual, "ns", "default"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchLabels(tt.labels, tt.matchers)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
