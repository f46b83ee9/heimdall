package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
)

func TestFilterRulesResponse(t *testing.T) {
	body := []byte(`{
		"status": "success",
		"data": {
			"groups": [
				{
					"name": "g1",
					"rules": [
						{"name": "r1", "type": "recording", "labels": {"team": "dev", "env": "prod"}},
						{"name": "r2", "type": "recording", "labels": {"team": "ops", "env": "prod"}}
					]
				}
			]
		}
	}`)

	t.Run("Bypass when no matchers", func(t *testing.T) {
		out, err := FilterRulesResponse(context.Background(), body, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(body) {
			t.Error("expected unchanged body when no matchers provided")
		}
	})

	t.Run("Filter by label", func(t *testing.T) {
		matchers := []*labels.Matcher{
			labels.MustNewMatcher(labels.MatchEqual, "team", "dev"),
		}
		out, err := FilterRulesResponse(context.Background(), body, matchers)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "r1") || strings.Contains(string(out), "r2") {
			t.Errorf("incorrect filtering: %s", string(out))
		}
	})

	t.Run("Empty groups removed", func(t *testing.T) {
		matchers := []*labels.Matcher{
			labels.MustNewMatcher(labels.MatchEqual, "team", "security"),
		}
		out, err := FilterRulesResponse(context.Background(), body, matchers)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), `"groups":[]`) {
			t.Errorf("expected empty groups list, got %s", string(out))
		}
	})

	t.Run("Malformed JSON", func(t *testing.T) {
		_, err := FilterRulesResponse(context.Background(), []byte(`{invalid`), []*labels.Matcher{{}})
		if err == nil {
			t.Error("expected error on malformed JSON")
		}
	})
}

func TestFilterAlertsResponse(t *testing.T) {
	body := []byte(`{
		"status": "success",
		"data": {
			"alerts": [
				{"labels": {"team": "dev"}, "state": "firing"},
				{"labels": {"team": "ops"}, "state": "firing"}
			]
		}
	}`)

	t.Run("Filter by label", func(t *testing.T) {
		matchers := []*labels.Matcher{
			labels.MustNewMatcher(labels.MatchEqual, "team", "ops"),
		}
		out, err := FilterAlertsResponse(context.Background(), body, matchers)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "ops") || strings.Contains(string(out), "dev") {
			t.Errorf("incorrect filtering: %s", string(out))
		}
	})

	t.Run("Malformed JSON", func(t *testing.T) {
		_, err := FilterAlertsResponse(context.Background(), []byte(`{invalid`), []*labels.Matcher{{}})
		if err == nil {
			t.Error("expected error on malformed JSON")
		}
	})

	t.Run("Bypass when no matchers", func(t *testing.T) {
		out, err := FilterAlertsResponse(context.Background(), body, nil)
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != string(body) {
			t.Error("expected unchanged body")
		}
	})
}
