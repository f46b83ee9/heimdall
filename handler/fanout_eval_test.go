package handler

// protects: Invariant[Isolation] - Tenants with identical filters must be grouped safely.
// protects: Invariant[Availability] - Handle OPA and filter parsing errors in evaluation.

import (
	"context"
	"errors"
	"testing"

	"github.com/f46b83ee9/heimdall/config"
)

func TestFanOutEngine_EvaluateTenants_Exhaustive(t *testing.T) {
	mockOPA := &MockOPA{Result: &OPAResult{Allow: true}}
	fe := NewFanOutEngine(mockOPA, config.MimirConfig{}, config.FanOutConfig{}, nil, nil)

	identity := &Identity{UserID: "alice"}

	t.Run("OPA error", func(t *testing.T) {
		mockOPA.Err = errors.New("OPA evaluation failure")
		_, err := fe.EvaluateTenants(context.Background(), identity, []string{"t1"}, ActionRead, "metrics")
		if err == nil {
			t.Error("expected error, got nil")
		}
	})

	t.Run("ParseFilters error", func(t *testing.T) {
		mockOPA.Err = nil
		// Invalid regex syntax triggers ParseFilters error
		mockOPA.Result = &OPAResult{Allow: true, EffectiveFilters: []string{`env=~"["`}}
		_, err := fe.EvaluateTenants(context.Background(), identity, []string{"t1"}, ActionRead, "metrics")
		if err == nil {
			t.Error("expected ParseFilters error, got nil")
		}
	})

	t.Run("All Denied", func(t *testing.T) {
		mockOPA.Result = &OPAResult{Allow: false}
		mockOPA.Err = nil
		groups, err := fe.EvaluateTenants(context.Background(), identity, []string{"t1"}, ActionRead, "metrics")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if groups != nil {
			t.Error("expected nil groups for all denied")
		}
	})

	t.Run("Shared Filters Grouping", func(t *testing.T) {
		mockOPA.Result = &OPAResult{Allow: true, EffectiveFilters: []string{`job="prometheus"`}}
		mockOPA.Err = nil
		groups, err := fe.EvaluateTenants(context.Background(), identity, []string{"t1", "t2"}, ActionRead, "metrics")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(groups) != 1 {
			t.Errorf("expected 1 group, got %d", len(groups))
		}
		if len(groups[0].TenantIDs) != 2 {
			t.Errorf("expected 2 tenants in group, got %d", len(groups[0].TenantIDs))
		}
	})
}
