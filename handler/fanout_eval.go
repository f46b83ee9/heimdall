package handler

import (
	"context"
	"fmt"
	"sort"

	"go.opentelemetry.io/otel/attribute"
)

// EvaluateTenants runs OPA authorization for each tenant and returns allowed tenants
// grouped by their canonical filter signature for native federation.
func (fe *FanOutEngine) EvaluateTenants(ctx context.Context, identity *Identity, tenantIDs []string, action Action, resource string) ([]filterGroup, error) {
	ctx, span := tracer.Start(ctx, "fanout.EvaluateTenants")
	defer span.End()

	span.SetAttributes(
		attribute.Int("fanout.requested_tenants", len(tenantIDs)),
		attribute.String("fanout.action", string(action)),
	)

	// Evaluate OPA once per tenant (invariant #1)
	results := make([]tenantResult, 0, len(tenantIDs))
	for _, tid := range tenantIDs {
		opaInput := OPAInput{
			UserID:   identity.UserID,
			Groups:   identity.Groups,
			TenantID: tid,
			Resource: resource,
			Action:   action,
		}

		opaResult, err := fe.opaClient.Evaluate(ctx, opaInput)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("OPA evaluation for tenant %s: %w", tid, err)
		}

		results = append(results, tenantResult{
			TenantID:         tid,
			Allow:            opaResult.Allow,
			EffectiveFilters: opaResult.EffectiveFilters,
		})
	}

	// Drop tenants with allow == false
	allowed := make([]tenantResult, 0, len(results))
	for _, r := range results {
		if r.Allow {
			allowed = append(allowed, r)
		}
	}

	// ALL DENIED edge case → return empty (caller will 403)
	if len(allowed) == 0 {
		span.SetAttributes(attribute.Bool("fanout.all_denied", true))
		return nil, nil
	}

	// Group tenants by canonical filter signature for native federation
	groupMap := make(map[string]*filterGroup)
	for _, r := range allowed {
		key := NormalizeFilters(r.EffectiveFilters)
		if g, exists := groupMap[key]; exists {
			g.TenantIDs = append(g.TenantIDs, r.TenantID)
		} else {
			groupMap[key] = &filterGroup{
				FilterKey: key,
				TenantIDs: []string{r.TenantID},
				Filters:   r.EffectiveFilters,
			}
		}
	}

	// Convert to sorted slice for deterministic ordering
	groups := make([]filterGroup, 0, len(groupMap))
	for _, g := range groupMap {
		// Sort tenant IDs lexicographically within each group
		sort.Strings(g.TenantIDs)

		// Parse filters into matchers
		matchers, err := ParseFilters(g.Filters)
		if err != nil {
			span.RecordError(err)
			return nil, fmt.Errorf("parsing filters %v: %w", g.Filters, err)
		}
		g.Matchers = matchers

		groups = append(groups, *g)
	}

	// Sort groups by filter key for deterministic dispatch
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].FilterKey < groups[j].FilterKey
	})

	span.SetAttributes(
		attribute.Int("fanout.allowed_tenants", len(allowed)),
		attribute.Int("fanout.groups", len(groups)),
	)

	return groups, nil
}
