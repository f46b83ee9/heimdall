package opa_test

import (
	"context"
	"testing"

	"github.com/f46b83ee9/heimdall/opa"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

func TestAuthzRego(t *testing.T) {
	ctx := context.Background()

	// We compile the embedded Rego policy per test to supply different data stores

	tests := []struct {
		name          string
		input         map[string]interface{}
		data          map[string]interface{}
		wantAllow     bool
		wantFilterLen int
	}{
		{
			name: "admin wildcard access",
			input: map[string]interface{}{
				"user_id":   "admin",
				"groups":    []string{"admins"},
				"action":    "read",
				"resource":  "metrics",
				"tenant_id": "acme",
			},
			data: map[string]interface{}{
				"proxy": map[string]interface{}{
					"tenants": map[string]interface{}{
						"acme": map[string]interface{}{},
					},
					"policies": []map[string]interface{}{
						{
							"effect":   "allow",
							"subjects": []map[string]interface{}{{"type": "group", "id": "admins"}},
							"actions":  []string{"*"},
							"scope":    map[string]interface{}{"tenants": []string{"*"}, "resources": []string{"metrics"}},
							"filters":  []string{},
						},
					},
				},
			},
			wantAllow:     true,
			wantFilterLen: 0,
		},
		{
			name: "user explicit deny overrides allow",
			input: map[string]interface{}{
				"user_id":   "bob",
				"groups":    []string{"devs"},
				"action":    "read",
				"resource":  "metrics",
				"tenant_id": "acme",
			},
			data: map[string]interface{}{
				"proxy": map[string]interface{}{
					"tenants": map[string]interface{}{
						"acme": map[string]interface{}{},
					},
					"policies": []map[string]interface{}{
						{
							"effect":   "allow",
							"subjects": []map[string]interface{}{{"type": "group", "id": "devs"}},
							"actions":  []string{"read"},
							"scope":    map[string]interface{}{"tenants": []string{"acme"}, "resources": []string{"metrics"}},
							"filters":  []string{"env=\"dev\""},
						},
						{
							"effect":   "deny",
							"subjects": []map[string]interface{}{{"type": "user", "id": "bob"}},
							"actions":  []string{"read"},
							"scope":    map[string]interface{}{"tenants": []string{"acme"}, "resources": []string{"metrics"}},
							"filters":  []string{},
						},
					},
				},
			},
			wantAllow:     false,
			wantFilterLen: 0,
		},
		{
			name: "user allowed with filters",
			input: map[string]interface{}{
				"user_id":   "alice",
				"groups":    []string{"devs"},
				"action":    "read",
				"resource":  "metrics",
				"tenant_id": "acme",
			},
			data: map[string]interface{}{
				"proxy": map[string]interface{}{
					"tenants": map[string]interface{}{
						"acme": map[string]interface{}{},
					},
					"policies": []map[string]interface{}{
						{
							"effect":   "allow",
							"subjects": []map[string]interface{}{{"type": "user", "id": "alice"}},
							"actions":  []string{"read"},
							"scope":    map[string]interface{}{"tenants": []string{"acme"}, "resources": []string{"metrics"}},
							"filters":  []string{"env=\"prod\""},
						},
					},
				},
			},
			wantAllow:     true,
			wantFilterLen: 1, // "env=\"prod\""
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []func(*rego.Rego){
				rego.Query("result = data.proxy.authz"),
				rego.Module("authz.rego", string(opa.AuthzRego)),
			}

			if tt.data != nil {
				options = append(options, rego.Store(inmem.NewFromObject(tt.data)))
			}

			query, err := rego.New(options...).PrepareForEval(ctx)
			if err != nil {
				t.Fatalf("failed to compile rego policy: %v", err)
			}

			rs, err := query.Eval(ctx, rego.EvalInput(tt.input))
			if err != nil {
				t.Fatalf("eval error: %v", err)
			}

			if len(rs) == 0 {
				t.Fatalf("no results returned")
			}

			resultMap := rs[0].Bindings["result"].(map[string]interface{})

			allow, ok := resultMap["allow"].(bool)
			if !ok {
				t.Fatalf("result missing allow boolean")
			}
			if allow != tt.wantAllow {
				t.Errorf("got allow=%v, want %v", allow, tt.wantAllow)
			}

			if allow {
				filters, ok := resultMap["effective_filters"].([]interface{})
				if !ok && tt.wantFilterLen > 0 {
					t.Fatalf("result missing effective_filters array")
				}
				if len(filters) != tt.wantFilterLen {
					t.Errorf("got %d filters, want %d", len(filters), tt.wantFilterLen)
				}
			}
		})
	}
}
