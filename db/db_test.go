package db

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testStore creates an in-memory SQLite store for testing.
func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	store := NewStore(db)
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	return store
}

// --- JSONField tests ---

// --- Consistency Invariants: JSONField Logic ---

func TestConsistency_DB_JSONField_Scan_Success(t *testing.T) {
	var f JSONField
	err := f.Scan(`{"key": "value"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(f.RawMessage(), &m); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if m["key"] != "value" {
		t.Errorf("expected 'value', got %q", m["key"])
	}

	// Bytes scan
	var f2 JSONField
	err = f2.Scan([]byte(`["a","b"]`))
	if err != nil {
		t.Fatal(err)
	}
	if string(f2.RawMessage()) != `["a","b"]` {
		t.Errorf("got %s", f2.RawMessage())
	}
}

func TestConsistency_DB_JSONField_ValueAndMarshal(t *testing.T) {
	t.Run("Value implementation", func(t *testing.T) {
		f := JSONField(`{"key": "val"}`)
		val, err := f.Value()
		if err != nil {
			t.Fatal(err)
		}
		if val.(string) != `{"key": "val"}` {
			t.Errorf("got %v", val)
		}
	})

	t.Run("Marshal/Unmarshal success", func(t *testing.T) {
		var f JSONField
		json.Unmarshal([]byte(`{"a":1}`), &f)
		data, _ := json.Marshal(f)
		if string(data) != `{"a":1}` {
			t.Errorf("got %s", data)
		}
	})
}

func TestConsistency_DB_JSONField_ErrorPaths(t *testing.T) {
	t.Run("Scan unsupported type", func(t *testing.T) {
		var f JSONField
		if err := f.Scan(123); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Unmarshal into nil field", func(t *testing.T) {
		var f *JSONField
		if err := f.UnmarshalJSON([]byte(`{}`)); err == nil {
			t.Error("expected error")
		}
	})
}

// --- Consistency Invariants: Tenant CRUD ---

func TestConsistency_DB_Tenant_CRUD(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	t.Run("Create and Get success", func(t *testing.T) {
		tenant := &Tenant{ID: "acme", Name: "Acme Corp"}
		if err := store.CreateTenant(ctx, tenant); err != nil {
			t.Fatal(err)
		}
		got, _ := store.GetTenant(ctx, "acme")
		if got.Name != "Acme Corp" {
			t.Errorf("got %s", got.Name)
		}
	})

	t.Run("List multiple tenants", func(t *testing.T) {
		store.CreateTenant(ctx, &Tenant{ID: "b", Name: "B"})
		tenants, _ := store.ListTenants(ctx)
		if len(tenants) < 2 {
			t.Errorf("expected at least 2, got %d", len(tenants))
		}
	})

	t.Run("Delete success", func(t *testing.T) {
		store.DeleteTenant(ctx, "acme")
		_, err := store.GetTenant(ctx, "acme")
		if err == nil {
			t.Error("expected not found")
		}
	})

	t.Run("Duplicate ID returns error", func(t *testing.T) {
		store.CreateTenant(ctx, &Tenant{ID: "dup", Name: "1"})
		err := store.CreateTenant(ctx, &Tenant{ID: "dup", Name: "2"})
		if err == nil {
			t.Error("expected error")
		}
	})
}

// --- Consistency Invariants: Policy CRUD ---

func TestConsistency_DB_Policy_CRUD(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	policy := &Policy{
		Name:     "p1",
		Effect:   "allow",
		Subjects: JSONField(`[{"type":"user","id":"alice"}]`),
		Actions:  JSONField(`["read"]`),
		Scope:    JSONField(`{"tenants":["acme"],"resources":["metrics"]}`),
		Filters:  JSONField(`[]`),
	}

	t.Run("Create and Get success", func(t *testing.T) {
		if err := store.CreatePolicy(ctx, policy); err != nil {
			t.Fatal(err)
		}
		got, _ := store.GetPolicy(ctx, policy.ID)
		if got.Name != "p1" {
			t.Errorf("got %s", got.Name)
		}
	})

	t.Run("List and Delete", func(t *testing.T) {
		policies, _ := store.ListPolicies(ctx)
		if len(policies) != 1 {
			t.Errorf("got %d", len(policies))
		}
		store.DeletePolicy(ctx, policy.ID)
		_, err := store.GetPolicy(ctx, policy.ID)
		if err == nil {
			t.Error("expected not found")
		}
	})
}

// protects: Invariant[Consistency] - Policies must be valid before persistence.
func TestPolicy_DB_Validation_Exhaustive(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		policy  *Policy
		wantErr string
	}{
		{"Empty effect", &Policy{Name: "p", Effect: ""}, "effect must be 'allow' or 'deny'"},
		{"Invalid subject", &Policy{Name: "p", Effect: "allow", Subjects: JSONField(`[{"type":"robot"}]`)}, "subject type must be 'user' or 'group'"},
		{"Empty scope", &Policy{Name: "p", Effect: "allow", Subjects: JSONField(`[{"type":"user","id":"a"}]`), Actions: JSONField(`["read"]`), Scope: JSONField(`{}`)}, "scope.tenants must not be empty"},
		{"Invalid resource", &Policy{Name: "p", Effect: "allow", Subjects: JSONField(`[{"type":"user","id":"a"}]`), Actions: JSONField(`["read"]`), Scope: JSONField(`{"tenants":["t1"],"resources":["bad"]}`)}, "resource must be 'metrics'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.CreatePolicy(ctx, tt.policy)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error %q, got %v", tt.wantErr, err)
			}
		})
	}
}

// --- Availability Invariants: Database Failures ---

func TestAvailability_DB_ConnectionFailures(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	sqlDB, _ := store.db.DB()
	sqlDB.Close()

	t.Run("CreatePolicy fails safely", func(t *testing.T) {
		p := &Policy{Name: "p", Effect: "allow", Subjects: JSONField(`[{"type":"user","id":"a"}]`), Actions: JSONField(`["read"]`), Scope: JSONField(`{"tenants":["t1"],"resources":["metrics"]}`)}
		if err := store.CreatePolicy(ctx, p); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Delete operations fall back gracefully", func(t *testing.T) {
		if err := store.DeletePolicy(ctx, 1); err == nil {
			t.Error("expected error")
		}
		if err := store.DeleteTenant(ctx, "t1"); err == nil {
			t.Error("expected error")
		}
	})
}
