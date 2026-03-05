package db

import (
	"context"
	"encoding/json"
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

func TestJSONField_Scan_String(t *testing.T) {
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
}

func TestJSONField_Scan_Bytes(t *testing.T) {
	var f JSONField
	err := f.Scan([]byte(`["a","b"]`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var arr []string
	if err := json.Unmarshal(f.RawMessage(), &arr); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if len(arr) != 2 || arr[0] != "a" {
		t.Errorf("expected [a b], got %v", arr)
	}
}

func TestJSONField_Scan_Nil(t *testing.T) {
	var f JSONField
	err := f.Scan(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Scan(nil) produces JSON "null"
	if string(f.RawMessage()) != "null" {
		t.Errorf("expected 'null', got %s", string(f.RawMessage()))
	}
}

func TestJSONField_Value(t *testing.T) {
	f := JSONField(`{"key": "val"}`)
	val, err := f.Value()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := val.(string)
	if !ok {
		t.Fatalf("expected string, got %T", val)
	}
	if s != `{"key": "val"}` {
		t.Errorf("unexpected value: %s", s)
	}
}

func TestJSONField_MarshalJSON(t *testing.T) {
	f := JSONField(`["x","y"]`)
	data, err := f.MarshalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `["x","y"]` {
		t.Errorf("expected [\"x\",\"y\"], got %s", data)
	}
}

func TestJSONField_UnmarshalJSON(t *testing.T) {
	var f JSONField
	err := f.UnmarshalJSON([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(f.RawMessage()) != `{"a":1}` {
		t.Errorf("expected {\"a\":1}, got %s", f.RawMessage())
	}
}

// --- Tenant CRUD tests ---

func TestCreateAndGetTenant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	tenant := &Tenant{ID: "acme", Name: "Acme Corp"}
	if err := store.CreateTenant(ctx, tenant); err != nil {
		t.Fatalf("creating tenant: %v", err)
	}

	got, err := store.GetTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("getting tenant: %v", err)
	}
	if got.Name != "Acme Corp" {
		t.Errorf("expected 'Acme Corp', got %q", got.Name)
	}
}

func TestListTenants(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	store.CreateTenant(ctx, &Tenant{ID: "a", Name: "A"})
	store.CreateTenant(ctx, &Tenant{ID: "b", Name: "B"})

	tenants, err := store.ListTenants(ctx)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(tenants) != 2 {
		t.Errorf("expected 2 tenants, got %d", len(tenants))
	}
}

func TestDeleteTenant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	store.CreateTenant(ctx, &Tenant{ID: "del", Name: "Delete Me"})

	if err := store.DeleteTenant(ctx, "del"); err != nil {
		t.Fatalf("deleting: %v", err)
	}

	_, err := store.GetTenant(ctx, "del")
	if err == nil {
		t.Fatal("expected error for deleted tenant")
	}
}

func TestGetTenant_NotFound(t *testing.T) {
	store := testStore(t)
	_, err := store.GetTenant(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent tenant")
	}
}

func TestCreateDuplicateTenant(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	store.CreateTenant(ctx, &Tenant{ID: "dup", Name: "First"})
	err := store.CreateTenant(ctx, &Tenant{ID: "dup", Name: "Second"})
	if err == nil {
		t.Fatal("expected error for duplicate tenant")
	}
}

// --- Policy CRUD tests ---

func TestCreateAndGetPolicy(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	policy := &Policy{
		Name:     "test-policy",
		Effect:   "allow",
		Subjects: JSONField(`[{"type":"user","id":"alice"}]`),
		Actions:  JSONField(`["read"]`),
		Scope:    JSONField(`{"tenants":["acme"],"resources":["metrics"]}`),
		Filters:  JSONField(`["env=\"prod\""]`),
	}

	if err := store.CreatePolicy(ctx, policy); err != nil {
		t.Fatalf("creating policy: %v", err)
	}

	got, err := store.GetPolicy(ctx, policy.ID)
	if err != nil {
		t.Fatalf("getting policy: %v", err)
	}
	if got.Name != "test-policy" {
		t.Errorf("expected 'test-policy', got %q", got.Name)
	}
	if got.Effect != "allow" {
		t.Errorf("expected 'allow', got %q", got.Effect)
	}
}

func TestListPolicies(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	store.CreatePolicy(ctx, &Policy{
		Name: "p1", Effect: "allow",
		Subjects: JSONField(`[{"type":"user","id":"alice"}]`),
		Actions:  JSONField(`["read"]`),
		Scope:    JSONField(`{"tenants":["acme"]}`),
		Filters:  JSONField(`[]`),
	})
	store.CreatePolicy(ctx, &Policy{
		Name: "p2", Effect: "deny",
		Subjects: JSONField(`[{"type":"user","id":"bob"}]`),
		Actions:  JSONField(`["read"]`),
		Scope:    JSONField(`{"tenants":["acme"]}`),
		Filters:  JSONField(`[]`),
	})

	policies, err := store.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}
}

func TestDeletePolicy(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	policy := &Policy{
		Name: "to-delete", Effect: "allow",
		Subjects: JSONField(`[{"type":"user","id":"alice"}]`),
		Actions:  JSONField(`["read"]`),
		Scope:    JSONField(`{"tenants":["acme"]}`),
		Filters:  JSONField(`[]`),
	}
	if err := store.CreatePolicy(ctx, policy); err != nil {
		t.Fatalf("creating: %v", err)
	}

	if policy.ID == 0 {
		t.Fatal("expected non-zero policy ID after create")
	}

	if err := store.DeletePolicy(ctx, policy.ID); err != nil {
		t.Fatalf("deleting: %v", err)
	}

	_, err := store.GetPolicy(ctx, policy.ID)
	if err == nil {
		t.Fatal("expected error for deleted policy")
	}
}

func TestGetPolicy_NotFound(t *testing.T) {
	store := testStore(t)
	_, err := store.GetPolicy(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error for nonexistent policy")
	}
}

func TestDeleteNonexistentTenant(t *testing.T) {
	store := testStore(t)
	err := store.DeleteTenant(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent tenant")
	}
}
