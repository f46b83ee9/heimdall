// Package db provides database models, initialization, and CRUD operations
// for Heimdall's tenant and policy data.
package db

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"gorm.io/gorm"
)

// JSONField is a custom type that properly implements sql.Scanner and driver.Valuer
// for storing JSON data in both Postgres and SQLite.
type JSONField json.RawMessage

// Scan implements the sql.Scanner interface.
func (j *JSONField) Scan(value interface{}) error {
	if value == nil {
		*j = JSONField("null")
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*j = JSONField(v)
		return nil
	case string:
		*j = JSONField(v)
		return nil
	default:
		return fmt.Errorf("unsupported type for JSONField: %T", value)
	}
}

// Value implements the driver.Valuer interface.
func (j JSONField) Value() (driver.Value, error) {
	if len(j) == 0 {
		return "null", nil
	}
	return string(j), nil
}

// MarshalJSON implements json.Marshaler.
func (j JSONField) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return json.RawMessage(j).MarshalJSON()
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *JSONField) UnmarshalJSON(data []byte) error {
	if j == nil {
		return errors.New("JSONField: UnmarshalJSON on nil pointer")
	}
	*j = append((*j)[0:0], data...)
	return nil
}

// RawMessage returns the underlying json.RawMessage.
func (j JSONField) RawMessage() json.RawMessage {
	return json.RawMessage(j)
}

// Tenant represents a Mimir tenant registered in Heimdall.
type Tenant struct {
	ID        string    `gorm:"primaryKey;size:255" json:"id"`
	Name      string    `gorm:"not null;size:255" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Subject represents a policy subject (user or group).
type Subject struct {
	Type string `json:"type" validate:"required,oneof=user group"`
	ID   string `json:"id" validate:"required"`
}

// PolicyScope defines the scope of a policy.
type PolicyScope struct {
	Tenants   []string `json:"tenants"`
	Resources []string `json:"resources"`
}

// Policy represents an access control policy stored in the database.
type Policy struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	Name      string    `gorm:"not null;uniqueIndex;size:255" json:"name"`
	Effect    string    `gorm:"not null;size:10" json:"effect"`
	Subjects  JSONField `gorm:"type:text;not null" json:"subjects"`
	Actions   JSONField `gorm:"type:text;not null" json:"actions"`
	Scope     JSONField `gorm:"type:text;not null" json:"scope"`
	Filters   JSONField `gorm:"type:text;not null" json:"filters"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store provides database operations for tenants and policies.
type Store struct {
	db *gorm.DB
}

// NewStore creates a new Store with the given GORM database connection.
func NewStore(db *gorm.DB) *Store {
	return &Store{db: db}
}

// DB returns the underlying GORM database connection.
func (s *Store) DB() *gorm.DB {
	return s.db
}

// Migrate runs AutoMigrate for all Heimdall models.
func (s *Store) Migrate() error {
	return s.db.AutoMigrate(&Tenant{}, &Policy{})
}

// --- Tenant CRUD ---

// CreateTenant creates a new tenant.
func (s *Store) CreateTenant(ctx context.Context, tenant *Tenant) error {
	ctx, span := tracer.Start(ctx, "db.CreateTenant")
	defer span.End()

	span.SetAttributes(attribute.String("tenant.id", tenant.ID))

	if err := s.db.WithContext(ctx).Create(tenant).Error; err != nil {
		span.RecordError(err)
		return fmt.Errorf("creating tenant: %w", err)
	}

	slog.InfoContext(ctx, "tenant created", "tenant_id", tenant.ID)
	return nil
}

// GetTenant retrieves a tenant by ID.
func (s *Store) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	ctx, span := tracer.Start(ctx, "db.GetTenant")
	defer span.End()

	var tenant Tenant
	if err := s.db.WithContext(ctx).First(&tenant, "id = ?", id).Error; err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("getting tenant %s: %w", id, err)
	}
	return &tenant, nil
}

// ListTenants returns all tenants.
func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	ctx, span := tracer.Start(ctx, "db.ListTenants")
	defer span.End()

	var tenants []Tenant
	if err := s.db.WithContext(ctx).Find(&tenants).Error; err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	return tenants, nil
}

// DeleteTenant deletes a tenant by ID.
func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	ctx, span := tracer.Start(ctx, "db.DeleteTenant")
	defer span.End()

	result := s.db.WithContext(ctx).Delete(&Tenant{}, "id = ?", id)
	if result.Error != nil {
		span.RecordError(result.Error)
		return fmt.Errorf("deleting tenant %s: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("tenant %s not found", id)
	}

	slog.InfoContext(ctx, "tenant deleted", "tenant_id", id)
	return nil
}

// --- Policy CRUD ---

// CreatePolicy creates a new policy after validation.
func (s *Store) CreatePolicy(ctx context.Context, policy *Policy) error {
	ctx, span := tracer.Start(ctx, "db.CreatePolicy")
	defer span.End()

	if err := validatePolicy(policy); err != nil {
		span.RecordError(err)
		return fmt.Errorf("policy validation failed: %w", err)
	}

	if err := s.db.WithContext(ctx).Create(policy).Error; err != nil {
		span.RecordError(err)
		return fmt.Errorf("creating policy: %w", err)
	}

	slog.InfoContext(ctx, "policy created", "policy_id", policy.ID, "policy_name", policy.Name)
	return nil
}

// GetPolicy retrieves a policy by ID.
func (s *Store) GetPolicy(ctx context.Context, id uint) (*Policy, error) {
	ctx, span := tracer.Start(ctx, "db.GetPolicy")
	defer span.End()

	var policy Policy
	if err := s.db.WithContext(ctx).First(&policy, id).Error; err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("getting policy %d: %w", id, err)
	}
	return &policy, nil
}

// ListPolicies returns all policies.
func (s *Store) ListPolicies(ctx context.Context) ([]Policy, error) {
	ctx, span := tracer.Start(ctx, "db.ListPolicies")
	defer span.End()

	var policies []Policy
	if err := s.db.WithContext(ctx).Find(&policies).Error; err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("listing policies: %w", err)
	}
	return policies, nil
}

// DeletePolicy deletes a policy by ID.
func (s *Store) DeletePolicy(ctx context.Context, id uint) error {
	ctx, span := tracer.Start(ctx, "db.DeletePolicy")
	defer span.End()

	result := s.db.WithContext(ctx).Delete(&Policy{}, id)
	if result.Error != nil {
		span.RecordError(result.Error)
		return fmt.Errorf("deleting policy %d: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("policy %d not found", id)
	}

	slog.InfoContext(ctx, "policy deleted", "policy_id", id)
	return nil
}

// validatePolicy performs structural validation on a policy.
func validatePolicy(p *Policy) error {
	// Validate effect
	if p.Effect != "allow" && p.Effect != "deny" {
		return fmt.Errorf("effect must be 'allow' or 'deny', got %q", p.Effect)
	}

	// Validate subjects JSON
	var subjects []Subject
	if err := json.Unmarshal(p.Subjects.RawMessage(), &subjects); err != nil {
		return fmt.Errorf("invalid subjects JSON: %w", err)
	}
	if len(subjects) == 0 {
		return fmt.Errorf("subjects must not be empty")
	}
	for _, s := range subjects {
		if s.Type != "user" && s.Type != "group" {
			return fmt.Errorf("subject type must be 'user' or 'group', got %q", s.Type)
		}
		if s.ID == "" {
			return fmt.Errorf("subject id must not be empty")
		}
	}

	// Validate actions JSON
	var actions []string
	if err := json.Unmarshal(p.Actions.RawMessage(), &actions); err != nil {
		return fmt.Errorf("invalid actions JSON: %w", err)
	}
	if len(actions) == 0 {
		return fmt.Errorf("actions must not be empty")
	}

	// Validate scope JSON
	var scope PolicyScope
	if err := json.Unmarshal(p.Scope.RawMessage(), &scope); err != nil {
		return fmt.Errorf("invalid scope JSON: %w", err)
	}
	if len(scope.Tenants) == 0 {
		return fmt.Errorf("scope.tenants must not be empty")
	}

	// Validate filters JSON (must be valid JSON array)
	var filters []string
	if err := json.Unmarshal(p.Filters.RawMessage(), &filters); err != nil {
		return fmt.Errorf("invalid filters JSON: %w", err)
	}

	return nil
}
