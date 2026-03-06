package db

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/f46b83ee9/heimdall/opa"
	"go.opentelemetry.io/otel/attribute"
)

// BundleData is the OPA data document served to OPA.
type BundleData struct {
	Tenants  map[string]interface{} `json:"tenants"`
	Policies []BundlePolicy         `json:"policies"`
}

// BundlePolicy is the policy representation in the OPA bundle.
type BundlePolicy struct {
	ID       uint        `json:"id"`
	Name     string      `json:"name"`
	Effect   string      `json:"effect"`
	Subjects []Subject   `json:"subjects"`
	Actions  []string    `json:"actions"`
	Scope    PolicyScope `json:"scope"`
	Filters  []string    `json:"filters"`
}

// BundleServer manages the OPA bundle lifecycle.
type BundleServer struct {
	store      *Store
	mu         sync.RWMutex
	revision   string
	bundleData []byte
	updatedAt  time.Time
	metrics    Metrics
}

// Metrics is a subset interface to avoid circular dependencies if needed,
// but since both are in the same or related packages, we can use the concrete type
// or a simplified interface. Here we use the concrete type via a local alias or interface if needed.
// For now, we'll assume we can pass the Metrics struct from handler.
type Metrics interface {
	RecordBundleRebuild(ctx context.Context)
	UpdateActiveTenants(ctx context.Context, count int64)
}

// NewBundleServer creates a new BundleServer that serves bundles from memory.
func NewBundleServer(store *Store, metrics Metrics) *BundleServer {
	return &BundleServer{
		store:   store,
		metrics: metrics,
	}
}

// Rebuild atomically rebuilds the OPA bundle from the current database state.
// It is mutex-protected, idempotent, and context-aware.
func (bs *BundleServer) Rebuild(ctx context.Context) (err error) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	// panic safety (Invariant #134)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during bundle rebuild: %v", r)
			slog.ErrorContext(ctx, "panic during bundle rebuild", "error", err, "stack", string(debug.Stack()))
		}
	}()

	// Fetch all tenants
	tenants, fetchErr := bs.store.ListTenants(ctx)
	if fetchErr != nil {
		return fmt.Errorf("fetching tenants for bundle: %w", fetchErr)
	}

	// Fetch all policies
	policies, fetchErr := bs.store.ListPolicies(ctx)
	if fetchErr != nil {
		return fmt.Errorf("fetching policies for bundle: %w", fetchErr)
	}

	// Build data document
	tenantMap := make(map[string]interface{})
	for _, t := range tenants {
		tenantMap[t.ID] = map[string]interface{}{
			"id":   t.ID,
			"name": t.Name,
		}
	}

	bundlePolicies := make([]BundlePolicy, 0, len(policies))
	for _, p := range policies {
		bp := BundlePolicy{
			ID:     p.ID,
			Name:   p.Name,
			Effect: p.Effect,
		}

		// Unmarshal all JSON fields in one pass
		fields := []struct {
			name string
			src  json.RawMessage
			dst  interface{}
		}{
			{"subjects", p.Subjects.RawMessage(), &bp.Subjects},
			{"actions", p.Actions.RawMessage(), &bp.Actions},
			{"scope", p.Scope.RawMessage(), &bp.Scope},
			{"filters", p.Filters.RawMessage(), &bp.Filters},
		}
		for _, f := range fields {
			if unmarshalErr := json.Unmarshal(f.src, f.dst); unmarshalErr != nil {
				return fmt.Errorf("unmarshaling policy %d %s: %w", p.ID, f.name, unmarshalErr)
			}
		}

		bundlePolicies = append(bundlePolicies, bp)
	}

	data := BundleData{
		Tenants:  tenantMap,
		Policies: bundlePolicies,
	}

	// Serialize
	dataJSON, marshalErr := json.Marshal(data)
	if marshalErr != nil {
		return fmt.Errorf("marshaling bundle data: %w", marshalErr)
	}

	// Compute revision
	hash := sha256.Sum256(dataJSON)
	revision := fmt.Sprintf("%x", hash[:8])

	// Atomic swap and trace ONLY if revision changed (reduce span and log noise)
	if revision != bs.revision {
		ctx, span := tracer.Start(ctx, "bundle.Rebuild")
		defer span.End()

		span.SetAttributes(
			attribute.Int("bundle.tenants", len(tenants)),
			attribute.Int("bundle.policies", len(policies)),
			attribute.String("bundle.revision", revision),
		)

		// Build the bundle in-memory
		var buf bytes.Buffer
		if writeErr := writeBundleMem(&buf, dataJSON, opa.AuthzRego, revision); writeErr != nil {
			span.RecordError(writeErr)
			return fmt.Errorf("writing in-memory bundle: %w", writeErr)
		}

		bs.bundleData = buf.Bytes()
		bs.revision = revision
		bs.updatedAt = time.Now()

		slog.InfoContext(ctx, "bundle rebuilt",
			"revision", revision,
			"tenants", len(tenants),
			"policies", len(policies),
		)

		if bs.metrics != nil {
			bs.metrics.RecordBundleRebuild(ctx)
			bs.metrics.UpdateActiveTenants(ctx, int64(len(tenants)))
		}
	}

	return nil
}

// writeBundleMem writes an OPA bundle tar.gz into a memory buffer.
func writeBundleMem(buf *bytes.Buffer, dataJSON []byte, regoContent []byte, revision string) error {
	gw := gzip.NewWriter(buf)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	now := time.Now()

	// Helper to write a file to the tarball
	writeFile := func(name string, content []byte) error {
		hdr := &tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(content)),
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
		return nil
	}

	// Write /proxy/data.json
	if err := writeFile("proxy/data.json", dataJSON); err != nil {
		return err
	}

	// Write /proxy/authz.rego
	if len(regoContent) > 0 {
		if err := writeFile("proxy/authz.rego", regoContent); err != nil {
			return err
		}
	}

	// Write .manifest
	manifest := map[string]interface{}{
		"revision": revision,
		"roots":    []string{"proxy"},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := writeFile(".manifest", manifestJSON); err != nil {
		return err
	}

	return nil
}

// ServeHTTP serves the OPA bundle file from memory.
func (bs *BundleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bs.mu.RLock()
	data := bs.bundleData
	rev := bs.revision
	updated := bs.updatedAt
	bs.mu.RUnlock()

	if len(data) == 0 {
		http.Error(w, "bundle not available", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("ETag", fmt.Sprintf("\"%s\"", rev))
	http.ServeContent(w, r, "bundle.tar.gz", updated, bytes.NewReader(data))
}

// StartPolling starts a background goroutine that periodically rebuilds the bundle.
// This is used for SQLite which doesn't support LISTEN/NOTIFY.
func (bs *BundleServer) StartPolling(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := bs.Rebuild(ctx); err != nil {
					slog.ErrorContext(ctx, "bundle polling rebuild failed", "error", err)
				}
			}
		}
	}()
}

// StartListenNotify starts listening for PostgreSQL NOTIFY events to trigger rebuilds.
// NOTE: database/sql does not support async notifications natively.
// For production use, replace with github.com/lib/pq or pgx listener.
// This implementation falls back to polling on the same interval.
func (bs *BundleServer) StartListenNotify(ctx context.Context, interval time.Duration) error {
	sqlDB, err := bs.store.DB().DB()
	if err != nil {
		return fmt.Errorf("getting underlying sql.DB: %w", err)
	}

	// Verify we can execute LISTEN (validates Postgres connectivity)
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("getting DB connection for LISTEN: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "LISTEN heimdall_changes"); err != nil {
		conn.Close()
		return fmt.Errorf("LISTEN failed: %w", err)
	}
	conn.Close()

	slog.InfoContext(ctx, "LISTEN/NOTIFY verified, falling back to polling (stdlib limitation)")

	// Fall back to polling since database/sql cannot receive async notifications.
	// The caller (serve.go) would need pgx/lib-pq for true push-based change detection.
	bs.StartPolling(ctx, interval)

	return nil
}
