package db_test

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/db"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupStore creates an in-memory SQLite store for testing.
func setupStore(t *testing.T) *db.Store {
	gormDB, err := gorm.Open(sqlite.Open("file:memdb"+t.Name()+"?mode=memory&cache=private"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open memory db: %v", err)
	}
	s := db.NewStore(gormDB)
	if err := gormDB.AutoMigrate(&db.Tenant{}, &db.Policy{}); err != nil {
		t.Fatalf("failed to migrate memory db: %v", err)
	}
	return s
}

func parseJSON(t *testing.T, s string) db.JSONField {
	t.Helper()
	var j json.RawMessage
	if err := json.Unmarshal([]byte(s), &j); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	return db.JSONField(j)
}

func TestBundleServer_ServeHTTP_EmptyMemory(t *testing.T) {
	store := setupStore(t)
	bs := db.NewBundleServer(store, nil) // passing nil is fine for now as it's optional

	req := httptest.NewRequest(http.MethodGet, "/bundles/bundle.tar.gz", nil)
	w := httptest.NewRecorder()

	bs.ServeHTTP(w, req)

	// Since Rebuild wasn't called, memory bundleData should be empty
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 for non-existent bundle, got %d", w.Code)
	}
}

func TestBundleServer_RebuildAndServe(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	bs := db.NewBundleServer(store, nil)

	// Insert test data
	err := store.CreateTenant(ctx, &db.Tenant{ID: "t1", Name: "Tenant 1"})
	if err != nil {
		t.Fatal(err)
	}
	p := &db.Policy{
		Name:     "allow-all",
		Effect:   "allow",
		Subjects: parseJSON(t, `[{"type":"user","id":"alice"}]`),
		Actions:  parseJSON(t, `["read"]`),
		Scope:    parseJSON(t, `{"tenants":["t1"],"resources":["metrics"]}`),
		Filters:  parseJSON(t, `[]`),
	}
	if err := store.CreatePolicy(ctx, p); err != nil {
		t.Fatal(err)
	}

	// Trigger rebuild
	err = bs.Rebuild(ctx)
	if err != nil {
		t.Fatalf("Rebuild failed: %v", err)
	}

	// Serve HTTP should now return 200 and the correct exact gzip bytes from memory
	req := httptest.NewRequest(http.MethodGet, "/bundles", nil)
	w := httptest.NewRecorder()
	bs.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("expected application/gzip, got %s", w.Header().Get("Content-Type"))
	}
	if w.Header().Get("ETag") == "" {
		t.Fatal("expected ETag header to be set")
	}

	// Decompress memory buffered tarball
	gz, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatalf("failed to decode gzip response: %v", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	filesFound := map[string]bool{}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar reading error: %v", err)
		}
		filesFound[header.Name] = true

		if header.Name == "proxy/data.json" {
			var bd db.BundleData
			if err := json.NewDecoder(tr).Decode(&bd); err != nil {
				t.Fatalf("failed to parse JSON from proxy/data.json: %v", err)
			}
			if len(bd.Tenants) != 1 {
				t.Fatalf("expected 1 tenant in bundle, got %d", len(bd.Tenants))
			}
			if len(bd.Policies) != 1 {
				t.Fatalf("expected 1 policy in bundle, got %d", len(bd.Policies))
			}
			if bd.Policies[0].Name != "allow-all" {
				t.Fatalf("expected policy 'allow-all', got '%s'", bd.Policies[0].Name)
			}
		}
	}

	if !filesFound["proxy/data.json"] {
		t.Fatal("proxy/data.json not found in tarball")
	}
	if !filesFound["proxy/authz.rego"] {
		t.Fatal("proxy/authz.rego not found in tarball")
	}
	if !filesFound[".manifest"] {
		t.Fatal(".manifest not found in tarball")
	}
}

func TestBundleServer_StartPolling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := setupStore(t)
	bs := db.NewBundleServer(store, nil)

	// Start polling with very short interval
	go bs.StartPolling(ctx, 100*time.Millisecond)

	// Wait for at least one poll
	time.Sleep(250 * time.Millisecond)
}

func TestBundleServer_StartListenNotify_Exhaustive(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := setupStore(t)
	bs := db.NewBundleServer(store, nil)

	// SQLite doesn't support LISTEN/NOTIFY, so it should exit early with a log (or just continue if loop is started)
	// Actually it checks if driver is postgres.
	bs.StartListenNotify(ctx, 100*time.Millisecond) // Should return quickly because not postgres
}

func TestBundleServer_Rebuild_Error(t *testing.T) {
	ctx := context.Background()
	// Store with closed DB to trigger errors
	gormDB, _ := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	sqlDB, _ := gormDB.DB()
	s := db.NewStore(gormDB)

	bs := db.NewBundleServer(s, nil)

	// Close DB to break it
	sqlDB.Close()

	err := bs.Rebuild(ctx)
	if err == nil {
		t.Error("expected error from Rebuild on broken DB")
	}
}

func TestBundleServer_Rebuild_UnmarshalError(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	bs := db.NewBundleServer(store, nil)

	// Create a policy with invalid JSON in subjects
	// Note: Store.CreatePolicy might check it, but let's see.
	// Actually, we can use raw GORM to insert it.
	gormDB := store.DB()
	p := db.Policy{
		Name:     "bad-json",
		Effect:   "allow",
		Subjects: db.JSONField(`{invalid}`),
	}
	gormDB.Create(&p)

	err := bs.Rebuild(ctx)
	if err == nil {
		t.Error("expected unmarshal error")
	} else if !strings.Contains(err.Error(), "unmarshaling policy") {
		t.Errorf("expected unmarshaling error, got %v", err)
	}
}

func TestBundleServer_ServeHTTP_Head(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	bs := db.NewBundleServer(store, nil)
	bs.Rebuild(ctx)

	req := httptest.NewRequest(http.MethodHead, "/bundles/bundle.tar.gz", nil)
	w := httptest.NewRecorder()
	bs.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if len(w.Body.Bytes()) != 0 {
		t.Errorf("expected empty body for HEAD, got %d bytes", len(w.Body.Bytes()))
	}
}
