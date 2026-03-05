//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/f46b83ee9/heimdall/db"
)

// --- Container infrastructure ---

type testInfra struct {
	network  *testcontainers.DockerNetwork
	postgres testcontainers.Container
	opa      testcontainers.Container
	mimir    testcontainers.Container
	heimdall testcontainers.Container

	postgresHost string // external DSN (mapped port)
	opaHost      string // OPA external URL (mapped port)
	mimirHost    string // Mimir external URL (mapped port)
	heimdallHost string // Heimdall external URL (mapped port)

	store *db.Store
	jwks  *jwksServer
}

func setupInfra(t *testing.T) *testInfra {
	t.Helper()
	ctx := context.Background()

	infra := &testInfra{}

	// Start JWKS mock server (on host, reachable by Heimdall via host networking)
	infra.jwks = startJWKSServer(t)
	t.Logf("JWKS server started at %s", infra.jwks.jwksURL())

	// Create shared Docker network
	net, err := network.New(ctx)
	if err != nil {
		t.Fatalf("creating network: %v", err)
	}
	infra.network = net
	t.Cleanup(func() { net.Remove(ctx) })

	networkName := net.Name

	// --- PostgreSQL ---
	pgReq := testcontainers.ContainerRequest{
		Image:        "postgres:17-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "heimdall",
			"POSTGRES_PASSWORD": "heimdall",
			"POSTGRES_DB":       "heimdall",
		},
		Networks: []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"postgres"},
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: pgReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("starting postgres: %v", err)
	}
	infra.postgres = pgContainer
	t.Cleanup(func() { pgContainer.Terminate(ctx) })

	pgHost, _ := pgContainer.Host(ctx)
	pgPort, _ := pgContainer.MappedPort(ctx, "5432")
	infra.postgresHost = fmt.Sprintf("postgres://heimdall:heimdall@%s:%s/heimdall?sslmode=disable", pgHost, pgPort.Port())

	// Connect and migrate via external port
	gormDB, err := gorm.Open(postgres.Open(infra.postgresHost), &gorm.Config{})
	if err != nil {
		t.Fatalf("connecting to postgres: %v", err)
	}
	infra.store = db.NewStore(gormDB)
	if err := infra.store.Migrate(); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	// --- Mimir ---
	mimirReq := testcontainers.ContainerRequest{
		Image:        "grafana/mimir:3.0.3",
		ExposedPorts: []string{"8080/tcp"},
		Tmpfs: map[string]string{
			"/tmp/mimir/rules": "",
		},
		Cmd: []string{
			"-target=all",
			"-server.http-listen-port=8080",
			"-auth.multitenancy-enabled=true",
			"-ingester.ring.replication-factor=1",
			"-tenant-federation.enabled=true",
			"-ruler-storage.backend=local",
			"-ruler-storage.local.directory=/tmp/mimir/rules",
			"-ruler.enable-api=true",
		},
		Networks: []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"mimir"},
		},
		WaitingFor: wait.ForHTTP("/ready").
			WithPort("8080").
			WithStartupTimeout(90 * time.Second),
	}

	mimirContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: mimirReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("starting mimir: %v", err)
	}
	infra.mimir = mimirContainer
	t.Cleanup(func() { mimirContainer.Terminate(ctx) })

	mimirHost, _ := mimirContainer.Host(ctx)
	mimirPort, _ := mimirContainer.MappedPort(ctx, "8080")
	infra.mimirHost = fmt.Sprintf("http://%s:%s", mimirHost, mimirPort.Port())

	return infra
}

// startHeimdall builds and starts Heimdall as a Docker container.
// It connects to Postgres (via Docker network alias), rebuilds the bundle,
// and serves the bundle on port 9092 for OPA to pull.
func (infra *testInfra) startHeimdall(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	networkName := infra.network.Name

	// Write config file that references Docker network aliases
	configYAML := fmt.Sprintf(`
server:
  main:
    addr: ":9091"
    read_timeout: 30s
    write_timeout: 30s
    idle_timeout: 120s
  bundle:
    addr: ":9092"

mimir:
  url: "http://mimir:8080"
  timeout: 30s

jwt:
  jwks_url: "%s"
  issuer: "heimdall-test"
  audience: "heimdall"
  groups_claim: "groups"

opa:
  url: "http://opa:8181"
  policy_path: "v1/data/proxy/authz"
  timeout: 5s

database:
  driver: "postgres"
  dsn: "postgres://heimdall:heimdall@postgres:5432/heimdall?sslmode=disable"
  refresh_interval: 5s

fanout:
  max_concurrency: 10
  timeout: 30s

telemetry:
  enabled: false
  service_name: "heimdall-e2e"
`, infra.jwks.hostJWKSURL("172.17.0.1"))

	configFile, err := os.CreateTemp("", "heimdall-config-*.yaml")
	if err != nil {
		t.Fatalf("creating config file: %v", err)
	}
	if _, writeErr := configFile.WriteString(configYAML); writeErr != nil {
		t.Fatalf("writing config: %v", writeErr)
	}
	configFile.Close()
	t.Cleanup(func() { os.Remove(configFile.Name()) })

	heimdallReq := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "../../",
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"9091/tcp", "9092/tcp"},
		Cmd:          []string{"serve", "--config=/etc/heimdall/config.yaml"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      configFile.Name(),
				ContainerFilePath: "/etc/heimdall/config.yaml",
				FileMode:          0o644,
			},
		},
		Networks: []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"heimdall"},
		},
		WaitingFor: wait.ForHTTP("/api/v1/query").
			WithPort("9091").
			WithStatusCodeMatcher(func(status int) bool {
				// 401 = server up (JWT middleware rejects), 400 = missing tenant
				return status == 401 || status == 200 || status == 400
			}).
			WithStartupTimeout(120 * time.Second),
	}

	heimdallContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: heimdallReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("starting heimdall: %v", err)
	}
	infra.heimdall = heimdallContainer
	t.Cleanup(func() { heimdallContainer.Terminate(ctx) })

	host, _ := heimdallContainer.Host(ctx)
	port, _ := heimdallContainer.MappedPort(ctx, "9091")
	infra.heimdallHost = fmt.Sprintf("http://%s:%s", host, port.Port())

	// Get the bundle server mapped port for verification
	bundlePort, _ := heimdallContainer.MappedPort(ctx, "9092")
	bundleURL := fmt.Sprintf("http://%s:%s/bundles/bundle.tar.gz", host, bundlePort.Port())

	log.Printf("Heimdall started at %s (bundle server at %s)", infra.heimdallHost, bundleURL)

	// Capture and log Heimdall container logs for debugging
	logs, logErr := heimdallContainer.Logs(ctx)
	if logErr == nil {
		logBytes, _ := io.ReadAll(logs)
		logs.Close()
		t.Logf("Heimdall container logs:\n%s", string(logBytes))
	}

	// Verify the bundle server is serving the bundle
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(bundleURL)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && len(body) > 0 {
				t.Logf("Bundle server verified ✓ (size=%d bytes, status=%d)", len(body), resp.StatusCode)
				return
			}
			t.Logf("Bundle server response: status=%d, size=%d", resp.StatusCode, len(body))
		} else {
			t.Logf("Bundle server check failed: %v", err)
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatal("Bundle server did not start serving the bundle in time")
}

// startOPA starts OPA configured to pull bundles from Heimdall's bundle server.
// Must be called AFTER startHeimdall so the bundle is available.
func (infra *testInfra) startOPA(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	networkName := infra.network.Name

	opaReq := testcontainers.ContainerRequest{
		Image:        "openpolicyagent/opa:1.14.0",
		ExposedPorts: []string{"8181/tcp"},
		Cmd: []string{
			"run", "--server",
			"--addr=0.0.0.0:8181",
			"--set=bundles.heimdall.service=heimdall-bundle",
			"--set=bundles.heimdall.resource=bundles/bundle.tar.gz",
			"--set=bundles.heimdall.polling.min_delay_seconds=2",
			"--set=bundles.heimdall.polling.max_delay_seconds=5",
			"--set=services.heimdall-bundle.url=http://heimdall:9092",
		},
		Networks: []string{networkName},
		NetworkAliases: map[string][]string{
			networkName: {"opa"},
		},
		WaitingFor: wait.ForHTTP("/health").
			WithPort("8181").
			WithStartupTimeout(30 * time.Second),
	}

	opaContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: opaReq,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("starting opa: %v", err)
	}
	infra.opa = opaContainer
	t.Cleanup(func() { opaContainer.Terminate(ctx) })

	opaHost, _ := opaContainer.Host(ctx)
	opaPort, _ := opaContainer.MappedPort(ctx, "8181")
	infra.opaHost = fmt.Sprintf("http://%s:%s", opaHost, opaPort.Port())

	log.Printf("OPA started at %s (pulling bundle from http://heimdall:9092)", infra.opaHost)
}

// --- Seeding helpers ---

// seedMimirSeries pushes time series to Mimir via remote write with Protobuf+Snappy.
func seedMimirSeries(t *testing.T, mimirURL, tenant string, metricName string, labels map[string]string, value float64) {
	t.Helper()

	now := time.Now().UnixMilli()

	// Build labels array
	lbls := []prompb.Label{
		{Name: "__name__", Value: metricName},
	}
	for k, v := range labels {
		lbls = append(lbls, prompb.Label{Name: k, Value: v})
	}
	// Sort labels for deterministic encoding
	sort.Slice(lbls, func(i, j int) bool { return lbls[i].Name < lbls[j].Name })

	writeReq := &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{
			{
				Labels: lbls,
				Samples: []prompb.Sample{
					{Value: value, Timestamp: now},
				},
			},
		},
	}

	data, err := proto.Marshal(writeReq)
	if err != nil {
		t.Fatalf("marshaling write request: %v", err)
	}

	compressed := snappy.Encode(nil, data)

	url := fmt.Sprintf("%s/api/v1/push", mimirURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("creating push request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Scope-OrgID", tenant)
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("pushing to Mimir: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("Mimir push failed with status %d: %s", resp.StatusCode, string(body))
	}

	t.Logf("seeded %s{%v} = %v to tenant %s", metricName, labels, value, tenant)
}

// waitForMimirSeries polls Mimir directly until the expected series count is met.
func waitForMimirSeries(t *testing.T, mimirURL, tenant, query string, minResults int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	interval := 500 * time.Millisecond

	for time.Now().Before(deadline) {
		url := fmt.Sprintf("%s/prometheus/api/v1/query?query=%s", mimirURL, query)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			time.Sleep(interval)
			continue
		}
		req.Header.Set("X-Scope-OrgID", tenant)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			time.Sleep(interval)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Logf("waitForMimirSeries: status %d", resp.StatusCode)
			time.Sleep(interval)
			continue
		}

		var qr struct {
			Data struct {
				Result []json.RawMessage `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &qr); err == nil && len(qr.Data.Result) >= minResults {
			t.Logf("waitForMimirSeries: found %d results (need %d) ✓", len(qr.Data.Result), minResults)
			return
		}

		t.Logf("waitForMimirSeries: waiting... (found %d, need %d)", len(qr.Data.Result), minResults)
		time.Sleep(interval)
		if interval < 5*time.Second {
			interval = time.Duration(float64(interval) * 1.5)
		}
	}

	t.Fatalf("waitForMimirSeries: timed out waiting for %d results for query %q on tenant %s", minResults, query, tenant)
}

// Sentinel to avoid unused import errors
var _ = math.MaxFloat64

// seedDatabase creates test tenants and policies.
func seedDatabase(t *testing.T, store *db.Store) {
	t.Helper()
	ctx := context.Background()

	// Create tenants
	tenants := []db.Tenant{
		{ID: "acme", Name: "Acme Corp"},
		{ID: "globex", Name: "Globex Inc"},
	}
	for _, tenant := range tenants {
		if err := store.CreateTenant(ctx, &tenant); err != nil {
			t.Fatalf("creating tenant %s: %v", tenant.ID, err)
		}
	}

	// Create policies
	policies := []db.Policy{
		{
			Name:     "allow-alice-read-acme",
			Effect:   "allow",
			Subjects: db.JSONField(`[{"type":"user","id":"alice"},{"type":"group","id":"developers"}]`),
			Actions:  db.JSONField(`["read"]`),
			Scope:    db.JSONField(`{"tenants":["acme"],"resources":["metrics"]}`),
			Filters:  db.JSONField(`["env=\"prod\""]`),
		},
		{
			Name:     "allow-admin-all",
			Effect:   "allow",
			Subjects: db.JSONField(`[{"type":"user","id":"admin"},{"type":"group","id":"admins"}]`),
			Actions:  db.JSONField(`["*"]`),
			Scope:    db.JSONField(`{"tenants":["*"],"resources":["metrics"]}`),
			Filters:  db.JSONField(`[]`),
		},
		{
			Name:     "deny-bob-acme",
			Effect:   "deny",
			Subjects: db.JSONField(`[{"type":"user","id":"bob"}]`),
			Actions:  db.JSONField(`["read"]`),
			Scope:    db.JSONField(`{"tenants":["acme"],"resources":["metrics"]}`),
			Filters:  db.JSONField(`[]`),
		},
	}
	for _, policy := range policies {
		if err := store.CreatePolicy(ctx, &policy); err != nil {
			t.Fatalf("creating policy %s: %v", policy.Name, err)
		}
	}

	t.Log("database seeded with tenants and policies")
}

// seedTestMetrics pushes labeled test series directly to Mimir.
func seedTestMetrics(t *testing.T, mimirURL string) {
	t.Helper()

	// Acme tenant metrics
	seedMimirSeries(t, mimirURL, "acme", "up", map[string]string{
		"env": "prod", "instance": "acme-web-1",
	}, 1)
	seedMimirSeries(t, mimirURL, "acme", "up", map[string]string{
		"env": "staging", "instance": "acme-web-2",
	}, 1)
	seedMimirSeries(t, mimirURL, "acme", "test_metric", map[string]string{
		"env": "prod", "namespace": "default",
	}, 42)
	seedMimirSeries(t, mimirURL, "acme", "test_metric", map[string]string{
		"env": "staging", "namespace": "kube-system",
	}, 99)

	// Globex tenant metrics
	seedMimirSeries(t, mimirURL, "globex", "up", map[string]string{
		"env": "prod", "instance": "globex-api-1",
	}, 1)
	seedMimirSeries(t, mimirURL, "globex", "test_metric", map[string]string{
		"env": "prod", "namespace": "globex-prod",
	}, 55)

	t.Log("Mimir seeded with test metrics")
}
