# Heimdall

 [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT) [![CI](https://github.com/f46b83ee9/heimdall/actions/workflows/ci.yml/badge.svg)](https://github.com/f46b83ee9/heimdall/actions/workflows/ci.yml) [![Go Version](https://img.shields.io/github/go-mod/go-version/f46b83ee9/heimdall.svg)](https://golang.org/doc/devel/release.html) [![Go Report Card](https://goreportcard.com/badge/github.com/f46b83ee9/heimdall)](https://goreportcard.com/report/github.com/f46b83ee9/heimdall) 

An identity-aware reverse proxy for [Grafana Mimir](https://grafana.com/oss/mimir/) that enforces multi-tenant access control using [OPA](https://www.openpolicyagent.org/) and PromQL query rewriting.

## What It Does

Heimdall sits between your users and Mimir, ensuring every request is:

1. **Authenticated** — JWT validated against your JWKS endpoint
2. **Authorized** — OPA evaluates per-tenant policies (allow/deny with filter scoping)
3. **Rewritten** — PromQL queries get label matchers injected from policy filters (e.g. `env="prod"`)
4. **Federated** — Multi-tenant queries use Mimir's native federation (`X-Scope-OrgID: acme|globex`)

```mermaid
sequenceDiagram
    participant Client
    participant Handler as Heimdall Handler
    participant OPA as OPA Engine
    participant Mimir as Upstream Mimir
    participant DB as SQL (Postgres/SQLite)

    Note over Handler: [1] Middleware & Tracing Entry
    Client->>Handler: Request (JWT + X-Scope-OrgID)
    
    Note over Handler: [2] Identity & Tenant Resolution
    Handler->>Handler: Validate JWT (Signature, Exp, Iss, Aud)
    Handler->>Handler: Extract sub (user_id) & groups

    loop [3] OPA Authorization Loop (Once per tenant)
        Handler->>OPA: input: {user_id, groups, tenant_id, action}
        OPA-->>Handler: {allow, effective_filters, accessible_tenants}
    end

    Note over Handler: [4] Authorization Check
    alt Any Deny Matches OR No Allow Matches
        Handler-->>Client: 403 Forbidden (JSON Envelope)
    else Authorized
        Note over Handler: [5] Fan-Out Grouping & AST Rewrite
        Handler->>Handler: Group tenants by identical filter signatures

        Note over Handler: [6] Upstream Dispatch (Parallel)
        par Group A (Tenant 1|Tenant 2)
            Handler->>Mimir: X-Scope-OrgID: T1|T2 + Rewritten Query
            Mimir-->>Handler: Result A
        and Group B (Tenant 3)
            Handler->>Mimir: X-Scope-OrgID: T3 + Rewritten Query
            Mimir-->>Handler: Result B
        end

        Note over Handler: [7] Response Handling
        Handler->>Handler: Deterministic Lexicographical Merge
        
        Note over Handler: [8] Client Response
        Handler-->>Client: 200 OK (Merged JSON)
    end
```

## Build

### With Go

```bash
make build
```

### With Docker

```bash
docker build -t heimdall .
```

## Run

### Prerequisites

- **Database (PostgreSQL or SQLite)** — stores tenants and policies
- **OPA** — evaluates authorization policies (pulls bundle from Heimdall)
- **JWKS endpoint** — for JWT signature verification

### Configuration

Create a `config.yaml`:

```yaml
server:
  main:
    addr: ":9091"              # Proxy API
    # tls:                     # Optional: enable HTTPS for proxy
    #   cert_file: "/etc/heimdall/tls/server.crt"
    #   key_file: "/etc/heimdall/tls/server.key"
    #   client_ca_file: "/etc/heimdall/tls/ca.crt"  # Optional: enables mTLS
  bundle:
    addr: ":9092"              # OPA bundle server
    # tls:                     # Optional: enable HTTPS for bundle server
    #   cert_file: "/etc/heimdall/tls/bundle.crt"
    #   key_file: "/etc/heimdall/tls/bundle.key"

mimir:
  url: "http://mimir:8080"    # Default fallback URL for Monolithic deployment
  # read_url: "http://mimir-query-frontend:8080" # Optional: Override for Microservices read path
  # write_url: "http://mimir-distributor:8080"   # Optional: Override for Microservices write path
  # ruler_url: "http://mimir-ruler:8080"         # Optional: Override for Microservices ruler path
  # alertmanager_url: "http://mimir-alertmanager:8080" # Optional: Override for Microservices alertmanager path
  auth:
    type: "bearer"            # Supports: basic, bearer, oauth2, api_key, mtls
    token: "your-mimir-token"

jwt:
  jwks_url: "https://your-idp.com/.well-known/jwks.json"
  issuer: "https://your-idp.com/"
  audience: "heimdall"

opa:
  url: "http://opa:8181"

database:
  driver: "sqlite"  # Can be "postgres", "sqlite", "mysql", "sqlserver"
  dsn: "file::memory:?cache=shared" # e.g. "heimdall.db" or "postgres://user:pass@localhost:5432/heimdall?sslmode=disable"

fanout:
  max_concurrency: 10

telemetry:
  enabled: false
```

All configuration can be overridden with environment variables using the `HEIMDALL_` prefix (e.g. `HEIMDALL_DATABASE_DSN`).

### Start with Go

```bash
./heimdall serve --config=config.yaml
```

### Start with Docker

```bash
docker run -v $(pwd)/config.yaml:/etc/heimdall/config.yaml \
  -p 9091:9091 -p 9092:9092 \
  heimdall serve --config=/etc/heimdall/config.yaml
```

### Configure OPA to Pull Bundles

OPA should be configured to pull its bundle from Heimdall's bundle server:

```yaml
services:
  heimdall:
    url: http://heimdall:9092

bundles:
  authz:
    service: heimdall
    resource: /bundles/bundle.tar.gz
    polling:
      min_delay_seconds: 5
      max_delay_seconds: 10
```

## Manage Tenants & Policies

```bash
# Create tenants
./heimdall tenant create acme "Acme Corp" --config=config.yaml
./heimdall tenant create globex "Globex Inc" --config=config.yaml

# Create a policy (allow alice to read acme with env="prod" filter)
./heimdall policy create --config=config.yaml \
  --name="allow-alice-read-acme" \
  --effect=allow \
  --subjects='[{"type":"user","id":"alice"}]' \
  --actions='["read"]' \
  --scope='{"tenants":["acme"]}' \
  --filters='["env=\"prod\""]'
```

## Observability & Instrumentation

Heimdall has built-in [OpenTelemetry](https://opentelemetry.io/) distributed tracing. When enabled, every request generates spans for the full pipeline: JWT validation → OPA evaluation → PromQL rewriting → Mimir upstream calls → response merging.

### Enable Tracing

Add to your `config.yaml`:

```yaml
telemetry:
  enabled: true
  otlp_endpoint: "localhost:4317"   # gRPC OTLP collector
  service_name: "heimdall"          # appears in your trace viewer
```

Or via environment variables:

```bash
export HEIMDALL_TELEMETRY_ENABLED=true
export HEIMDALL_TELEMETRY_OTLP_ENDPOINT=localhost:4317
```

### Backends

Heimdall exports traces via **OTLP gRPC** (insecure), compatible with:

| Backend | Receiver endpoint |
|---------|------------------|
| **Jaeger** | `localhost:4317` (OTLP native) |
| **Grafana Tempo** | `localhost:4317` |
| **OpenTelemetry Collector** | `localhost:4317` |
| **Datadog Agent** | `localhost:4317` (with OTLP ingest enabled) |

Example with Jaeger all-in-one:

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 4317:4317 \
  jaegertracing/all-in-one:latest

# Then start Heimdall with telemetry.enabled=true
# View traces at http://localhost:16686
```

### What Gets Traced

Every request generates a trace with the following spans:

```
heimdall.request
├── jwt.Validate              # Token parsing + signature check
├── opa.Evaluate              # Per-tenant policy evaluation (one span per tenant)
├── db.CreateTenant           # Database operations (if applicable)
├── handler.RewriteQuery      # PromQL AST rewriting with filter injection
├── fanout.Dispatch           # Parallel upstream requests to Mimir
│   └── fanout.UpstreamCall   # Individual Mimir request per filter group
└── handler.MergeResults      # Response merging for multi-tenant queries
```

### Context Propagation

Heimdall propagates W3C `traceparent` headers to upstream Mimir calls, so traces link across services. Incoming `traceparent` headers are also respected, allowing end-to-end tracing from your client through Heimdall to Mimir.

### Structured Logging

All `slog` log lines include `trace_id` and `span_id` when telemetry is enabled, making it easy to correlate logs with traces:

```
INFO request started trace_id=abc123 span_id=def456 method=GET path=/api/v1/query
INFO JWT validated trace_id=abc123 span_id=789abc user_id=alice groups_count=2
```

### Prometheus Metrics

Metrics are **always enabled** (even without tracing) and served at `GET :9092/metrics` (same port as the bundle server).

Available metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `heimdall_requests_total` | counter | method, path, status | Total HTTP requests |
| `heimdall_request_duration_seconds` | histogram | method, path, status | Request latency |
| `heimdall_opa_evaluations_total` | counter | — | OPA policy evaluations |
| `heimdall_opa_evaluation_duration_seconds` | histogram | — | OPA evaluation latency |
| `heimdall_upstream_requests_total` | counter | method, path, status | Upstream Mimir requests |
| `heimdall_upstream_request_duration_seconds` | histogram | method, path, status | Upstream request latency |
| `heimdall_bundle_rebuilds_total` | counter | — | OPA bundle rebuilds |
| `heimdall_active_tenants` | gauge | — | Number of active tenants |
| `heimdall_tenant_cache_hits_total` | counter | — | OPA Tenant auto-resolve read cache hits |
| `heimdall_tenant_cache_misses_total` | counter | — | OPA Tenant auto-resolve read cache misses |
| `heimdall_fanout_active_goroutines` | gauge | — | Number of active fan-out dispatch goroutines |
| `heimdall_fanout_dropped_requests_total` | counter | — | Upstream requests declined due to backend concurrency limits |

Scrape config for Prometheus:

```yaml
scrape_configs:
  - job_name: heimdall
    static_configs:
      - targets: ["heimdall:9092"]
```

## Health Checks

- `GET /healthz` — liveness probe (always 200)
- `GET /readyz` — readiness probe (checks database connectivity)

## Test

```bash
# Unit tests
make test

# OPA Rego policy tests
opa test ./opa/

# E2E tests (requires Docker)
go test -tags=e2e -timeout=10m ./tests/e2e/
```

## License

See [LICENSE](LICENSE) for details.
