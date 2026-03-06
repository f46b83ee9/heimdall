# Heimdall Testing Stack

This directory contains a complete, self-contained Docker Compose stack to run Heimdall along with its typical ecosystem for testing and development. 

The stack includes:
- **Heimdall**: The identity-aware reverse proxy.
- **Grafana Mimir**: The upstream metrics storage.
- **Dex Identity Provider**: A test OpenID Connect (OIDC) provider.
- **Open Policy Agent (OPA)**: For authorization policy evaluation.
- **PostgreSQL**: Heimdall's database for tenants and policies.
- **Grafana**: Pre-configured to authenticate via Dex and query Heimdall.
- **OpenTelemetry Core**: OpenTelemetry Collector & Jaeger for distributed tracing.
- **Prometheus**: To scrape internal metric endpoints (e.g. from Heimdall).

## Getting Started

1. **Start the stack**
   ```bash
   docker compose up -d
   ```
   *(This will build the Heimdall image from your local source code context).*

2. **Seed Heimdall Database**
   By default, the stack starts empty. You can use the Heimdall binary or curl to create tenants and policies on `localhost:9091`. 
   
   Example creating an `acme` tenant and resource-restricted policy:
   ```bash
   ../heimdall tenant create acme "Acme Corp" --config ./config/heimdall.yaml
   
   ../heimdall policy create --config ./config/heimdall.yaml \
     --name "allow-alice-acme" \
     --effect allow \
     --subjects '[{"type":"user","id":"alice@acme.com"}]' \
     --actions '["read"]' \
     --scope '{"tenants":["acme"], "resources":["metrics"]}' \
     --filters '["env=\"prod\""]'
   ```

   **Batch Policy Creation**
   Heimdall supports creating multiple policies at once from a JSON file or stdin:
   ```bash
   # From a JSON file (single object or array)
   ../heimdall policy create policies.json --config ./config/heimdall.yaml

   # From stdin
   cat policies.json | ../heimdall policy create - --config ./config/heimdall.yaml
   ```

3. **Login to Grafana**
   - Open your browser to **http://localhost:3000**
   - Click "Sign in with Dex"
   - You can log in using one of the pre-configured static users:
     - User: `admin@example.com` / Password: `password` (Admin Role)
     - User: `alice@acme.com` / Password: `password` (Viewer Role)
     - User: `bob@globex.com` / Password: `password` (Viewer Role)

4. **View Traces in Jaeger**
   - Open **http://localhost:16686** to view distributed traces natively exported by Heimdall via OpenTelemetry.

5. **Stop the stack**
   ```bash
   docker compose down -v
   ```
