<p align="center">
  <img src="assets/logo.png" alt="IronVeil Logo" width="400">
</p>

# IronVeil

**IronVeil** is a high-performance, Rust-based database proxy designed for real-time PII (Personally Identifiable Information) anonymization. It sits between your application and your database, intercepting queries and masking sensitive data on the fly without requiring changes to your application code.

## Features

### Core Functionality
*   **Real-time Anonymization**: Masks PII data in database result sets on the fly.
*   **Multi-Database Support**: Works with both **PostgreSQL** and **MySQL** wire protocols.
*   **Zero-Copy Parsing**: Built with `tokio` and `bytes` for high throughput and low latency.
*   **Configurable Rules**: Define masking strategies per column via `proxy.yaml` with table-scoped matching for MySQL and PostgreSQL.
*   **TLS Support**: Client-to-proxy and proxy-to-upstream TLS encryption.

### PII Detection
*   **Extended PII Types**: Detects emails, credit cards, SSN, phone numbers, IP addresses, dates of birth, and passport numbers.
*   **Heuristic Detection**: Automatically detects and masks PII using regex patterns.
*   **JSON/Array Support**: Recursively masks PII in JSON objects and PostgreSQL/MySQL array types.
*   **Deterministic Masking**: Same input always produces the same fake output (useful for testing).

### Production Ready
*   **Graceful Shutdown**: Signal handling (SIGTERM, SIGINT) with connection draining.
*   **API Authentication**: API key and JWT (HS256) authentication for management endpoints.
*   **Connection Limits**: Max connections and rate limiting support.
*   **Connection Timeouts**: Configurable idle and connect timeouts.
*   **Health Checks**: Background upstream health monitoring with configurable thresholds.
*   **Hot Reload**: Automatic config reload on file changes, plus manual reload API.

### Observability
*   **Prometheus Metrics**: `/metrics` endpoint with connection, query, and masking metrics.
*   **OpenTelemetry**: Distributed tracing integration for observability.
*   **Audit Logging**: Comprehensive audit trail for all security-relevant events.
*   **Live Inspector**: View real-time query logs and data transformations via the web dashboard.

### Web Dashboard
*   **Real-time Monitoring**: Live connection graphs, query activity, and masking statistics.
*   **Rule Management**: Create, test, and preview masking rules with live feedback.
*   **PII Scanner**: Scan databases for sensitive data and apply rules automatically.
*   **Theme Support**: Dark, light, and system themes with persistent preference.
*   **Responsive Design**: Modern UI built with React, Tailwind CSS, and Framer Motion.

## Dashboard View

![IronVeil Dashboard View](assets/dashboard-view.png)

## Tech Stack

*   **Core**: Rust 2024 Edition (Tokio, Axum, tokio-util)
*   **Frontend**: Next.js 16, React 19, Tailwind CSS 4, Shadcn UI, Recharts, Framer Motion
*   **Observability**: OpenTelemetry (OTLP)
*   **Deployment**: Docker Compose

## Getting Started

### Quick Start with Docker

1.  **Start the stack**:
    ```bash
    docker compose up -d --build
    ```

2.  **Verify the Management API**:
    Open [http://localhost:3001/health](http://localhost:3001/health) to confirm proxy and upstream status.

3.  **Connect to the Proxy (PostgreSQL)**:
    ```bash
    psql -h 127.0.0.1 -p 6543 -U postgres
    ```

4.  **Run the Web Dashboard (optional, separate process)**:
    ```bash
    cd web
    npm install
    npm run dev
    ```
    Then open [http://localhost:3000](http://localhost:3000).

### Running Locally

```bash
# Build
cargo build --release

# Run with PostgreSQL (default)
./target/release/iron-veil --port 6543 --upstream-host 127.0.0.1 --upstream-port 5432

# Run with MySQL
./target/release/iron-veil --port 6543 --upstream-host 127.0.0.1 --upstream-port 3306 --protocol mysql
```

## CLI Options

```
Usage: iron-veil [OPTIONS]

Options:
  -p, --port <PORT>                    Port to listen on [default: 6543]
      --upstream-host <UPSTREAM_HOST>  Upstream database host [default: 127.0.0.1]
      --upstream-port <UPSTREAM_PORT>  Upstream database port [default: 5432]
      --config <CONFIG>                Path to configuration file [default: proxy.yaml]
      --api-port <API_PORT>            Management API port [default: 3001]
      --protocol <PROTOCOL>            Database protocol to proxy [default: postgres]
                                       [possible values: postgres, mysql]
      --shutdown-timeout <SECONDS>     Graceful shutdown timeout [default: 30]
  -h, --help                           Print help
  -V, --version                        Print version
```

## Configuration

Edit `proxy.yaml` to configure masking rules:

```yaml
# TLS Configuration
tls:
  enabled: false
  cert_path: "certs/server.crt"
  key_path: "certs/server.key"

upstream_tls: false

# OpenTelemetry (send traces to Jaeger, Grafana Tempo, etc.)
telemetry:
  enabled: false
  otlp_endpoint: "http://localhost:4317"
  service_name: "iron-veil"

# Management API Security
api:
  api_key: "your-secret-key"  # Optional: protects endpoints via X-API-Key header
  jwt_secret: "your-jwt-secret"  # Optional: allows Authorization: Bearer <token>

# Connection Limits
limits:
  max_connections: 1000  # Optional: max concurrent connections
  connections_per_second: 100  # Optional: rate limit for new connections
  connect_timeout_secs: 30  # Upstream connection timeout (default: 30)
  idle_timeout_secs: 300  # Idle connection timeout (default: 300)
  upstream_pool_size: 500  # Optional: cap concurrent upstream sessions
  upstream_pool_wait_timeout_secs: 5  # Wait time for upstream slot before reject (default: 5)

# Upstream Health Check
health_check:
  enabled: true  # Enable health checks (default: true)
  interval_secs: 10  # Check interval (default: 10)
  timeout_secs: 5  # Health check timeout (default: 5)
  unhealthy_threshold: 3  # Failures before unhealthy (default: 3)
  healthy_threshold: 1  # Successes before healthy (default: 1)

# Masking Rules
rules:
  - table: "users"        # Table-specific rule
    column: "email"
    strategy: "email"
  - table: "users"
    column: "phone_number"
    strategy: "phone"
  - column: "address"     # Global rule (any table)
    strategy: "address"
  - column: "metadata"    # JSON column masking
    strategy: "json"
```

### Available Masking Strategies

| Strategy | Description | Example Output |
|----------|-------------|----------------|
| `email` | Generates fake email | `john.doe@example.com` |
| `phone` | Generates fake phone number | `555-123-4567` |
| `address` | Generates fake city name | `Springfield` |
| `credit_card` | Generates fake CC number | `4532-xxxx-xxxx-1234` |
| `hash` | Deterministic SHA-256 hash | `sha256:2cf24dba5fb0a30e...` |
| `json` | Recursively masks PII in JSON | `{"email": "fake@example.com"}` |

### Rule Matching Notes

- MySQL: `table` + `column` rules are enforced as configured.
- PostgreSQL: IronVeil resolves `table_oid` values to table names at session bootstrap and then enforces `table` + `column` rules.
- If PostgreSQL OID lookup fails (for example due to permissions), IronVeil safely falls back to global `column` rules for that session.

### PII Types Auto-Detected

| Type | Pattern | Example |
|------|---------|---------|
| Email | Standard email format | `user@domain.com` |
| Credit Card | 13-19 digit numbers | `4111111111111111` |
| SSN | XXX-XX-XXXX format | `123-45-6789` |
| Phone | International format with country code | `+1-555-123-4567` |
| IP Address | IPv4 format | `192.168.1.1` |
| Date of Birth | Various date formats | `1990-01-15`, `01/15/1990` |
| Passport | Alphanumeric (6-9 chars) | `AB1234567` |

## Management API

The management API runs on port 3001 by default.

### Public Endpoints (No Auth Required)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with upstream status |
| `/metrics` | GET | Prometheus metrics |

### Protected Endpoints (Require API Key or JWT)
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/rules` | GET | List masking rules (returns `{ "rules": [...] }`) |
| `/rules` | POST | Add or update a masking rule (upsert by `table`+`column`) |
| `/rules/delete` | POST | Delete a rule by index or column/table |
| `/rules/export` | GET | Export rules as JSON |
| `/rules/import` | POST | Import rules from JSON array |
| `/config` | GET | Get config summary (`masking_enabled`, `rules_count`) |
| `/config` | POST | Update configuration |
| `/config/reload` | POST | Reload config from disk |
| `/scan` | POST | Scan database for PII (requires DB credentials; PostgreSQL scanner currently) |
| `/connections` | GET | List active connections |
| `/stats` | GET | Get statistics (queries, masking counts, connection history) |
| `/schema` | POST | Get database schema (PostgreSQL scanner currently) |
| `/logs` | GET | Get recent query logs |
| `/audit` | GET | Get audit logs (supports `?limit=N`, `?event_type=X`, `?outcome=Y`) |

`GET /health` includes runtime upstream metadata:

```json
{
  "status": "ok",
  "version": "0.1.3",
  "upstream": {
    "host": "localhost",
    "port": 5432,
    "protocol": "postgres",
    "healthy": true
  }
}
```

### Scan Request Body

`POST /scan` and `POST /schema` require a JSON body:

```json
{
  "username": "postgres",
  "password": "password",
  "database": "postgres",
  "schema": "public",
  "sample_size": 100,
  "confidence_threshold": 0.5,
  "exclude_tables": []
}
```

`POST /scan` and `POST /schema` can return:

- `401 Unauthorized` with code `auth_required` when `username` or `password` is missing/blank.
- `501 Not Implemented` with code `unsupported_protocol` when IronVeil runs with `--protocol mysql`.
- `502 Bad Gateway` with code `connection_failed` when upstream DB connection fails.
- `500 Internal Server Error` with code `query_failed` when schema/query execution fails after connection.

### Rule Upsert & Deduplication

- Rule identity is normalized by `(table, column)` (case-insensitive).
- `POST /rules` is idempotent for the same target:
  - same strategy -> unchanged
  - different strategy -> updates existing rule strategy
- `POST /rules/import` deduplicates incoming and existing duplicates by target.

### Authentication

```bash
# Using API Key
curl -H "X-API-Key: your-secret-key" http://localhost:3001/rules

# Using JWT
curl -H "Authorization: Bearer <token>" http://localhost:3001/rules
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Client    │────▶│   IronVeil   │────▶│  Database   │
│  (psql/app) │◀────│    Proxy     │◀────│ (PG/MySQL)  │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │  Dashboard  │
                    │ (Next.js)   │
                    └─────────────┘
```

## Project Structure

```
iron-veil/
├── src/
│   ├── main.rs          # Entry point, CLI, connection handling
│   ├── config.rs        # Configuration loading (proxy.yaml)
│   ├── api.rs           # Axum management API
│   ├── state.rs         # Shared application state
│   ├── scanner.rs       # PII regex scanner (7 PII types)
│   ├── db_scanner.rs    # Real database introspection & PII scanning
│   ├── audit.rs         # Audit logging for security events
│   ├── interceptor.rs   # Anonymizer implementations (PG + MySQL)
│   ├── telemetry.rs     # OpenTelemetry setup
│   ├── metrics.rs       # Prometheus metrics
│   └── protocol/
│       ├── mod.rs
│       ├── postgres.rs  # PostgreSQL wire protocol codec
│       └── mysql.rs     # MySQL wire protocol codec
├── tests/
│   └── integration_test.rs  # Integration tests (20 tests)
├── monitoring/
│   └── grafana/
│       └── ironveil-dashboard.json  # Baseline Grafana dashboard
├── web/                 # Next.js dashboard
├── proxy.yaml           # Configuration file
└── docker-compose.yml   # Backend stack (proxy + postgres)
```

## Monitoring

### Prometheus Metrics

Metrics are exposed at `http://localhost:3001/metrics`:

```
# Connection metrics
ironveil_connections_total
ironveil_connections_active
ironveil_connections_rejected_total{reason="rate_limit|max_connections|upstream_pool_closed|upstream_pool_wait_timeout"}

# Query metrics
ironveil_queries_total{protocol="postgres|mysql"}
ironveil_query_duration_seconds{protocol="postgres|mysql"}

# Masking metrics
ironveil_fields_masked_total
ironveil_masking_errors_total

# Health metrics
ironveil_upstream_healthy
ironveil_upstream_health_check_latency_ms
ironveil_upstream_timeouts_total
ironveil_idle_timeouts_total

# Upstream pool metrics
ironveil_upstream_pool_active_connections
ironveil_upstream_pool_size
ironveil_upstream_pool_utilization_ratio
ironveil_upstream_pool_wait_seconds
ironveil_upstream_pool_acquire_timeouts_total
```

### Grafana Dashboard Template

Use the baseline dashboard at `monitoring/grafana/ironveil-dashboard.json`.

Import steps:
1. Open Grafana and go to **Dashboards** -> **New** -> **Import**.
2. Upload `monitoring/grafana/ironveil-dashboard.json`.
3. Select your Prometheus datasource when prompted.
4. Save the dashboard as `IronVeil Overview`.

The dashboard includes panels for upstream health, connection activity, query throughput/latency, masking operations, timeout rates, and upstream pool saturation/wait behavior.

## Development

```bash
# Run all tests
cargo test

# Run only unit tests
cargo test --bin iron-veil

# Run only integration tests
cargo test --test integration_test

# Check for issues
cargo clippy

# Format code
cargo fmt

# Build the web dashboard
cd web && npm install && npm run build
```

### Web API Configuration

The dashboard reads API settings from optional `NEXT_PUBLIC_*` variables:

- `NEXT_PUBLIC_API_BASE_URL` (default: `http://localhost:3001`)
- `NEXT_PUBLIC_IRONVEIL_API_KEY` (sent as `X-API-Key`)
- `NEXT_PUBLIC_IRONVEIL_BEARER_TOKEN` (sent as `Authorization: Bearer ...`)

## Testing with Docker

```bash
# Start backend stack (proxy + postgres)
docker compose up -d

# View logs
docker compose logs -f proxy
```

Run the dashboard separately when needed:

```bash
cd web
npm install
npm run dev
```

Run integration tests in strict mode (fail if required services are not running):

```bash
IRONVEIL_REQUIRE_SERVICES=1 cargo test --test integration_test
```

## Testing OpenTelemetry

1. Start Jaeger:
   ```bash
   docker run -d --name jaeger -p 16686:16686 -p 4317:4317 jaegertracing/all-in-one:latest
   ```

2. Enable telemetry in `proxy.yaml`:
   ```yaml
   telemetry:
     enabled: true
     otlp_endpoint: "http://localhost:4317"
     service_name: "iron-veil"
   ```

3. View traces at [http://localhost:16686](http://localhost:16686)

## License

MIT
