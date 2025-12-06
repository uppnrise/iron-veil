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
*   **Configurable Rules**: Define masking strategies per table and column via `proxy.yaml`.
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

2.  **Access the Dashboard**:
    Open [http://localhost:3000](http://localhost:3000) to view the control plane.

3.  **Connect to the Proxy (PostgreSQL)**:
    ```bash
    psql -h 127.0.0.1 -p 6543 -U postgres
    ```

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
| `json` | Recursively masks PII in JSON | `{"email": "fake@example.com"}` |

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
| `/rules` | GET | List all masking rules |
| `/rules` | POST | Add a new masking rule |
| `/rules/delete` | POST | Delete a rule by index or column/table |
| `/rules/export` | GET | Export rules as JSON |
| `/rules/import` | POST | Import rules from JSON array |
| `/config` | GET | Get current configuration |
| `/config` | POST | Update configuration |
| `/config/reload` | POST | Reload config from disk |
| `/scan` | POST | Scan database for PII (queries information_schema, samples data) |
| `/connections` | GET | List active connections |
| `/stats` | GET | Get statistics (queries, masking counts, connection history) |
| `/schema` | POST | Get database schema (tables and columns) |
| `/logs` | GET | Get recent query logs |
| `/audit` | GET | Get audit logs (supports `?limit=N`, `?event_type=X`, `?outcome=Y`) |

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
│   └── integration_test.rs  # Integration tests (17 tests)
├── web/                 # Next.js dashboard
├── proxy.yaml           # Configuration file
└── docker-compose.yml   # Full stack deployment
```

## Monitoring

### Prometheus Metrics

Metrics are exposed at `http://localhost:3001/metrics`:

```
# Connection metrics
ironveil_connections_total
ironveil_connections_active
ironveil_connections_rejected_total{reason="rate_limit|max_connections"}

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
```

## Development

```bash
# Run tests (79 tests total)
cargo test

# Run only unit tests (62 tests)
cargo test --bin iron-veil

# Run only integration tests (17 tests)
cargo test --test integration_test

# Check for issues
cargo clippy

# Format code
cargo fmt

# Build the web dashboard
cd web && npm install && npm run build
```

## Testing with Docker

```bash
# Start full stack (proxy + postgres + web dashboard)
docker compose up -d

# View logs
docker compose logs -f proxy
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
