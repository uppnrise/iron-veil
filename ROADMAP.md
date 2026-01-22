# IronVeil Production Readiness Roadmap

## Overview

This document outlines the remaining work needed to make IronVeil production-ready. Items are prioritized by criticality.

---

## 🔴 Critical (Must Have Before Production)

### 1. Graceful Shutdown ✅
- [x] Add signal handling (SIGTERM, SIGINT)
- [x] Drain active connections before shutdown
- [x] Flush OpenTelemetry traces on shutdown
- [x] Add configurable shutdown timeout (`--shutdown-timeout`)

**Files:** `src/main.rs`

### 2. Error Handling - Remove `unwrap()` in Production Code ✅
- [x] Replace `unwrap()` with proper error handling in `main.rs` (buffer parsing)
- [x] Replace `unwrap()` in `api.rs` server startup
- [x] Add graceful error responses instead of panics

**Files:** `src/main.rs`, `src/api.rs`

### 3. Management API Authentication ✅
- [x] Add API key authentication middleware
- [x] Support for JWT tokens (HS256 algorithm)
- [x] Add `api_key` and `jwt_secret` configuration options in `proxy.yaml`
- [x] Protect sensitive endpoints: `/rules`, `/config`, `/scan`, `/connections`, `/schema`, `/logs`

**Files:** `src/api.rs`, `src/config.rs`, `proxy.yaml`

### 4. Connection Limits & Rate Limiting ✅
- [x] Add `max_connections` config option
- [x] Implement connection semaphore/pool
- [x] Add rate limiting for new connections (`connections_per_second`)
- [x] Return proper error when limit reached (connection rejected with warning log)

**Files:** `src/main.rs`, `src/config.rs`

### 5. Connection Timeouts ✅
- [x] Add `idle_timeout_secs` config option (default: 300s)
- [x] Add `connect_timeout_secs` for upstream connections (default: 30s)
- [x] Close idle connections after timeout
- [x] Applied to both PostgreSQL and MySQL protocols

**Files:** `src/main.rs`, `src/config.rs`

### 6. Docker Build Optimization ✅
- [x] Create `.dockerignore` file to exclude:
  - `target/`
  - `.git/`
  - `web/node_modules/`
  - `*.md`
- [x] Reduce build context from 3.4GB to ~1.5MB

**Files:** `.dockerignore`

---

## 🟡 High Priority (Should Have)

### 7. Upstream Health Check ✅
- [x] Background health check task with configurable interval
- [x] Enhanced `/health` endpoint that checks upstream status
- [x] Configurable thresholds (unhealthy_threshold, healthy_threshold)
- [x] Health status tracking with latency metrics
- [x] Returns HTTP 503 when upstream is unhealthy

**Configuration:**
```yaml
health_check:
  enabled: true
  interval_secs: 10
  timeout_secs: 5
  unhealthy_threshold: 3
  healthy_threshold: 1
```

**Files:** `src/main.rs`, `src/api.rs`, `src/state.rs`, `src/config.rs`

### 8. Implement Real Database Scanner ✅
- [x] Replace mocked `/scan` endpoint with actual implementation
- [x] Query `information_schema` for column metadata
- [x] Sample data from tables for PII detection
- [x] Support PostgreSQL schemas (MySQL in future)
- [x] Column name heuristics for PII detection
- [x] Schema discovery endpoint (`POST /schema`)

**API Endpoints:**
- `POST /scan` - Scan database for PII (requires db credentials in body)
- `POST /schema` - Get database schema information

**Request Body:**
```json
{
  "username": "postgres",
  "password": "password",
  "database": "mydb",
  "schema": "public",
  "sample_size": 100,
  "confidence_threshold": 0.5,
  "exclude_tables": ["migrations", "logs"]
}
```

**Files:** `src/db_scanner.rs` (new), `src/api.rs`, `src/state.rs`, `Cargo.toml`

### 9. Rule Persistence ✅
- [x] Save rules added via API back to `proxy.yaml`
- [x] Delete rules via API with persistence
- [x] Add rule export endpoint (`GET /rules/export`)
- [x] Add rule import endpoint (`POST /rules/import`)

**API Endpoints:**
- `POST /rules` - Add new rule (auto-persisted)
- `POST /rules/delete` - Delete rule by index or column/table
- `GET /rules/export` - Export rules as JSON file
- `POST /rules/import` - Import rules from JSON array

**Files:** `src/api.rs`, `src/state.rs`

### 10. Prometheus Metrics (Grafana template pending)
- [x] Add `/metrics` endpoint
- [x] Track: connections (opened/closed/rejected), queries, masked fields, latency
- [x] Integrate with `metrics` and `metrics-exporter-prometheus` crates
- [ ] Add Grafana dashboard template (future enhancement)

**Metrics Exposed:**
- `ironveil_connections_total` - Total connections received
- `ironveil_connections_active` - Currently active connections
- `ironveil_connections_rejected_total` - Rejected connections (by reason)
- `ironveil_queries_total` - Total queries processed (by protocol)
- `ironveil_query_duration_seconds` - Query processing latency histogram
- `ironveil_fields_masked_total` - Total PII fields masked
- `ironveil_masking_errors_total` - Masking errors encountered
- `ironveil_upstream_health_check_latency_ms` - Health check latency
- `ironveil_upstream_healthy` - Upstream health status (0/1)
- `ironveil_upstream_timeouts_total` - Upstream connection timeouts
- `ironveil_idle_timeouts_total` - Idle connection timeouts

**Files:** `src/metrics.rs` (new), `src/api.rs`, `src/state.rs`, `Cargo.toml`

### 11. Frontend Dynamic Version ✅
- [x] Fetch version from `/health` endpoint (already implemented)
- [x] Display upstream connection status dynamically in dashboard
- [x] Show latency metrics in upstream status card
- [x] Update sidebar to show real-time upstream health
- [x] Status indicator reflects overall system health (ok/degraded)

**Files:** `web/src/app/page.tsx`, `web/src/components/sidebar.tsx`

---

## 🟢 Medium Priority (Nice to Have)

### 12. Extended PII Detection ✅
- [x] Add SSN regex pattern (US format: XXX-XX-XXXX)
- [x] Add phone number patterns (US 10-digit format)
- [x] Add passport number patterns (common alphanumeric formats)
- [x] Add IP address detection (IPv4)
- [x] Add date of birth detection (YYYY-MM-DD, MM/DD/YYYY, etc.)
- [ ] Optional: NLP-based name detection (future enhancement)

**PII Types Detected:**
- Email, Credit Card (existing)
- SSN, Phone, IP Address, Date of Birth, Passport (new)

**Files:** `src/scanner.rs`, `src/interceptor.rs`

### 13. Integration Tests ✅
- [x] Add end-to-end tests with real PostgreSQL protocol testing
- [x] Add end-to-end tests with real MySQL protocol testing
- [x] Test TLS/SSL request handling
- [x] Test masking pattern accuracy (regex validation)
- [x] CI pipeline compatible (tests skip gracefully when server not running)

**Test Coverage:**
- API tests: health, metrics, rules, config, connections endpoints
- PostgreSQL tests: connection, SSL request, upstream unavailable handling
- MySQL tests: connection and handshake protocol
- Masking tests: email, credit card, SSN, IP, phone pattern validation
- Protocol tests: message length calculation for PostgreSQL and MySQL

**Files:** `tests/integration_test.rs`, `Cargo.toml` (dev-dependencies)

### 14. Configuration Hot Reload ✅
- [x] Watch `proxy.yaml` for changes using `notify` crate
- [x] Automatically reload rules when file changes (debounced)
- [x] Add API endpoint to trigger manual reload (`POST /config/reload`)
- [x] Graceful error handling if config file is invalid

**Implementation:**
- File watcher uses `notify` crate with 2-second poll interval
- 1-second debounce to prevent rapid reloads
- Manual reload via `POST /config/reload` (auth required)
- Invalid configs are rejected without affecting running config

**Files:** `src/main.rs`, `src/state.rs`, `src/api.rs`, `Cargo.toml`

### 15. Connection Pooling
- [ ] Implement upstream connection pooling
- [ ] Reduce connection overhead
- [ ] Add pool size configuration

**Files:** `src/main.rs`, `src/config.rs`

### 16. Audit Logging ✅
- [x] Log all configuration changes
- [x] Log authentication attempts (success/failure/denied)
- [x] Structured JSON audit log format
- [x] Log rotation support (configurable file size and retention)
- [x] In-memory audit log storage (last 1000 entries)
- [x] API endpoint to query audit logs with filtering

**Audit Events Logged:**
- `auth_attempt` - Authentication success, failure, or denied
- `config_change` - Configuration updates (with old/new values)
- `rule_added` - New masking rule added
- `rule_deleted` - Masking rule removed
- `rules_imported` - Bulk rule import
- `config_reload` - Config reloaded from disk
- `database_scan` - PII scan performed
- `schema_query` - Schema discovery query

**API Endpoint:**
- `GET /audit` - Get audit logs
- `GET /audit?limit=N` - Limit results
- `GET /audit?event_type=<type>` - Filter by event type
- `GET /audit?outcome=<outcome>` - Filter by outcome (success/failure/denied)

**Configuration:**
```yaml
audit:
  enabled: true
  log_to_stdout: false
  log_file: "/var/log/ironveil/audit.log"
  rotation_enabled: true
  max_file_size_bytes: 10485760  # 10MB
  max_rotated_files: 5
  events: []  # Empty = log all events
```

**Files:** `src/audit.rs` (new), `src/api.rs`, `src/state.rs`, `src/config.rs`, `Cargo.toml`

---

## 🔵 Low Priority (Future Enhancements)

### 17. Multi-Database Support
- [ ] Support multiple upstream databases
- [ ] Route based on database name
- [ ] Per-database masking rules

### 18. Query Rewriting
- [ ] Block certain queries (DROP, DELETE without WHERE)
- [ ] Query sanitization
- [ ] Query allow/deny lists

### 19. Caching Layer
- [ ] Cache frequently accessed masked data
- [ ] Reduce upstream load
- [ ] Cache invalidation strategy

### 20. Web UI Enhancements ✅
- [x] Rule testing/preview (with live masking preview dialog)
- [x] Connection statistics graphs (real-time charts using Recharts)
- [x] Dark/light theme toggle (using next-themes)
- [x] Enhanced dashboard with metrics tabs
- [x] Reusable UI component library (Button, Dialog, Tabs, Switch, Badge, etc.)
- [x] Animated transitions with Framer Motion

**Features Implemented:**
- **Rule Testing Dialog**: Test masking strategies with sample data before saving rules
- **Live Preview**: See masked output in real-time as you configure rules
- **Connection Charts**: Area charts showing connections, queries, and masked fields over time
- **Masking Stats**: Bar/distribution charts showing masking operations by strategy
- **Theme System**: Dark/Light/System themes with persistent preference
- **Dashboard Tabs**: Organized view with Connections, Masking Stats, and Activity tabs
- **Enhanced Settings**: Theme toggle, notification settings, strict mode toggles
- **Improved Rules Page**: Quick preview, delete confirmation, strategy badges

**UI Components Added:**
- Button (with variants: default, destructive, outline, secondary, ghost, success, warning)
- Dialog (modal dialogs with Radix UI)
- Switch (toggle switches)
- Tabs (tabbed content)
- Badge (status indicators)
- Input/Select/Label (form components)
- Tooltip (hover tooltips)
- StatsCard (metric display cards)
- Charts (ConnectionsChart, MultiLineChart, MaskingStatsChart, QueryTypesChart)

**Dependencies Added:**
- `recharts` - Charting library
- `next-themes` - Theme management
- `@radix-ui/react-*` - Accessible UI primitives
- `class-variance-authority` - Component variants
- `clsx` + `tailwind-merge` - Conditional class names

**Files:** `web/src/components/`, `web/src/app/`, `web/src/lib/utils.ts`

---

## Progress Tracking

| Category | Total | Completed | Remaining |
|----------|-------|-----------|-----------|
| 🔴 Critical | 6 | 6 | 0 |
| 🟡 High Priority | 5 | 4 | 1 |
| 🟢 Medium Priority | 5 | 4 | 1 |
| 🔵 Low Priority | 4 | 1 | 3 |
| **Total** | **20** | **15** | **5** |

---

## Quick Wins (Can Be Done in < 1 Hour Each)

- [x] Create `.dockerignore` file
- [x] Fix `unwrap()` calls (5 locations)
- [x] Add connection timeout config
- [ ] Fetch version dynamically in settings page

---

## Definition of Done

For each item to be considered complete:
- [ ] Implementation complete
- [ ] Unit tests added/updated
- [ ] Documentation updated
- [ ] Code reviewed
- [ ] Tested in Docker environment
