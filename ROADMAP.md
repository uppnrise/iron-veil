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

### 5. Connection Timeouts
- [ ] Add `idle_timeout` config option
- [ ] Add `connect_timeout` for upstream connections
- [ ] Implement keepalive checks
- [ ] Clean up stale connections

**Files:** `src/main.rs`, `src/config.rs`

### 6. Docker Build Optimization
- [ ] Create `.dockerignore` file to exclude:
  - `target/`
  - `.git/`
  - `web/node_modules/`
  - `*.md`
- [ ] Reduce build context from 2.6GB to ~10MB

**Files:** `.dockerignore` (new)

---

## 🟡 High Priority (Should Have)

### 7. Upstream Health Check
- [ ] Verify upstream database connectivity at startup
- [ ] Add `/health` endpoint that checks upstream status
- [ ] Configurable retry logic for upstream connection failures
- [ ] Circuit breaker pattern for upstream failures

**Files:** `src/main.rs`, `src/api.rs`

### 8. Implement Real Database Scanner
- [ ] Replace mocked `/scan` endpoint with actual implementation
- [ ] Query `information_schema` for column metadata
- [ ] Sample data from tables for PII detection
- [ ] Support both PostgreSQL and MySQL schemas

**Files:** `src/api.rs`, `src/scanner.rs`

### 9. Rule Persistence
- [ ] Save rules added via API back to `proxy.yaml`
- [ ] Or add database storage option (SQLite/PostgreSQL)
- [ ] Add rule versioning/history
- [ ] Add rule import/export endpoints

**Files:** `src/api.rs`, `src/config.rs`

### 10. Prometheus Metrics
- [ ] Add `/metrics` endpoint
- [ ] Track: connections, queries, masked fields, latency
- [ ] Integrate with `opentelemetry` metrics
- [ ] Add Grafana dashboard template

**Files:** `src/api.rs`, `src/telemetry.rs`

### 11. Frontend Dynamic Version
- [ ] Fetch version from `/health` endpoint instead of hardcoded
- [ ] Display upstream connection status dynamically

**Files:** `web/src/app/settings/page.tsx`

---

## 🟢 Medium Priority (Nice to Have)

### 12. Extended PII Detection
- [ ] Add SSN regex pattern
- [ ] Add phone number patterns (international)
- [ ] Add passport number patterns
- [ ] Add IP address detection
- [ ] Add date of birth detection
- [ ] Optional: NLP-based name detection

**Files:** `src/scanner.rs`

### 13. Integration Tests
- [ ] Add end-to-end tests with real PostgreSQL
- [ ] Add end-to-end tests with real MySQL
- [ ] Test TLS connections
- [ ] Test masking accuracy
- [ ] CI pipeline integration

**Files:** `tests/` (new directory)

### 14. Configuration Hot Reload
- [ ] Watch `proxy.yaml` for changes
- [ ] Reload rules without restart
- [ ] Add API endpoint to trigger reload

**Files:** `src/config.rs`, `src/main.rs`

### 15. Connection Pooling
- [ ] Implement upstream connection pooling
- [ ] Reduce connection overhead
- [ ] Add pool size configuration

**Files:** `src/main.rs`, `src/config.rs`

### 16. Audit Logging
- [ ] Log all configuration changes
- [ ] Log authentication attempts
- [ ] Structured audit log format
- [ ] Log rotation support

**Files:** `src/api.rs`, `src/state.rs`

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

### 20. Web UI Enhancements
- [ ] Rule testing/preview
- [ ] Visual query builder
- [ ] Connection statistics graphs
- [ ] Dark/light theme toggle

---

## Progress Tracking

| Category | Total | Completed | Remaining |
|----------|-------|-----------|-----------|
| 🔴 Critical | 6 | 0 | 6 |
| 🟡 High Priority | 5 | 0 | 5 |
| 🟢 Medium Priority | 5 | 0 | 5 |
| 🔵 Low Priority | 4 | 0 | 4 |
| **Total** | **20** | **0** | **20** |

---

## Quick Wins (Can Be Done in < 1 Hour Each)

1. Create `.dockerignore` file
2. Fix `unwrap()` calls (5 locations)
3. Add connection timeout config
4. Fetch version dynamically in settings page

---

## Definition of Done

For each item to be considered complete:
- [ ] Implementation complete
- [ ] Unit tests added/updated
- [ ] Documentation updated
- [ ] Code reviewed
- [ ] Tested in Docker environment
