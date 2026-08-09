# Changelog

All notable changes to IronVeil are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows semantic versioning.

## [Unreleased]

A production-readiness pass over the whole repository, driven by a
multi-model audit and a black-box vetting run against MySQL 8.4.

### Breaking

- `proxy.yaml` is now validated on load: unknown keys and unknown masking
  strategies are startup errors instead of being silently ignored.
- Heuristic PII detection is configurable and the ambiguous detectors are
  **off by default**. Previously every text-format date became `1900-01-01`,
  every dotted quad became `0.0.0.0`, and every bare 16-digit value was
  rewritten — with no rule and no log. Set `heuristics.types` to re-enable
  `credit_card`, `ip`, `dob` or `passport`.
- The management API binds `127.0.0.1` by default and refuses to start on a
  non-loopback address without `api.api_key` or `api.jwt_secret`.
- `POST /rules/delete` takes `{table, column}`; the positional `index` form is
  gone (it deleted the wrong rule when the list changed between fetch and
  delete).
- `GET /health` no longer returns the upstream host, port or raw error text,
  and answers 503 with `"status": "starting"` until the first probe completes.
- `GET /logs` no longer contains pre-masking values.
- MySQL server-side prepared statements (binary protocol) are rejected with
  `ER_UNSUPPORTED_PS` instead of being forwarded with masking bypassed.
- The dashboard no longer reads credentials from `NEXT_PUBLIC_*` env vars.
- The crate is now a library plus a binary (`src/lib.rs`).

### Added

- `masking_secret` (or `IRONVEIL_MASKING_SECRET`) keys the deterministic
  masking functions, so pseudonyms cannot be confirmed or brute-forced.
- `name` and `text` masking strategies; `address` now yields a street address.
- Client and upstream TLS for MySQL, and multi-round authentication relay, so
  `caching_sha2_password` full auth completes.
- `--bind` and `--api-bind`; `api.bind` and `api.cors_origins`.
- Rule matching on true provenance (MySQL `org_name`/`org_table`, PostgreSQL
  `table_oid`+`attnum`), case-insensitively.
- Email and phone masking inside free text.
- 0xFFFFFF multi-packet reassembly for MySQL payloads at or above 16 MiB.
- `ironveil_binary_protocol_rejected_total` and
  `ironveil_copy_passthrough_total` metrics; Prometheus histograms now export
  `_bucket` series, fixing the shipped Grafana p95 panels.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and Security Posture,
  Protocol Support and Scanner Support sections in the README (the offline
  scanner is PostgreSQL-only; runtime masking covers both protocols).
- `docker-compose.tls.yml` overlay; CI jobs for the dashboard, `cargo audit`
  and the end-to-end masking suite.

### Changed

- `serde_yaml` (archived upstream) replaced with `serde_yaml_ng`;
  `thiserror` 1 → 2.

### Fixed

- Credit-card detection accepts 13–19 digits and validates Luhn; phone
  detection requires visible formatting, so bare identifiers survive.
- Explicit `json` rules fail closed instead of forwarding the raw value.
- The MySQL codec forwards every unmodified packet type verbatim, bounds-checks
  every read (no panics on short or empty packets), errors on truncated result
  rows instead of substituting NULL, and patches handshake capability bytes in
  place.
- The PostgreSQL codec caps frame lengths and bounds-checks the `T` and `P`
  branches; a 4-byte packet can no longer force a multi-GB allocation.
- SIGTERM actually drains: connection tasks receive cancellation and close with
  a protocol-level error.
- `accept()` errors no longer terminate the process; the config watcher no
  longer blocks a runtime worker; upstream TLS config is built once at startup.
- Mutating API handlers persist atomically before swapping live state.
- Audit logging warns when it has no durable sink, records the client IP, and
  serializes rotation.
- Scanner connects via `tokio_postgres::Config` (no libpq string injection),
  clamps `sample_size`, quotes identifiers, and no longer panics on multi-byte
  sample values.
- Dashboard: real numbers instead of fabricated tiles, error banners instead of
  silent empty states, health that fails to unknown rather than green, and
  `next` upgraded past the critical RCE advisory.
- `ironveil_query_duration_seconds` measures the real query round trip
  (PostgreSQL ReadyForQuery, MySQL result-set terminator) instead of an
  in-memory lock acquisition, which read ~0 forever.
- Masking stats are recorded once per row instead of once per masked field,
  removing a process-global write lock from the packet hot path.
- A segmented PostgreSQL startup prelude no longer skips the TLS-aware branch
  and get an unconditional cleartext denial.
- `release.sh` can no longer cut a release from a failing test run.
- Integration probes detect a dead proxy instead of reporting it up.

## [0.1.1]

Initial published release.
