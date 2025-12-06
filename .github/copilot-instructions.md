# GitHub Copilot Instructions

You are an expert Rust developer building a high-performance database proxy for PII anonymization.

## Tech Stack
- **Core**: Rust (2024 edition)
- **Async Runtime**: `tokio`
- **Web Server**: `axum`
- **CLI**: `clap`
- **Logging**: `tracing`, `tracing-subscriber`
- **Telemetry**: `opentelemetry`, `opentelemetry-otlp`, `tracing-opentelemetry`
- **Protocol Handling**: `tokio-util` (Codecs), `bytes`
- **TLS**: `tokio-rustls`, `rustls`
- **Frontend**: Next.js (React), Tailwind CSS, Shadcn UI

## Project Structure
```
src/
├── main.rs          # Entry point, CLI args, connection routing (PG/MySQL)
├── config.rs        # Configuration loading from proxy.yaml
├── api.rs           # Axum REST API for management dashboard
├── state.rs         # Shared AppState (config, logs, connections)
├── scanner.rs       # Regex-based PII detection
├── db_scanner.rs    # Real database introspection & PII scanning
├── interceptor.rs   # Anonymizer trait + implementations for PG and MySQL
├── telemetry.rs     # OpenTelemetry initialization
└── protocol/
    ├── mod.rs
    ├── postgres.rs  # PostgreSQL wire protocol codec
    └── mysql.rs     # MySQL wire protocol codec
```

## Coding Principles
1.  **Safety & Performance**: Prioritize memory safety. Use `Arc` and `RwLock` for shared state. Aim for zero-copy parsing where possible using `bytes::Bytes` and `BytesMut`.
2.  **Error Handling**: Use `thiserror` for library errors and `anyhow` for application errors. Never use `unwrap()` in production code; always handle `Result` and `Option`.
3.  **Async/Await**: All I/O must be non-blocking. Use `tokio::select!` for concurrent bidirectional proxy loops.
4.  **Functional Style**: Prefer iterators (`map`, `filter`, `fold`) over explicit loops. Use `Option`/`Result` combinators (`and_then`, `map_err`).
5.  **Testing**: Write comprehensive unit tests for all protocol parsing and anonymization logic. Every codec and transformation must be covered.
6.  **Tracing**: Use `#[instrument]` from `tracing` crate on key functions. Add spans for connection handling, query processing, and data masking.

## Protocol Implementation Guidelines
- **PostgreSQL**: Messages have format `[Type: 1 byte][Length: 4 bytes][Payload]`. Length includes itself but NOT the type byte.
- **MySQL**: Packets have format `[Length: 3 bytes LE][Sequence: 1 byte][Payload]`. State machine tracks handshake → auth → command phases.
- **Critical**: When modifying packet payloads (masking), recalculate and update length headers to maintain protocol integrity.

## Key Files to Reference
- `proxy.yaml` - Configuration schema (TLS, telemetry, masking rules)
- `src/protocol/postgres.rs` - Reference implementation for wire protocol codec
- `src/interceptor.rs` - `PacketInterceptor` and `MySqlPacketInterceptor` traits

## Current Capabilities
- PostgreSQL wire protocol (v3.0) with TLS support
- MySQL wire protocol (text protocol results)
- Masking strategies: email, phone, address, credit_card, json
- Heuristic PII detection via regex
- JSON and Array type recursive masking
- Deterministic masking (seeded fake data generation)
- OpenTelemetry distributed tracing
- Management API with live query inspector
- Real database introspection (information_schema queries)
- PII scanning with confidence scores and sample masking

## Frontend Guidelines
- Use Functional Components with Hooks.
- Use Strong Typing with TypeScript.
- State management via React Query (TanStack Query) for server state.
- Follow Shadcn UI patterns for component styling.
