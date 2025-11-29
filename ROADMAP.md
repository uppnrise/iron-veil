# Project Roadmap: Database Anonymization Proxy

## Phase 1: The "Walking Skeleton" (Core Proxy Logic)
- [x] **1.1 Rust Project Scaffolding**
    - [x] Initialize Rust project with `cargo new`
    - [x] Add dependencies: `tokio`, `clap`, `tracing`, `bytes`, `tokio-util`
    - [x] Set up basic TCP listener and upstream connection forwarding
- [x] **1.2 Protocol Parsing (PostgreSQL)**
    - [x] Implement `tokio-util` Codec for Postgres Wire Protocol (v3.0)
    - [x] Parse `StartupMessage` and Handshake
    - [x] Parse `SimpleQuery` and `ExtendedQuery` flows
    - [x] Intercept `RowDescription` packets (metadata)
    - [x] Intercept `DataRow` packets (actual data)
- [x] **1.3 Interception Middleware**
    - [x] Create `PacketInterceptor` trait
    - [x] Implement logic to modify `DataRow` byte buffers
    - [x] Ensure packet length headers are recalculated correctly
- [x] **1.4 Basic Faker Implementation**
    - [x] Integrate `fake-rs` crate
    - [x] Hardcode a rule to replace a specific column (e.g., "email") with fake data

## Phase 2: The "Smart" Engine (Configuration & Detection)
- [x] **2.1 Configuration System**
    - [x] Define `proxy.yaml` structure
    - [x] Implement config loader
    - [x] Map table/column names to masking strategies
- [x] **2.2 Deterministic Masking**
    - [x] Implement seeded hashing / format-preserving encryption
    - [x] Ensure "John Doe" always maps to the same fake identity
- [ ] **2.3 NLP & Heuristic Detection**
    - [x] Implement Regex scanner for PII (Credit Cards, SSNs, Emails)
    - [ ] (Optional) Integrate `rust-bert` or `ort` for NLP-based name detection
- [ ] **2.4 Complex Type Handling**
    - [x] Support JSON/JSONB masking
    - [x] Support Array types

## Phase 3: Control Plane (Web UI)
- [x] **3.1 Management API (Rust)**
    - [x] Set up `Axum` web server alongside the proxy
    - [x] Implement endpoints: `/connections`, `/schema`, `/rules`, `/logs`
- [x] **3.2 Frontend Setup**
    - [x] Initialize Next.js project with Tailwind & TypeScript
    - [x] Setup Shadcn/UI-style components and "Obsidian" Dark Theme
    - [x] Implement Sidebar Layout and Dashboard with Real-time Data
- [x] **3.3 PII Scanner UI**
    - [x] Create "Scan Database" feature
    - [x] Display PII report and allow "One-click Apply" for rules
- [x] **3.4 Live Query Inspector**
    - [x] Build "Network Tab" for DB queries
    - [x] Show diff view (Original vs. Masked Data)
- [x] **3.5 Rules Management UI**
    - [x] View active masking rules
    - [x] Add/Edit/Delete rules manually

## Phase 4: Enterprise Hardening
- [ ] **4.1 Security**
    - [ ] Implement TLS termination (Client -> Proxy)
    - [ ] Implement Upstream TLS (Proxy -> Prod DB)
- [ ] **4.2 Performance & Observability**
    - [ ] Optimize for Zero-Copy parsing where possible
    - [ ] Implement Connection Pooling (`bb8` or `deadpool`)
    - [ ] Integrate OpenTelemetry (OTEL) for distributed tracing
- [ ] **4.3 MySQL Support**
    - [ ] Implement MySQL Wire Protocol parser
    - [ ] Adapt interception logic for MySQL packets

## Phase 5: Deployment & Infrastructure
- [x] **5.1 Containerization**
    - [x] Create production-ready `Dockerfile` (Multi-stage build)
    - [x] Create `docker-compose.yml` for full stack simulation (App + Proxy + DB)
