# Build Stage
FROM rust:1.97-slim AS builder

WORKDIR /usr/src/app

# Cache dependency compilation: build a stub crate with just the manifests
# so dependency layers are reused when only src/ changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# Build the real application (touch main.rs so cargo rebuilds the binary
# instead of reusing the stub artifact)
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# Runtime Stage - trixie matches the glibc of the rust:1.97-slim builder
FROM debian:trixie-slim

# ca-certificates for outbound TLS, curl for the container HEALTHCHECK
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Run as a dedicated non-root user
RUN useradd -r -u 10001 -s /usr/sbin/nologin ironveil

WORKDIR /usr/local/bin

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/iron-veil .

# Copy the configuration file (default)
COPY proxy.yaml .

USER ironveil

# Expose the proxy port and API port
EXPOSE 6543
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3001/health || exit 1

# Run the binary
CMD ["./iron-veil", "--upstream-host", "postgres", "--upstream-port", "5432", "--config", "proxy.yaml"]
