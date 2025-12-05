# Build Stage
FROM rust:latest AS builder

WORKDIR /usr/src/app
COPY . .

# Build the application in release mode
RUN cargo build --release

# Runtime Stage - use trixie to match glibc version from rust:latest
FROM debian:trixie-slim

# Install OpenSSL and CA certificates (useful for future TLS support)
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/iron-veil .

# Copy the configuration file (default)
COPY --from=builder /usr/src/app/proxy.yaml .

# Expose the proxy port and API port
EXPOSE 6543
EXPOSE 3001

# Run the binary
CMD ["./iron-veil", "--upstream-host", "postgres", "--upstream-port", "5432", "--config", "proxy.yaml"]
