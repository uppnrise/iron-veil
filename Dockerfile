# Build Stage
FROM rust:latest AS builder

WORKDIR /usr/src/app
COPY . .

# Build the application in release mode
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim

# Install OpenSSL and CA certificates (useful for future TLS support)
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/bin

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/ironveil .

# Copy the configuration file (default)
COPY --from=builder /usr/src/app/proxy.yaml .

# Expose the proxy port and API port
EXPOSE 6543
EXPOSE 3001

# Run the binary
CMD ["./ironveil", "--upstream-host", "postgres", "--upstream-port", "5432", "--config", "proxy.yaml"]
