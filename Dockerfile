# Build a fully static binary so the runtime image does not need an OS layer.
FROM rust:alpine AS builder

RUN apk add --no-cache build-base ca-certificates cmake file perl

WORKDIR /usr/src/app
COPY . .

RUN cargo build --release \
    && file target/release/iron-veil | grep -Eq "statically linked|static-pie linked"

# A scratch runtime contains no package manager or OS packages for scanners to flag.
FROM scratch

WORKDIR /usr/local/bin

COPY --from=builder /usr/src/app/target/release/iron-veil .
COPY --from=builder /usr/src/app/proxy.yaml .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

USER 65532:65532

# Expose the proxy port and API port
EXPOSE 6543
EXPOSE 3001

CMD ["./iron-veil", "--upstream-host", "postgres", "--upstream-port", "5432", "--config", "proxy.yaml"]
