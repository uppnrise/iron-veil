#!/bin/bash
#
# Generate a local CA and a server certificate for IronVeil / the demo
# postgres container.
#
# Safe by default:
#   - Existing key material (ca.key, server.key) is never overwritten
#     unless --force is given.
#   - If a CA already exists it is reused to re-sign a fresh server
#     certificate (renewal), so previously distributed ca.crt files stay valid.
#
# Usage:
#   ./scripts/generate_certs.sh [--force]
#
#   --force   Regenerate ALL key material, including the CA. Clients that
#             trust the old ca.crt will need the new one.
set -euo pipefail

# Directory to store certificates
CERT_DIR="${CERT_DIR:-certs}"

FORCE=false
for arg in "$@"; do
    case "$arg" in
        -f|--force)
            FORCE=true
            ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | tail -n +2
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (see --help)" >&2
            exit 1
            ;;
    esac
done

if ! command -v openssl > /dev/null 2>&1; then
    echo "Error: openssl is required but not installed." >&2
    exit 1
fi

mkdir -p "$CERT_DIR"

# 1+2. CA key and certificate
if [ -f "$CERT_DIR/ca.key" ] && [ "$FORCE" = false ]; then
    echo "Reusing existing CA key ($CERT_DIR/ca.key). Use --force to regenerate."
else
    if [ -f "$CERT_DIR/ca.key" ]; then
        echo "--force given: regenerating CA (previously distributed ca.crt files become invalid)"
    fi
    echo "Generating CA key..."
    openssl genrsa -out "$CERT_DIR/ca.key" 2048

    echo "Generating CA certificate (valid for 10 years)..."
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
      -sha256 -days 3650 -out "$CERT_DIR/ca.crt" \
      -subj "/C=US/ST=State/L=City/O=IronVeil/OU=Security/CN=IronVeilRootCA"
fi

if [ ! -f "$CERT_DIR/ca.crt" ]; then
    echo "Regenerating CA certificate from existing CA key..."
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" \
      -sha256 -days 3650 -out "$CERT_DIR/ca.crt" \
      -subj "/C=US/ST=State/L=City/O=IronVeil/OU=Security/CN=IronVeilRootCA"
fi

# 3. Server private key (reused on renewal)
if [ -f "$CERT_DIR/server.key" ] && [ "$FORCE" = false ]; then
    echo "Reusing existing server key ($CERT_DIR/server.key). Use --force to regenerate."
else
    echo "Generating Server key..."
    openssl genrsa -out "$CERT_DIR/server.key" 2048
fi

# 4. Certificate Signing Request (CSR) configuration
cat > "$CERT_DIR/csr.conf" <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = State
L = City
O = IronVeil
OU = Proxy
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
DNS.2 = iron-veil
DNS.3 = postgres
IP.1 = 127.0.0.1
IP.2 = 0.0.0.0
EOF

# 5. Generate the CSR (runs on renewal too: re-signs even when keys are reused)
echo "Generating Server CSR..."
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" -config "$CERT_DIR/csr.conf"

# 6. Server certificate signed by the CA (valid for 1 year)
echo "Generating Server Certificate..."
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial -out "$CERT_DIR/server.crt" -days 365 -sha256 \
  -extfile "$CERT_DIR/csr.conf" -extensions req_ext

# Cleanup
rm -f "$CERT_DIR/server.csr" "$CERT_DIR/csr.conf"

# 7. Fix permissions/ownership so the postgres container (uid 999) can use
#    the key when ./certs is bind-mounted (see docker-compose.tls.yml).
chmod 600 "$CERT_DIR/server.key"
if chown 999:999 "$CERT_DIR/server.key" 2>/dev/null; then
    echo "server.key ownership set to 999:999 (postgres container user)"
elif command -v sudo > /dev/null 2>&1 && sudo -n chown 999:999 "$CERT_DIR/server.key" 2>/dev/null; then
    echo "server.key ownership set to 999:999 via sudo (postgres container user)"
else
    echo ""
    echo "NOTE: could not chown $CERT_DIR/server.key to 999:999."
    echo "If you use docker-compose.tls.yml, the postgres container needs to"
    echo "read the key as uid 999. Run:"
    echo "  sudo chown 999:999 $CERT_DIR/server.key"
fi

echo "------------------------------------------------"
echo "Certificates generated in '$CERT_DIR/'"
echo "------------------------------------------------"
echo "1. server.key: Private key (Keep secure!)"
echo "2. server.crt: Public certificate (Configure in proxy.yaml)"
echo "3. ca.crt:     Root CA (Distribute to clients to trust the connection)"
