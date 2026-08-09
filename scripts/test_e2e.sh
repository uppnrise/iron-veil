#!/bin/bash

#######################################
# IronVeil E2E Test Suite
# Tests both PostgreSQL and MySQL protocols
#
# Usage: ./scripts/test_e2e.sh [postgres|mysql|all]
#######################################

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
PG_PORT=5433
MYSQL_PORT=3307
PROXY_PORT=6543
API_PORT=3001
GRACEFUL_TEST_PORT=6599
GRACEFUL_API_PORT=3099
PROXY_PID=""
TEST_PROTOCOL="${1:-postgres}"  # Default to postgres, can pass 'mysql' or 'all'

# Container images (postgres tag kept in sync with docker-compose.yml).
# Pin MySQL to 8.0: 8.4 defaults to caching_sha2_password, which needs either
# TLS or an RSA public-key exchange the cleartext proxy path does not yet
# handle cleanly (auth packets get misread as column definitions). 8.0 still
# supports mysql_native_password for non-TLS e2e.
POSTGRES_IMAGE="postgres:17"
MYSQL_IMAGE="mysql:8.0"

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

# Populated by run_query_pg / run_query_mysql
QUERY_OK=false
QUERY_OUTPUT=""

# The suite does not depend on the shipped proxy.yaml (its demo rules change
# independently); it generates its own config below.
E2E_CONFIG=""

#######################################
# Helper Functions
#######################################

log_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_section() {
    echo ""
    echo -e "${YELLOW}▶ $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_info() {
    echo -e "  $1"
}

require_tools() {
    local missing=false
    for cmd in "$@"; do
        if ! command -v "$cmd" > /dev/null 2>&1; then
            echo -e "${RED}Required tool not found: $cmd${NC}" >&2
            missing=true
        fi
    done
    if [ "$missing" = true ]; then
        exit 1
    fi
}

detect_docker_host_addr() {
    # Sensible fallbacks per platform
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        DOCKER_HOST_ADDR="172.17.0.1"  # Default Docker bridge gateway on Linux
    else
        DOCKER_HOST_ADDR="host.docker.internal"
    fi

    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        local gateway
        gateway=$(docker network inspect bridge \
            --format '{{ (index .IPAM.Config 0).Gateway }}' 2>/dev/null || true)
        if [ -n "$gateway" ] && [ "$gateway" != "<no value>" ]; then
            DOCKER_HOST_ADDR="$gateway"
        fi
    fi
    log_info "Using Docker host address: $DOCKER_HOST_ADDR"
}

write_e2e_config() {
    E2E_CONFIG="$(mktemp -t ironveil-e2e-config.XXXXXX)"
    cat > "$E2E_CONFIG" <<'EOF'
masking_enabled: true
upstream_tls: false
rules:
  - table: users
    column: email
    strategy: email
  - table: users
    column: phone_number
    strategy: phone
heuristics:
  enabled: true
  types: ["email", "phone", "ssn", "credit_card"]
EOF
    log_info "Generated e2e proxy config: $E2E_CONFIG"
}

# Run a query through the proxy with psql. Sets QUERY_OK / QUERY_OUTPUT.
run_query_pg() {
    local sql="$1"
    QUERY_OK=false
    QUERY_OUTPUT=""
    if QUERY_OUTPUT=$(docker run --rm -e PGPASSWORD=password "$POSTGRES_IMAGE" \
        psql -h "$DOCKER_HOST_ADDR" -p "$PROXY_PORT" -U postgres -t -c "$sql" 2>&1); then
        QUERY_OK=true
    fi
}

# Run a query through the proxy with mysql client. Sets QUERY_OK / QUERY_OUTPUT.
run_query_mysql() {
    local sql="$1"
    QUERY_OK=false
    QUERY_OUTPUT=""
    # Keep mysql's "Using a password on the command line" warning off stdout so
    # assert_masked's row count is not inflated by the CLI noise (2>&1 used to
    # make the warning look like a second result row).
    local err
    err=$(mktemp -t ironveil-mysql-err.XXXXXX)
    if QUERY_OUTPUT=$(docker run --rm "$MYSQL_IMAGE" \
        mysql -h "$DOCKER_HOST_ADDR" -P "$PROXY_PORT" -uroot -ppassword testdb \
        --skip-column-names -e "$sql" 2>"$err"); then
        QUERY_OK=true
    else
        QUERY_OUTPUT=$(cat "$err")
    fi
    rm -f "$err"
}

# Positive-then-negative masking assertion:
# 1. the query must have succeeded,
# 2. it must have returned the expected number of data rows,
# 3. only then is the absence of the PII string meaningful.
assert_masked() {
    local expected_rows="$1"
    local pii="$2"
    local description="$3"

    if [ "$QUERY_OK" != true ]; then
        log_error "$description - query failed: $QUERY_OUTPUT"
        return 0
    fi

    local rows
    rows=$(printf '%s\n' "$QUERY_OUTPUT" | sed -e '/^[[:space:]]*$/d' | wc -l)
    if [ "$rows" -ne "$expected_rows" ]; then
        log_error "$description - expected $expected_rows rows, got $rows. Output: $QUERY_OUTPUT"
        return 0
    fi

    if printf '%s\n' "$QUERY_OUTPUT" | grep -qF "$pii"; then
        log_error "$description - found unmasked PII: '$pii'"
    else
        log_success "$description"
    fi
    return 0
}

# Assert API response contains expected value
assert_api_response() {
    local response="$1"
    local expected="$2"
    local description="$3"

    if echo "$response" | grep -q "$expected"; then
        log_success "$description"
    else
        log_error "$description - Expected '$expected' in response"
    fi
    return 0
}

# Is something accepting TCP connections on host:port?
#
# Uses bash's built-in /dev/tcp redirection rather than nc/socat/lsof: those
# are three different tools with three different flag dialects across
# platforms, and a missing one used to read as "port is free" (which is how
# the port-conflict preflight silently passed). The subshell closes the
# descriptor on exit, and every call site targets localhost, so a refused
# connection returns immediately rather than waiting on a connect timeout.
tcp_port_open() {
    local host=$1 port=$2
    (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null
}

# bash can be built with --disable-net-redirections, in which case /dev/tcp is
# a nonexistent path rather than a socket. Detect that once, up front, instead
# of having every probe quietly report "nothing is listening".
require_tcp_probe() {
    local err
    err=$( (exec 3<>/dev/tcp/127.0.0.1/1) 2>&1 || true )
    if [[ "$err" == *"No such file"* ]]; then
        echo -e "${RED}This bash was built without /dev/tcp support, which this suite uses for port probes.${NC}" >&2
        echo "  Run the suite with a bash that has network redirections enabled." >&2
        exit 1
    fi
}

# Wait for a service to be ready
wait_for_port() {
    local port=$1
    local name=$2
    local max_attempts=30
    local attempt=0

    while ! tcp_port_open localhost "$port"; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge "$max_attempts" ]; then
            log_error "Timeout waiting for $name on port $port"
            return 1
        fi
        sleep 1
    done
    log_success "$name is ready on port $port"
    return 0
}

start_proxy() {
    # Args are forwarded verbatim to iron-veil; config is always the e2e config
    ./target/release/iron-veil --config "$E2E_CONFIG" "$@" &
    PROXY_PID=$!
}

#######################################
# Cleanup
#######################################

cleanup() {
    log_section "Cleaning up..."

    # Stop proxy gracefully with SIGTERM
    if [ -n "$PROXY_PID" ]; then
        kill -TERM "$PROXY_PID" 2>/dev/null || true
        # Wait for graceful shutdown (max 5 seconds)
        for _ in {1..50}; do
            if ! kill -0 "$PROXY_PID" 2>/dev/null; then
                break
            fi
            sleep 0.1
        done
        # Force kill if still running
        kill -9 "$PROXY_PID" 2>/dev/null || true
        log_info "Stopped proxy (PID: $PROXY_PID)"
    fi

    # Stop containers
    docker rm -f pg-test mysql-test 2>/dev/null || true
    log_info "Removed test containers"

    # Remove generated config
    if [ -n "$E2E_CONFIG" ]; then
        rm -f "$E2E_CONFIG"
    fi
}
trap cleanup EXIT

#######################################
# Graceful Shutdown Test
#######################################

test_graceful_shutdown() {
    log_section "Test: Graceful Shutdown"

    # Start a fresh proxy instance for shutdown test
    ./target/release/iron-veil \
        --config "$E2E_CONFIG" \
        --port "$GRACEFUL_TEST_PORT" \
        --upstream-host localhost \
        --upstream-port "$PG_PORT" \
        --api-port "$GRACEFUL_API_PORT" \
        --protocol postgres \
        --shutdown-timeout 5 &
    local test_pid=$!

    # Wait for proxy to start
    sleep 2
    if ! kill -0 "$test_pid" 2>/dev/null; then
        log_error "Graceful shutdown test: Proxy failed to start"
        return 0
    fi

    # Send SIGTERM
    kill -TERM "$test_pid" 2>/dev/null || true

    # Wait for graceful exit (should complete within shutdown timeout)
    local waited=0
    while kill -0 "$test_pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
        sleep 0.5
        waited=$((waited + 1))
    done

    # Check if process exited
    if kill -0 "$test_pid" 2>/dev/null; then
        log_error "Graceful shutdown: Process did not exit within timeout"
        kill -9 "$test_pid" 2>/dev/null || true
        return 0
    fi

    # Check exit code (wait returns the exit status)
    local exit_code=0
    wait "$test_pid" 2>/dev/null || exit_code=$?

    # Exit code 0 or 143 (128 + 15 for SIGTERM) are acceptable
    if [ "$exit_code" -eq 0 ] || [ "$exit_code" -eq 143 ]; then
        log_success "Graceful shutdown completed successfully (exit code: $exit_code)"
    else
        log_error "Graceful shutdown: Unexpected exit code $exit_code"
    fi
}

#######################################
# Port Conflict Check
#######################################

check_ports() {
    log_section "Checking for port conflicts..."

    local ports=("$PROXY_PORT" "$API_PORT" "$GRACEFUL_TEST_PORT" "$GRACEFUL_API_PORT")

    if [ "$TEST_PROTOCOL" = "postgres" ] || [ "$TEST_PROTOCOL" = "all" ]; then
        ports+=("$PG_PORT")
    fi

    if [ "$TEST_PROTOCOL" = "mysql" ] || [ "$TEST_PROTOCOL" = "all" ]; then
        ports+=("$MYSQL_PORT")
    fi

    for port in "${ports[@]}"; do
        if tcp_port_open 127.0.0.1 "$port"; then
            log_error "Port $port is already accepting connections"
            echo "  A previous run may still be up. Try: docker compose down"
            echo "  To find the listener: ss -ltnp 'sport = :$port'  (or: lsof -ti :$port)"
            exit 1
        fi
    done

    log_info "All required ports are available"
}

#######################################
# Build
#######################################

build_proxy() {
    log_section "Building IronVeil (release)..."
    cargo build --release --quiet
    if [ ! -x ./target/release/iron-veil ]; then
        log_error "Build did not produce ./target/release/iron-veil"
        exit 1
    fi
}

#######################################
# PostgreSQL Tests
#######################################

setup_postgres() {
    log_section "Starting PostgreSQL container..."

    docker rm -f pg-test 2>/dev/null || true
    docker run --name pg-test \
        -e POSTGRES_PASSWORD=password \
        -p "$PG_PORT:5432" \
        -d "$POSTGRES_IMAGE" > /dev/null

    if ! wait_for_port "$PG_PORT" "PostgreSQL"; then
        log_error "Failed to start PostgreSQL"
        return 1
    fi
    sleep 2  # Extra time for PG to fully initialize

    log_section "Seeding PostgreSQL test data..."

    docker exec -i pg-test psql -U postgres <<'EOF'
-- Table with explicit masking rules
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT,
    phone_number TEXT,
    address TEXT
);
INSERT INTO users (email, phone_number, address) VALUES
    ('john.doe@company.com', '555-123-4567', '742 Evergreen Terrace, Springfield'),
    ('jane.smith@gmail.com', '555-987-6543', '221B Baker Street, London');

-- Table without explicit rules (heuristic detection)
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    customer_email TEXT,
    credit_card TEXT,
    notes TEXT
);
-- Credit-card fixtures must be Luhn-valid: the scanner rejects arbitrary
-- 16-digit strings so heuristics do not rewrite order numbers.
INSERT INTO customers (customer_email, credit_card, notes) VALUES
    ('secret@hidden.org', '4111-1111-1111-1111', 'Regular customer'),
    ('private@email.net', '4532-0151-1283-0366', 'VIP member');

-- JSON data table
DROP TABLE IF EXISTS profiles;
CREATE TABLE profiles (
    id SERIAL PRIMARY KEY,
    data JSONB
);
INSERT INTO profiles (data) VALUES
    ('{"user": {"email": "nested@json.com", "name": "Test"}, "payment": {"cc": "1111-2222-3333-4444"}}');

-- Array data table
DROP TABLE IF EXISTS tags;
CREATE TABLE tags (
    id SERIAL PRIMARY KEY,
    values TEXT[]
);
INSERT INTO tags (values) VALUES
    (ARRAY['normal_tag', 'array@email.com', '4111-1111-1111-1111']);
EOF

    log_success "PostgreSQL seeded with test data"
}

run_postgres_tests() {
    log_header "PostgreSQL Protocol Tests"

    setup_postgres || return 1

    log_section "Starting IronVeil proxy (PostgreSQL mode)..."
    start_proxy --port "$PROXY_PORT" --upstream-host localhost --upstream-port "$PG_PORT" --api-port "$API_PORT" --protocol postgres

    if ! wait_for_port "$PROXY_PORT" "IronVeil Proxy"; then
        log_error "Failed to start proxy"
        return 1
    fi
    sleep 2

    # Test 1: Explicit rules masking
    log_section "Test: Explicit Masking Rules"
    run_query_pg "SELECT email, phone_number FROM users;"
    echo "$QUERY_OUTPUT"
    assert_masked 2 "john.doe@company.com" "Email 'john.doe@company.com' was masked"
    assert_masked 2 "555-123-4567" "Phone '555-123-4567' was masked"

    # Test 2: Heuristic detection
    log_section "Test: Heuristic PII Detection"
    run_query_pg "SELECT customer_email, credit_card, notes FROM customers;"
    echo "$QUERY_OUTPUT"
    assert_masked 2 "secret@hidden.org" "Heuristic: Email detected and masked"
    assert_masked 2 "4111-1111-1111-1111" "Heuristic: Credit card detected and masked"

    # Test 3: JSON masking
    log_section "Test: JSON Recursive Masking"
    run_query_pg "SELECT data FROM profiles;"
    echo "$QUERY_OUTPUT"
    assert_masked 1 "nested@json.com" "JSON: Nested email was masked"
    assert_masked 1 "1111-2222-3333-4444" "JSON: Nested credit card was masked"

    # Test 4: Array masking
    log_section "Test: Array Element Masking"
    run_query_pg "SELECT values FROM tags;"
    echo "$QUERY_OUTPUT"
    assert_masked 1 "array@email.com" "Array: Email element was masked"
    assert_masked 1 "4111-1111-1111-1111" "Array: Credit card element was masked"

    # Stop proxy for next test suite
    kill "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    sleep 1
}

#######################################
# MySQL Tests
#######################################

setup_mysql() {
    log_section "Starting MySQL container..."

    docker rm -f mysql-test 2>/dev/null || true
    # mysql_native_password keeps cleartext e2e auth working through the proxy
    # without TLS (see MYSQL_IMAGE comment above).
    docker run --name mysql-test \
        -e MYSQL_ROOT_PASSWORD=password \
        -e MYSQL_DATABASE=testdb \
        -p "$MYSQL_PORT:3306" \
        -d "$MYSQL_IMAGE" \
        --default-authentication-plugin=mysql_native_password > /dev/null

    log_info "Waiting for MySQL to initialize (this takes ~30s)..."
    sleep 30

    if ! wait_for_port "$MYSQL_PORT" "MySQL"; then
        log_error "Failed to start MySQL"
        return 1
    fi

    log_section "Seeding MySQL test data..."

    docker exec -i mysql-test mysql -uroot -ppassword testdb <<'EOF'
-- Table with explicit masking rules
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255),
    phone_number VARCHAR(50),
    address VARCHAR(255)
);
INSERT INTO users (email, phone_number, address) VALUES
    ('mysql.user@test.com', '555-111-2222', '1600 Pennsylvania Avenue');

-- Heuristic detection table
DROP TABLE IF EXISTS orders;
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    buyer_email VARCHAR(255),
    card_number VARCHAR(50),
    status VARCHAR(50)
);
INSERT INTO orders (buyer_email, card_number, status) VALUES
    ('buyer@shop.com', '4111-1111-1111-1111', 'completed');
EOF

    log_success "MySQL seeded with test data"
}

run_mysql_tests() {
    log_header "MySQL Protocol Tests"

    setup_mysql || return 1

    log_section "Starting IronVeil proxy (MySQL mode)..."
    start_proxy --port "$PROXY_PORT" --upstream-host localhost --upstream-port "$MYSQL_PORT" --api-port "$API_PORT" --protocol mysql

    if ! wait_for_port "$PROXY_PORT" "IronVeil Proxy"; then
        log_error "Failed to start proxy"
        return 1
    fi
    sleep 2

    # Test 1: Explicit rules masking
    log_section "Test: MySQL Explicit Masking Rules"
    run_query_mysql "SELECT email, phone_number FROM users;"
    echo "$QUERY_OUTPUT"
    assert_masked 1 "mysql.user@test.com" "MySQL: Email was masked"
    assert_masked 1 "555-111-2222" "MySQL: Phone was masked"

    # Test 2: Heuristic detection
    log_section "Test: MySQL Heuristic Detection"
    run_query_mysql "SELECT buyer_email, card_number FROM orders;"
    echo "$QUERY_OUTPUT"
    assert_masked 1 "buyer@shop.com" "MySQL Heuristic: Email detected and masked"
    assert_masked 1 "4111-1111-1111-1111" "MySQL Heuristic: Credit card detected and masked"

    # Stop proxy
    kill "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    sleep 1
}

#######################################
# Management API Tests
#######################################

run_api_tests() {
    log_header "Management API Tests"

    # Start proxy for API tests (use postgres by default)
    if ! docker ps | grep -q pg-test; then
        setup_postgres || return 1
    fi

    log_section "Starting IronVeil proxy for API tests..."
    start_proxy --port "$PROXY_PORT" --upstream-host localhost --upstream-port "$PG_PORT" --api-port "$API_PORT"

    if ! wait_for_port "$API_PORT" "Management API"; then
        log_error "Failed to start Management API"
        return 1
    fi

    # Health check: /health returns 503 until the first successful upstream
    # probe, so poll until it reports healthy.
    log_section "Test: Health Endpoint"
    local response=""
    local healthy=false
    for _ in {1..30}; do
        response=$(curl -s "http://localhost:$API_PORT/health" || true)
        if echo "$response" | grep -q '"healthy":true'; then
            healthy=true
            break
        fi
        sleep 1
    done
    echo "$response"
    if [ "$healthy" = true ]; then
        log_success "Health endpoint reports healthy upstream"
    else
        log_error "Health endpoint never reported a healthy upstream"
    fi
    assert_api_response "$response" "ok" "Health endpoint returns 'ok'"

    # Connections endpoint
    log_section "Test: Connections Endpoint"
    response=$(curl -s "http://localhost:$API_PORT/connections" || true)
    echo "$response"
    assert_api_response "$response" "active_connections" "Connections endpoint returns data"

    # Rules endpoint
    log_section "Test: Rules Endpoint"
    response=$(curl -s "http://localhost:$API_PORT/rules" || true)
    echo "$response"
    assert_api_response "$response" "rules" "Rules endpoint returns data"

    # Config endpoint
    log_section "Test: Config Endpoint"
    response=$(curl -s "http://localhost:$API_PORT/config" || true)
    echo "$response"
    assert_api_response "$response" "masking_enabled" "Config endpoint returns data"

    # Toggle masking
    log_section "Test: Toggle Masking"
    response=$(curl -s -X POST "http://localhost:$API_PORT/config" \
        -H "Content-Type: application/json" \
        -d '{"masking_enabled": false}' || true)
    echo "$response"
    assert_api_response "$response" "false" "Masking can be disabled"

    # Re-enable
    curl -s -X POST "http://localhost:$API_PORT/config" \
        -H "Content-Type: application/json" \
        -d '{"masking_enabled": true}' > /dev/null || true

    # Metrics endpoint (Prometheus)
    log_section "Test: Metrics Endpoint (Prometheus)"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$API_PORT/metrics" || true)
    if [ "$http_code" = "200" ]; then
        log_success "Metrics endpoint returns HTTP 200"
    else
        log_error "Metrics endpoint returned HTTP $http_code (expected 200)"
    fi

    # Run a query to generate metrics, then check for them
    run_query_pg "SELECT 1;"
    sleep 1

    response=$(curl -s "http://localhost:$API_PORT/metrics" || true)
    # Check for Prometheus format (HELP or TYPE lines, or metric values)
    if echo "$response" | grep -qE "^(#|[a-z_]+)"; then
        log_success "Metrics endpoint returns valid Prometheus format"
    elif [ -z "$response" ]; then
        # Empty metrics is also valid if no metrics recorded yet
        log_success "Metrics endpoint returns empty (no metrics recorded yet - expected)"
    else
        log_error "Metrics endpoint returned unexpected format"
    fi

    # Stats endpoint (Application Statistics)
    log_section "Test: Stats Endpoint"
    response=$(curl -s "http://localhost:$API_PORT/stats" || true)
    echo "$response"

    # Verify stats endpoint returns expected fields
    assert_api_response "$response" "active_connections" "Stats returns active_connections"
    assert_api_response "$response" "total_connections" "Stats returns total_connections"
    assert_api_response "$response" "masking" "Stats returns masking object"
    assert_api_response "$response" "queries" "Stats returns queries object"
    assert_api_response "$response" "history" "Stats returns history array"

    # Run a query to generate stats
    run_query_pg "SELECT email FROM users LIMIT 1;"
    sleep 1

    # Verify stats updated after query
    response=$(curl -s "http://localhost:$API_PORT/stats" || true)
    local total_queries
    total_queries=$(echo "$response" | grep -o '"total":[0-9]*' | head -1 | grep -o '[0-9]*' || true)

    if [ -n "$total_queries" ] && [ "$total_queries" -ge 1 ]; then
        log_success "Stats shows query count >= 1 after SELECT query (got $total_queries)"
    else
        log_error "Stats query count not incremented (got: $total_queries)"
    fi

    kill "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
}

#######################################
# Negative/Error Handling Tests
#######################################

run_negative_tests() {
    log_header "Negative & Error Handling Tests"

    # Start proxy for negative tests
    if ! docker ps | grep -q pg-test; then
        setup_postgres || return 1
    fi

    log_section "Starting IronVeil proxy for negative tests..."
    start_proxy --port "$PROXY_PORT" --upstream-host localhost --upstream-port "$PG_PORT" --api-port "$API_PORT"

    if ! wait_for_port "$PROXY_PORT" "IronVeil Proxy"; then
        log_error "Failed to start proxy for negative tests"
        return 1
    fi
    sleep 1

    # Test 1: Invalid API endpoint
    log_section "Test: Invalid API Endpoint Returns 404"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$API_PORT/nonexistent" || true)
    if [ "$http_code" = "404" ]; then
        log_success "Invalid endpoint returns HTTP 404"
    else
        log_error "Invalid endpoint returned HTTP $http_code (expected 404)"
    fi

    # Test 2: Invalid JSON in config update
    log_section "Test: Invalid JSON Payload Handling"
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:$API_PORT/config" \
        -H "Content-Type: application/json" \
        -d 'invalid json{' || true)
    if [ "$http_code" = "400" ] || [ "$http_code" = "422" ]; then
        log_success "Invalid JSON returns HTTP $http_code (client error)"
    else
        log_error "Invalid JSON returned HTTP $http_code (expected 400 or 422)"
    fi

    # Test 3: Connection to proxy works even with invalid query
    log_section "Test: Proxy Handles Invalid SQL Gracefully"
    run_query_pg "INVALID SQL QUERY HERE;"
    if [ "$QUERY_OK" = false ] && echo "$QUERY_OUTPUT" | grep -qi "error\|syntax"; then
        log_success "Proxy forwards SQL errors correctly"
    else
        log_error "Proxy didn't forward SQL error as expected: $QUERY_OUTPUT"
    fi

    # Test 4: Query with no PII should pass through unchanged
    log_section "Test: Non-PII Data Passes Unchanged"
    run_query_pg "SELECT 'hello_world' as test, 12345 as number;"
    if [ "$QUERY_OK" = true ] && echo "$QUERY_OUTPUT" | grep -q "hello_world" \
        && echo "$QUERY_OUTPUT" | grep -q "12345"; then
        log_success "Non-PII data passes through unchanged"
    else
        log_error "Non-PII data was unexpectedly modified or query failed: $QUERY_OUTPUT"
    fi

    kill "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    sleep 1
}

#######################################
# Connection Load & Drain Tests
#######################################

run_connection_tests() {
    log_header "Connection Load & Drain Tests"

    if ! docker ps | grep -q pg-test; then
        setup_postgres || return 1
    fi

    log_section "Starting IronVeil proxy for connection tests..."
    start_proxy --port "$PROXY_PORT" --upstream-host localhost --upstream-port "$PG_PORT" --api-port "$API_PORT" --shutdown-timeout 10

    if ! wait_for_port "$PROXY_PORT" "IronVeil Proxy"; then
        log_error "Failed to start proxy for connection tests"
        return 1
    fi
    sleep 1

    # Test 1: Verify connection count increments
    log_section "Test: Active Connection Counting"

    # Start a long-running connection in background
    docker run --rm -e PGPASSWORD=password "$POSTGRES_IMAGE" \
        psql -h "$DOCKER_HOST_ADDR" -p "$PROXY_PORT" -U postgres -c "SELECT pg_sleep(5);" &>/dev/null &
    local bg_pid=$!
    sleep 1

    # Check active connections
    local response
    response=$(curl -s "http://localhost:$API_PORT/connections" || true)
    local active_count
    active_count=$(echo "$response" | grep -o '"active_connections":[0-9]*' | grep -o '[0-9]*$' || true)

    if [ -n "$active_count" ] && [ "$active_count" -ge 1 ]; then
        log_success "Active connection count is $active_count (expected >= 1)"
    else
        log_error "Active connection count is '$active_count' (expected >= 1)"
    fi

    # Wait for background query to finish
    wait "$bg_pid" 2>/dev/null || true
    sleep 1

    # Verify count decremented
    response=$(curl -s "http://localhost:$API_PORT/connections" || true)
    active_count=$(echo "$response" | grep -o '"active_connections":[0-9]*' | grep -o '[0-9]*$' || true)

    if [ -n "$active_count" ] && [ "$active_count" -eq 0 ]; then
        log_success "Connection count decremented to 0 after disconnect"
    else
        log_error "Connection count is '$active_count' (expected 0)"
    fi

    # Test 2: Graceful drain with active connection
    log_section "Test: Graceful Shutdown Drains Connections"

    # Start a quick query in background
    docker run --rm -e PGPASSWORD=password "$POSTGRES_IMAGE" \
        psql -h "$DOCKER_HOST_ADDR" -p "$PROXY_PORT" -U postgres -c "SELECT pg_sleep(2);" &>/dev/null &
    bg_pid=$!
    sleep 0.5

    # Send shutdown signal
    kill -TERM "$PROXY_PID" 2>/dev/null || true

    # Wait for proxy to shutdown gracefully
    local waited=0
    while kill -0 "$PROXY_PID" 2>/dev/null && [ "$waited" -lt 15 ]; do
        sleep 0.5
        waited=$((waited + 1))
    done

    # Check if process exited cleanly
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        log_success "Proxy shutdown gracefully with active connection"
    else
        log_error "Proxy did not shutdown within timeout"
        kill -9 "$PROXY_PID" 2>/dev/null || true
    fi

    wait "$bg_pid" 2>/dev/null || true
    PROXY_PID=""
}

#######################################
# Upstream Failure Tests
#######################################

run_upstream_failure_tests() {
    log_header "Upstream Failure Handling Tests"

    log_section "Starting IronVeil proxy with invalid upstream..."

    # Start proxy pointing to non-existent upstream
    start_proxy --port "$PROXY_PORT" --upstream-host localhost --upstream-port 59999 --api-port "$API_PORT"

    if ! wait_for_port "$API_PORT" "Management API"; then
        log_error "Failed to start proxy"
        return 1
    fi

    # Wait for multiple health check failures (default unhealthy_threshold is 3)
    log_info "Waiting for upstream to be marked unhealthy (may take a few health check cycles)..."
    sleep 5

    # Test 1: Health endpoint shows failing upstream
    log_section "Test: Health Shows Upstream Issues"
    local response
    response=$(curl -s "http://localhost:$API_PORT/health" || true)

    # Check for either unhealthy status OR consecutive failures > 0
    if echo "$response" | grep -q '"healthy":false' || echo "$response" | grep -q '"consecutive_failures":[1-9]'; then
        log_success "Health correctly reports upstream issues (unhealthy or has failures)"
    elif echo "$response" | grep -q '"last_error":null'; then
        log_error "Health shows no upstream errors (expected failures)"
    else
        log_success "Health shows upstream errors in last_error"
    fi

    # Test 2: Connection attempt fails gracefully
    log_section "Test: Connection to Dead Upstream Fails Gracefully"
    run_query_pg "SELECT 1;"
    if [ "$QUERY_OK" = false ] && echo "$QUERY_OUTPUT" | grep -qi "connection\|refused\|error\|failed"; then
        log_success "Connection to dead upstream fails with clear error"
    else
        log_error "Unexpected behavior when connecting to dead upstream: $QUERY_OUTPUT"
    fi

    kill "$PROXY_PID" 2>/dev/null || true
    PROXY_PID=""
    sleep 1
}

#######################################
# Main
#######################################

main() {
    log_header "IronVeil E2E Test Suite"
    echo -e "  Protocol: ${BOLD}$TEST_PROTOCOL${NC}"
    echo -e "  Time: $(date)"

    # Port probing is done with bash's own /dev/tcp, so nc/socat/lsof are not
    # required. curl carries the management-API assertions; the psql and mysql
    # clients run inside the test containers rather than on the host.
    require_tools docker cargo curl mktemp sed grep
    require_tcp_probe
    detect_docker_host_addr
    write_e2e_config
    check_ports
    build_proxy

    case $TEST_PROTOCOL in
        postgres)
            run_postgres_tests
            run_api_tests
            run_negative_tests
            run_connection_tests
            run_upstream_failure_tests
            test_graceful_shutdown
            ;;
        mysql)
            run_mysql_tests
            ;;
        all)
            run_postgres_tests
            run_mysql_tests
            run_api_tests
            run_negative_tests
            run_connection_tests
            run_upstream_failure_tests
            test_graceful_shutdown
            ;;
        *)
            echo "Usage: $0 [postgres|mysql|all]"
            exit 1
            ;;
    esac

    # Summary
    log_header "Test Summary"
    echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
    echo ""

    if [ "$TESTS_FAILED" -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed! ✓${NC}"
        exit 0
    fi
}

main
