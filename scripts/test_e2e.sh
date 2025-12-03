#!/bin/bash

#######################################
# IronVeil E2E Test Suite
# Tests both PostgreSQL and MySQL protocols
#######################################

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
PROXY_PID=""
TEST_PROTOCOL="${1:-postgres}"  # Default to postgres, can pass 'mysql' or 'all'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

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

# Assert that output does NOT contain original PII
assert_not_contains() {
    local output="$1"
    local pattern="$2"
    local description="$3"
    
    if echo "$output" | grep -q "$pattern"; then
        log_error "$description"
        return 0  # Don't fail the script
    else
        log_success "$description"
        return 0
    fi
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

# Wait for a service to be ready
wait_for_port() {
    local port=$1
    local name=$2
    local max_attempts=30
    local attempt=0
    
    while ! nc -z localhost $port 2>/dev/null; do
        attempt=$((attempt + 1))
        if [ $attempt -ge $max_attempts ]; then
            log_error "Timeout waiting for $name on port $port"
            return 1
        fi
        sleep 1
    done
    log_success "$name is ready on port $port"
    return 0
}

#######################################
# Cleanup
#######################################

cleanup() {
    log_section "Cleaning up..."
    
    # Stop proxy
    if [ -n "$PROXY_PID" ]; then
        kill $PROXY_PID 2>/dev/null || true
        log_info "Stopped proxy (PID: $PROXY_PID)"
    fi
    
    # Stop containers
    docker rm -f pg-test mysql-test 2>/dev/null || true
    log_info "Removed test containers"
}
trap cleanup EXIT

#######################################
# Port Conflict Check
#######################################

check_ports() {
    log_section "Checking for port conflicts..."
    
    local ports=("$PROXY_PORT" "$API_PORT")
    
    if [ "$TEST_PROTOCOL" = "postgres" ] || [ "$TEST_PROTOCOL" = "all" ]; then
        ports+=("$PG_PORT")
    fi
    
    if [ "$TEST_PROTOCOL" = "mysql" ] || [ "$TEST_PROTOCOL" = "all" ]; then
        ports+=("$MYSQL_PORT")
    fi
    
    for port in "${ports[@]}"; do
        if lsof -i ":$port" > /dev/null 2>&1; then
            log_error "Port $port is in use"
            echo "  Run: docker compose down && lsof -ti :$port | xargs kill -9"
            exit 1
        fi
    done
    
    log_info "All required ports are available"
}

#######################################
# PostgreSQL Tests
#######################################

setup_postgres() {
    log_section "Starting PostgreSQL container..."
    
    docker rm -f pg-test 2>/dev/null || true
    docker run --name pg-test \
        -e POSTGRES_PASSWORD=password \
        -p $PG_PORT:5432 \
        -d postgres:16 > /dev/null
    
    if ! wait_for_port $PG_PORT "PostgreSQL"; then
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
INSERT INTO customers (customer_email, credit_card, notes) VALUES 
    ('secret@hidden.org', '4532-1234-5678-9012', 'Regular customer'),
    ('private@email.net', '5425-9876-5432-1098', 'VIP member');

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
    (ARRAY['normal_tag', 'array@email.com', '9999-8888-7777-6666']);
EOF
    
    log_success "PostgreSQL seeded with test data"
}

run_postgres_tests() {
    log_header "PostgreSQL Protocol Tests"
    
    setup_postgres || return 1
    
    log_section "Starting IronVeil proxy (PostgreSQL mode)..."
    cargo build --release --quiet 2>/dev/null || cargo build --quiet
    ./target/release/iron-veil --port $PROXY_PORT --upstream-port $PG_PORT --api-port $API_PORT --protocol postgres &
    PROXY_PID=$!
    
    if ! wait_for_port $PROXY_PORT "IronVeil Proxy"; then
        log_error "Failed to start proxy"
        return 1
    fi
    sleep 2
    
    # Test 1: Explicit rules masking
    log_section "Test: Explicit Masking Rules"
    local result
    result=$(docker run --rm -e PGPASSWORD=password postgres:16 \
        psql -h host.docker.internal -p $PROXY_PORT -U postgres -t -c "SELECT email, phone_number FROM users;" 2>/dev/null)
    
    echo "$result"
    assert_not_contains "$result" "john.doe@company.com" "Email 'john.doe@company.com' was masked"
    assert_not_contains "$result" "555-123-4567" "Phone '555-123-4567' was masked"
    
    # Test 2: Heuristic detection
    log_section "Test: Heuristic PII Detection"
    result=$(docker run --rm -e PGPASSWORD=password postgres:16 \
        psql -h host.docker.internal -p $PROXY_PORT -U postgres -t -c "SELECT customer_email, credit_card, notes FROM customers;" 2>/dev/null)
    
    echo "$result"
    assert_not_contains "$result" "secret@hidden.org" "Heuristic: Email detected and masked"
    assert_not_contains "$result" "4532-1234-5678-9012" "Heuristic: Credit card detected and masked"
    
    # Test 3: JSON masking
    log_section "Test: JSON Recursive Masking"
    result=$(docker run --rm -e PGPASSWORD=password postgres:16 \
        psql -h host.docker.internal -p $PROXY_PORT -U postgres -t -c "SELECT data FROM profiles;" 2>/dev/null)
    
    echo "$result"
    assert_not_contains "$result" "nested@json.com" "JSON: Nested email was masked"
    assert_not_contains "$result" "1111-2222-3333-4444" "JSON: Nested credit card was masked"
    
    # Test 4: Array masking
    log_section "Test: Array Element Masking"
    result=$(docker run --rm -e PGPASSWORD=password postgres:16 \
        psql -h host.docker.internal -p $PROXY_PORT -U postgres -t -c "SELECT values FROM tags;" 2>/dev/null)
    
    echo "$result"
    assert_not_contains "$result" "array@email.com" "Array: Email element was masked"
    assert_not_contains "$result" "9999-8888-7777-6666" "Array: Credit card element was masked"
    
    # Stop proxy for next test suite
    kill $PROXY_PID 2>/dev/null || true
    PROXY_PID=""
    sleep 1
}

#######################################
# MySQL Tests
#######################################

setup_mysql() {
    log_section "Starting MySQL container..."
    
    docker rm -f mysql-test 2>/dev/null || true
    docker run --name mysql-test \
        -e MYSQL_ROOT_PASSWORD=password \
        -e MYSQL_DATABASE=testdb \
        -p $MYSQL_PORT:3306 \
        -d mysql:8 > /dev/null
    
    log_info "Waiting for MySQL to initialize (this takes ~30s)..."
    sleep 30
    
    if ! wait_for_port $MYSQL_PORT "MySQL"; then
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
    cargo build --release --quiet 2>/dev/null || cargo build --quiet
    ./target/release/iron-veil --port $PROXY_PORT --upstream-port $MYSQL_PORT --api-port $API_PORT --protocol mysql &
    PROXY_PID=$!
    
    if ! wait_for_port $PROXY_PORT "IronVeil Proxy"; then
        log_error "Failed to start proxy"
        return 1
    fi
    sleep 2
    
    # Test 1: Explicit rules masking
    log_section "Test: MySQL Explicit Masking Rules"
    local result
    result=$(docker run --rm mysql:8 \
        mysql -h host.docker.internal -P $PROXY_PORT -uroot -ppassword testdb \
        -e "SELECT email, phone_number FROM users;" 2>/dev/null)
    
    echo "$result"
    assert_not_contains "$result" "mysql.user@test.com" "MySQL: Email was masked"
    assert_not_contains "$result" "555-111-2222" "MySQL: Phone was masked"
    
    # Test 2: Heuristic detection
    log_section "Test: MySQL Heuristic Detection"
    result=$(docker run --rm mysql:8 \
        mysql -h host.docker.internal -P $PROXY_PORT -uroot -ppassword testdb \
        -e "SELECT buyer_email, card_number FROM orders;" 2>/dev/null)
    
    echo "$result"
    assert_not_contains "$result" "buyer@shop.com" "MySQL Heuristic: Email detected and masked"
    assert_not_contains "$result" "4111-1111-1111-1111" "MySQL Heuristic: Credit card detected and masked"
    
    # Stop proxy
    kill $PROXY_PID 2>/dev/null || true
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
    ./target/release/iron-veil --port $PROXY_PORT --upstream-port $PG_PORT --api-port $API_PORT &
    PROXY_PID=$!
    
    if ! wait_for_port $API_PORT "Management API"; then
        log_error "Failed to start Management API"
        return 1
    fi
    sleep 1
    
    # Health check
    log_section "Test: Health Endpoint"
    local response
    response=$(curl -s http://localhost:$API_PORT/health)
    echo "$response"
    assert_api_response "$response" "ok" "Health endpoint returns 'ok'"
    
    # Connections endpoint
    log_section "Test: Connections Endpoint"
    response=$(curl -s http://localhost:$API_PORT/connections)
    echo "$response"
    assert_api_response "$response" "active_connections" "Connections endpoint returns data"
    
    # Rules endpoint
    log_section "Test: Rules Endpoint"
    response=$(curl -s http://localhost:$API_PORT/rules)
    echo "$response"
    assert_api_response "$response" "rules" "Rules endpoint returns data"
    
    # Config endpoint
    log_section "Test: Config Endpoint"
    response=$(curl -s http://localhost:$API_PORT/config)
    echo "$response"
    assert_api_response "$response" "masking_enabled" "Config endpoint returns data"
    
    # Toggle masking
    log_section "Test: Toggle Masking"
    response=$(curl -s -X POST http://localhost:$API_PORT/config \
        -H "Content-Type: application/json" \
        -d '{"masking_enabled": false}')
    echo "$response"
    assert_api_response "$response" "false" "Masking can be disabled"
    
    # Re-enable
    curl -s -X POST http://localhost:$API_PORT/config \
        -H "Content-Type: application/json" \
        -d '{"masking_enabled": true}' > /dev/null
    
    kill $PROXY_PID 2>/dev/null || true
    PROXY_PID=""
}

#######################################
# Main
#######################################

main() {
    log_header "IronVeil E2E Test Suite"
    echo -e "  Protocol: ${BOLD}$TEST_PROTOCOL${NC}"
    echo -e "  Time: $(date)"
    
    check_ports
    
    case $TEST_PROTOCOL in
        postgres)
            run_postgres_tests
            run_api_tests
            ;;
        mysql)
            run_mysql_tests
            ;;
        all)
            run_postgres_tests
            run_mysql_tests
            run_api_tests
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
    
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed! ✓${NC}"
        exit 0
    fi
}

main
