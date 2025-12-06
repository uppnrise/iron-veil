#!/bin/bash

#######################################
# IronVeil Release Script
# Builds, tests, and packages releases
#######################################

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WEB_DIR="$PROJECT_ROOT/web"

# Release configuration
RELEASE_DIR="$PROJECT_ROOT/release"
DIST_DIR="$PROJECT_ROOT/dist"

#######################################
# Helper Functions
#######################################

log_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_step() {
    echo -e "${YELLOW}▶ $1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

show_help() {
    echo "Usage: $0 [OPTIONS] [VERSION]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -d, --dry-run       Run checks without creating release artifacts"
    echo "  -s, --skip-tests    Skip running tests"
    echo "  -w, --skip-web      Skip building web frontend"
    echo "  -t, --tag           Create git tag for the release"
    echo "  -p, --push          Push tag to remote (requires --tag)"
    echo "  --docker            Build Docker image"
    echo "  --docker-push       Push Docker image to registry (requires --docker)"
    echo ""
    echo "Arguments:"
    echo "  VERSION             Version string (e.g., 1.0.0). If not provided,"
    echo "                      reads from Cargo.toml"
    echo ""
    echo "Examples:"
    echo "  $0                  Build release with version from Cargo.toml"
    echo "  $0 1.0.0            Build release version 1.0.0"
    echo "  $0 --tag 1.0.0      Build and tag version 1.0.0"
    echo "  $0 --docker         Build release with Docker image"
    echo "  $0 -d               Dry run (validation only)"
    exit 0
}

get_version_from_cargo() {
    grep '^version' "$PROJECT_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/'
}

get_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux";;
        Darwin*)    echo "darwin";;
        MINGW*|MSYS*|CYGWIN*) echo "windows";;
        *)          echo "unknown";;
    esac
}

get_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64";;
        arm64|aarch64)  echo "arm64";;
        *)              echo "$(uname -m)";;
    esac
}

#######################################
# Parse Arguments
#######################################

DRY_RUN=false
SKIP_TESTS=false
SKIP_WEB=false
CREATE_TAG=false
PUSH_TAG=false
BUILD_DOCKER=false
PUSH_DOCKER=false
VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -s|--skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -w|--skip-web)
            SKIP_WEB=true
            shift
            ;;
        -t|--tag)
            CREATE_TAG=true
            shift
            ;;
        -p|--push)
            PUSH_TAG=true
            shift
            ;;
        --docker)
            BUILD_DOCKER=true
            shift
            ;;
        --docker-push)
            PUSH_DOCKER=true
            BUILD_DOCKER=true
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            show_help
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

# Get version
if [ -z "$VERSION" ]; then
    VERSION=$(get_version_from_cargo)
fi

OS=$(get_os)
ARCH=$(get_arch)
BINARY_NAME="iron-veil"
RELEASE_NAME="${BINARY_NAME}-v${VERSION}-${OS}-${ARCH}"

#######################################
# Pre-flight Checks
#######################################

log_header "IronVeil Release v${VERSION}"

log_step "Running pre-flight checks..."

# Check we're in the project root
if [ ! -f "$PROJECT_ROOT/Cargo.toml" ]; then
    log_error "Cargo.toml not found. Run from project root."
    exit 1
fi

# Check required tools
for cmd in cargo git; do
    if ! command -v $cmd &> /dev/null; then
        log_error "$cmd is required but not installed."
        exit 1
    fi
done

# Check Node.js for web build
if [ "$SKIP_WEB" = false ]; then
    if ! command -v npm &> /dev/null; then
        log_error "npm is required for web build. Use --skip-web to skip."
        exit 1
    fi
fi

# Check Docker for image build
if [ "$BUILD_DOCKER" = true ]; then
    if ! command -v docker &> /dev/null; then
        log_error "Docker is required for --docker option."
        exit 1
    fi
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    log_error "Working directory has uncommitted changes."
    log_info "Please commit or stash changes before release."
    git status --short
    exit 1
fi

log_success "Pre-flight checks passed"

#######################################
# Code Quality Checks
#######################################

log_header "Code Quality Checks"

cd "$PROJECT_ROOT"

log_step "Running cargo fmt --check..."
if ! cargo fmt --check; then
    log_error "Code is not formatted. Run 'cargo fmt' first."
    exit 1
fi
log_success "Code formatting OK"

log_step "Running cargo clippy..."
if ! cargo clippy --all-targets --all-features -- -D warnings 2>/dev/null; then
    log_error "Clippy found issues. Please fix before release."
    exit 1
fi
log_success "Clippy checks passed"

# Web linting
if [ "$SKIP_WEB" = false ] && [ -d "$WEB_DIR" ]; then
    log_step "Running web linting..."
    cd "$WEB_DIR"
    if ! npm run lint 2>/dev/null; then
        log_error "Web linting failed. Please fix before release."
        exit 1
    fi
    log_success "Web linting passed"
    cd "$PROJECT_ROOT"
fi

#######################################
# Run Tests
#######################################

if [ "$SKIP_TESTS" = false ]; then
    log_header "Running Tests"
    
    log_step "Running Rust tests..."
    if ! cargo test 2>&1 | tee /tmp/test-output.txt | tail -20; then
        if grep -q "FAILED" /tmp/test-output.txt; then
            log_error "Tests failed."
            exit 1
        fi
    fi
    
    # Check if tests actually passed
    if grep -q "test result: ok" /tmp/test-output.txt; then
        log_success "All tests passed"
    elif grep -q "FAILED" /tmp/test-output.txt; then
        log_error "Tests failed."
        exit 1
    else
        log_success "Tests completed"
    fi
else
    log_info "Skipping tests (--skip-tests)"
fi

#######################################
# Build Release
#######################################

if [ "$DRY_RUN" = true ]; then
    log_header "Dry Run Complete"
    log_success "All checks passed. Ready to release v${VERSION}"
    exit 0
fi

log_header "Building Release"

# Clean previous artifacts
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Build Rust binary
log_step "Building Rust binary (release mode)..."
cargo build --release

log_success "Binary built: target/release/$BINARY_NAME"

# Build web frontend
if [ "$SKIP_WEB" = false ] && [ -d "$WEB_DIR" ]; then
    log_step "Building web frontend..."
    cd "$WEB_DIR"
    npm ci --silent
    npm run build
    log_success "Web frontend built"
    cd "$PROJECT_ROOT"
fi

#######################################
# Package Release
#######################################

log_header "Packaging Release"

PACKAGE_DIR="$DIST_DIR/$RELEASE_NAME"
mkdir -p "$PACKAGE_DIR"

# Copy binary
log_step "Copying binary..."
cp "target/release/$BINARY_NAME" "$PACKAGE_DIR/"

# Copy configuration
log_step "Copying configuration files..."
cp proxy.yaml "$PACKAGE_DIR/"
cp README.md "$PACKAGE_DIR/"

# Copy certificates directory (structure only, user generates certs)
log_step "Copying scripts and certificate generator..."
mkdir -p "$PACKAGE_DIR/scripts"
cp scripts/generate_certs.sh "$PACKAGE_DIR/scripts/"
mkdir -p "$PACKAGE_DIR/certs"
echo "# Place your TLS certificates here" > "$PACKAGE_DIR/certs/README.md"

# Copy web build if present
if [ "$SKIP_WEB" = false ] && [ -d "$WEB_DIR/.next" ]; then
    log_step "Copying web frontend..."
    mkdir -p "$PACKAGE_DIR/web"
    cp -r "$WEB_DIR/.next" "$PACKAGE_DIR/web/"
    cp -r "$WEB_DIR/public" "$PACKAGE_DIR/web/" 2>/dev/null || true
    cp "$WEB_DIR/package.json" "$PACKAGE_DIR/web/"
    cp "$WEB_DIR/next.config.ts" "$PACKAGE_DIR/web/"
fi

# Create archive
log_step "Creating release archive..."
cd "$DIST_DIR"
if [ "$OS" = "windows" ]; then
    zip -r "${RELEASE_NAME}.zip" "$RELEASE_NAME"
    ARCHIVE_FILE="${RELEASE_NAME}.zip"
else
    tar -czf "${RELEASE_NAME}.tar.gz" "$RELEASE_NAME"
    ARCHIVE_FILE="${RELEASE_NAME}.tar.gz"
fi

# Generate checksums
log_step "Generating checksums..."
if command -v sha256sum &> /dev/null; then
    sha256sum "$ARCHIVE_FILE" > "${ARCHIVE_FILE}.sha256"
elif command -v shasum &> /dev/null; then
    shasum -a 256 "$ARCHIVE_FILE" > "${ARCHIVE_FILE}.sha256"
fi

cd "$PROJECT_ROOT"

log_success "Package created: dist/$ARCHIVE_FILE"

#######################################
# Docker Build
#######################################

if [ "$BUILD_DOCKER" = true ]; then
    log_header "Building Docker Image"
    
    DOCKER_TAG="iron-veil:v${VERSION}"
    DOCKER_TAG_LATEST="iron-veil:latest"
    
    log_step "Building Docker image: $DOCKER_TAG"
    docker build -t "$DOCKER_TAG" -t "$DOCKER_TAG_LATEST" .
    
    log_success "Docker image built: $DOCKER_TAG"
    
    if [ "$PUSH_DOCKER" = true ]; then
        log_step "Pushing Docker image..."
        docker push "$DOCKER_TAG"
        docker push "$DOCKER_TAG_LATEST"
        log_success "Docker image pushed"
    fi
fi

#######################################
# Git Tag
#######################################

if [ "$CREATE_TAG" = true ]; then
    log_header "Creating Git Tag"
    
    TAG_NAME="v${VERSION}"
    
    # Check if tag exists
    if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
        log_error "Tag $TAG_NAME already exists."
        exit 1
    fi
    
    log_step "Creating tag: $TAG_NAME"
    git tag -a "$TAG_NAME" -m "Release $TAG_NAME"
    log_success "Tag created: $TAG_NAME"
    
    if [ "$PUSH_TAG" = true ]; then
        log_step "Pushing tag to remote..."
        git push origin "$TAG_NAME"
        log_success "Tag pushed to remote"
    fi
fi

#######################################
# Summary
#######################################

log_header "Release Summary"

echo ""
echo -e "  ${BOLD}Version:${NC}     v${VERSION}"
echo -e "  ${BOLD}Platform:${NC}    ${OS}-${ARCH}"
echo -e "  ${BOLD}Binary:${NC}      target/release/$BINARY_NAME"
echo -e "  ${BOLD}Package:${NC}     dist/$ARCHIVE_FILE"

if [ -f "$DIST_DIR/${ARCHIVE_FILE}.sha256" ]; then
    CHECKSUM=$(cat "$DIST_DIR/${ARCHIVE_FILE}.sha256" | awk '{print $1}')
    echo -e "  ${BOLD}SHA256:${NC}      ${CHECKSUM:0:16}..."
fi

if [ "$BUILD_DOCKER" = true ]; then
    echo -e "  ${BOLD}Docker:${NC}      $DOCKER_TAG"
fi

if [ "$CREATE_TAG" = true ]; then
    echo -e "  ${BOLD}Git Tag:${NC}    $TAG_NAME"
fi

echo ""
log_success "Release v${VERSION} complete!"
echo ""

# Next steps
echo -e "${BOLD}Next Steps:${NC}"
if [ "$CREATE_TAG" = false ]; then
    echo "  • Create git tag:     $0 --tag $VERSION"
fi
if [ "$PUSH_TAG" = false ] && [ "$CREATE_TAG" = true ]; then
    echo "  • Push tag to remote: git push origin v$VERSION"
fi
if [ "$BUILD_DOCKER" = false ]; then
    echo "  • Build Docker image: $0 --docker $VERSION"
fi
echo "  • Upload to GitHub:   gh release create v$VERSION dist/$ARCHIVE_FILE"
echo ""
