#!/usr/bin/env bash
#
# Production deployment script for LeWAF
#
# Usage:
#   ./deploy.sh [environment]
#
# Examples:
#   ./deploy.sh production    # Deploy to production
#   ./deploy.sh staging       # Deploy to staging
#   ./deploy.sh development   # Deploy to development

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ENV="${1:-production}"

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Checking requirements..."

    # Check for required commands
    local required_commands=("docker" "docker-compose" "curl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done

    log_info "All requirements satisfied"
}

validate_environment() {
    log_info "Validating environment: $ENV"

    case "$ENV" in
        production|prod)
            ENV="production"
            ;;
        staging|stage)
            ENV="staging"
            ;;
        development|dev)
            ENV="development"
            ;;
        *)
            log_error "Invalid environment: $ENV"
            log_error "Valid environments: production, staging, development"
            exit 1
            ;;
    esac

    log_info "Environment validated: $ENV"
}

build_images() {
    log_info "Building Docker images..."

    cd "$PROJECT_ROOT/examples/production"
    docker-compose build lewaf-app

    log_info "Docker images built successfully"
}

run_tests() {
    log_info "Running tests..."

    cd "$PROJECT_ROOT"

    # Run tests in Docker container to ensure consistency
    docker run --rm \
        -v "$PROJECT_ROOT:/app" \
        -w /app \
        python:3.12-slim \
        /bin/bash -c "pip install -q uv && uv sync --frozen && uv run pytest -q --tb=short"

    if [ $? -ne 0 ]; then
        log_error "Tests failed! Aborting deployment."
        exit 1
    fi

    log_info "All tests passed"
}

verify_rules() {
    log_info "Verifying CRS rules..."

    cd "$PROJECT_ROOT"

    # Check if coraza.conf exists and can be parsed
    if [ ! -f "coraza.conf" ]; then
        log_error "coraza.conf not found"
        exit 1
    fi

    # Verify rules load correctly
    docker run --rm \
        -v "$PROJECT_ROOT:/app" \
        -w /app \
        python:3.12-slim \
        /bin/bash -c "pip install -q uv && uv sync --frozen && uv run python -c \"
from lewaf.parser import parse_config_file
try:
    rules = parse_config_file('coraza.conf')
    print(f'Successfully loaded {len(rules)} rules')
except Exception as e:
    print(f'Failed to load rules: {e}')
    exit(1)
\""

    if [ $? -ne 0 ]; then
        log_error "Rule verification failed! Aborting deployment."
        exit 1
    fi

    log_info "CRS rules verified"
}

deploy() {
    log_info "Deploying LeWAF to $ENV environment..."

    cd "$PROJECT_ROOT/examples/production"

    # Set environment variable
    export ENV="$ENV"

    # Stop existing containers
    log_info "Stopping existing containers..."
    docker-compose down

    # Start new containers
    log_info "Starting containers..."
    docker-compose up -d lewaf-app

    # Wait for health check
    log_info "Waiting for application to be healthy..."
    sleep 5

    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
            log_info "Application is healthy"
            break
        fi

        attempt=$((attempt + 1))
        if [ $attempt -eq $max_attempts ]; then
            log_error "Application failed to become healthy"
            docker-compose logs lewaf-app
            exit 1
        fi

        echo -n "."
        sleep 2
    done
    echo ""

    log_info "Deployment successful!"
}

start_monitoring() {
    log_info "Starting monitoring stack..."

    cd "$PROJECT_ROOT/examples/production"

    if [ "$ENV" = "production" ]; then
        docker-compose up -d prometheus grafana
        log_info "Monitoring stack started"
        log_info "Prometheus: http://localhost:9090"
        log_info "Grafana: http://localhost:3000 (admin/admin)"
    else
        log_warn "Monitoring stack not started (production only)"
    fi
}

show_status() {
    log_info "Deployment Status:"
    echo ""
    echo "Environment: $ENV"
    echo "Application: http://localhost:8000"
    echo "Health Check: http://localhost:8000/health"
    echo "Metrics: http://localhost:8000/metrics"

    if [ "$ENV" = "production" ]; then
        echo "Prometheus: http://localhost:9090"
        echo "Grafana: http://localhost:3000"
    fi

    echo ""
    log_info "Container Status:"
    cd "$PROJECT_ROOT/examples/production"
    docker-compose ps
}

main() {
    log_info "LeWAF Deployment Script"
    log_info "======================="
    echo ""

    check_requirements
    validate_environment

    # Confirm production deployment
    if [ "$ENV" = "production" ]; then
        log_warn "You are about to deploy to PRODUCTION"
        read -p "Continue? (yes/no): " -r
        echo
        if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi

    build_images
    run_tests
    verify_rules
    deploy
    start_monitoring
    show_status

    echo ""
    log_info "Deployment complete! 🚀"
}

# Run main function
main
