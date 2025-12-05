#!/usr/bin/env bash
#
# Health check script for LeWAF deployment
#
# Usage:
#   ./health_check.sh [url]
#
# Examples:
#   ./health_check.sh                          # Check localhost:8000
#   ./health_check.sh http://example.com       # Check remote deployment

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BASE_URL="${1:-http://localhost:8000}"
TIMEOUT=5

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

check_health() {
    log_info "Checking health endpoint..."

    local response
    response=$(curl -sf -w "\n%{http_code}" --max-time "$TIMEOUT" "$BASE_URL/health" 2>&1)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        log_error "Health check failed: Connection error"
        return 1
    fi

    local body=$(echo "$response" | head -n -1)
    local status_code=$(echo "$response" | tail -n 1)

    if [ "$status_code" -ne 200 ]; then
        log_error "Health check failed: HTTP $status_code"
        return 1
    fi

    # Parse JSON response
    local status=$(echo "$body" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    local uptime=$(echo "$body" | grep -o '"uptime_seconds":[0-9.]*' | cut -d':' -f2)

    if [ "$status" = "healthy" ]; then
        log_info "✓ Health check passed"
        log_info "  Status: $status"
        log_info "  Uptime: ${uptime}s"
        return 0
    else
        log_error "Health check failed: Status is $status"
        return 1
    fi
}

check_homepage() {
    log_info "Checking homepage..."

    local status_code
    status_code=$(curl -sf -w "%{http_code}" -o /dev/null --max-time "$TIMEOUT" "$BASE_URL/" 2>&1)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        log_error "Homepage check failed: Connection error"
        return 1
    fi

    if [ "$status_code" -eq 200 ]; then
        log_info "✓ Homepage accessible"
        return 0
    else
        log_error "Homepage check failed: HTTP $status_code"
        return 1
    fi
}

check_waf_blocking() {
    log_info "Checking WAF blocking..."

    # Test with a malicious request (SQL injection attempt)
    local status_code
    status_code=$(curl -sf -w "%{http_code}" -o /dev/null --max-time "$TIMEOUT" \
        "$BASE_URL/?id=1' OR '1'='1" 2>&1 || echo "403")

    # WAF should block this (403) or detect it (200 if DetectionOnly)
    if [ "$status_code" = "403" ]; then
        log_info "✓ WAF is blocking malicious requests (mode: On)"
        return 0
    elif [ "$status_code" = "200" ]; then
        log_warn "⚠ WAF is in detection mode (not blocking)"
        return 0
    else
        log_error "Unexpected response: HTTP $status_code"
        return 1
    fi
}

check_metrics() {
    log_info "Checking metrics endpoint..."

    local status_code
    status_code=$(curl -sf -w "%{http_code}" -o /dev/null --max-time "$TIMEOUT" \
        "$BASE_URL/metrics" 2>&1 || echo "000")

    if [ "$status_code" -eq 200 ]; then
        log_info "✓ Metrics endpoint accessible"
        return 0
    else
        log_warn "⚠ Metrics endpoint returned: HTTP $status_code"
        return 0  # Don't fail on metrics
    fi
}

check_response_time() {
    log_info "Checking response time..."

    local response_time
    response_time=$(curl -sf -w "%{time_total}" -o /dev/null --max-time "$TIMEOUT" "$BASE_URL/" 2>&1)

    if [ $? -ne 0 ]; then
        log_error "Response time check failed"
        return 1
    fi

    # Convert to milliseconds
    response_time_ms=$(echo "$response_time * 1000" | bc)
    response_time_ms=${response_time_ms%.*}  # Remove decimal

    if [ "$response_time_ms" -lt 1000 ]; then
        log_info "✓ Response time: ${response_time_ms}ms"
        return 0
    else
        log_warn "⚠ Slow response time: ${response_time_ms}ms"
        return 0  # Don't fail on slow response
    fi
}

run_all_checks() {
    local failed=0

    check_health || failed=$((failed + 1))
    echo ""

    check_homepage || failed=$((failed + 1))
    echo ""

    check_waf_blocking || failed=$((failed + 1))
    echo ""

    check_metrics || failed=$((failed + 1))
    echo ""

    check_response_time || failed=$((failed + 1))
    echo ""

    return $failed
}

main() {
    log_info "LeWAF Health Check"
    log_info "=================="
    log_info "Target: $BASE_URL"
    echo ""

    if run_all_checks; then
        log_info "All checks passed! ✓"
        exit 0
    else
        log_error "Some checks failed"
        exit 1
    fi
}

# Run main function
main
