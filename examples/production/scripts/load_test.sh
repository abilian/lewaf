#!/usr/bin/env bash
#
# Simple load testing script for LeWAF
#
# Usage:
#   ./load_test.sh [url] [requests] [concurrency]
#
# Examples:
#   ./load_test.sh                                    # Default: localhost:8000, 1000 requests, 10 concurrent
#   ./load_test.sh http://example.com                 # 1000 requests to example.com
#   ./load_test.sh http://example.com 5000 50         # 5000 requests, 50 concurrent

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
URL="${1:-http://localhost:8000}"
TOTAL_REQUESTS="${2:-1000}"
CONCURRENCY="${3:-10}"

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

check_dependencies() {
    log_info "Checking dependencies..."

    if ! command -v ab &> /dev/null; then
        log_error "Apache Bench (ab) not found"
        log_info "Install with: apt-get install apache2-utils (Ubuntu/Debian)"
        log_info "            or: brew install apache2 (macOS)"
        exit 1
    fi

    log_info "Dependencies satisfied"
}

run_load_test() {
    log_info "Running load test..."
    log_info "  URL: $URL"
    log_info "  Total requests: $TOTAL_REQUESTS"
    log_info "  Concurrency: $CONCURRENCY"
    echo ""

    # Run Apache Bench
    ab -n "$TOTAL_REQUESTS" -c "$CONCURRENCY" -g /dev/null "$URL/" | tee /tmp/lewaf_load_test.log

    echo ""
}

run_malicious_load_test() {
    log_info "Running malicious request load test..."
    log_info "  Testing WAF blocking under load"
    echo ""

    # Test SQL injection under load
    log_info "Testing SQL injection detection..."
    ab -n 100 -c 10 -g /dev/null "$URL/?id=1' OR '1'='1" 2>&1 | grep -E "Failed requests|Non-2xx responses"

    echo ""

    # Test XSS under load
    log_info "Testing XSS detection..."
    ab -n 100 -c 10 -g /dev/null "$URL/?q=<script>alert(1)</script>" 2>&1 | grep -E "Failed requests|Non-2xx responses"

    echo ""
}

analyze_results() {
    log_info "Analyzing results..."

    if [ ! -f /tmp/lewaf_load_test.log ]; then
        log_error "Results file not found"
        return 1
    fi

    # Extract key metrics
    local requests_per_sec
    requests_per_sec=$(grep "Requests per second" /tmp/lewaf_load_test.log | awk '{print $4}')

    local time_per_request
    time_per_request=$(grep "Time per request" /tmp/lewaf_load_test.log | head -1 | awk '{print $4}')

    local failed_requests
    failed_requests=$(grep "Failed requests" /tmp/lewaf_load_test.log | awk '{print $3}')

    echo ""
    log_info "Summary:"
    echo "  Requests/sec:    $requests_per_sec"
    echo "  Time/request:    ${time_per_request}ms"
    echo "  Failed requests: $failed_requests"

    # Performance thresholds
    local rps_threshold=100
    local tpr_threshold=100

    if (( $(echo "$requests_per_sec > $rps_threshold" | bc -l) )); then
        log_info "✓ Good throughput (>${rps_threshold} req/s)"
    else
        log_warn "⚠ Low throughput (<${rps_threshold} req/s)"
    fi

    if (( $(echo "$time_per_request < $tpr_threshold" | bc -l) )); then
        log_info "✓ Good response time (<${tpr_threshold}ms)"
    else
        log_warn "⚠ Slow response time (>${tpr_threshold}ms)"
    fi

    if [ "$failed_requests" -eq 0 ]; then
        log_info "✓ No failed requests"
    else
        log_warn "⚠ $failed_requests requests failed"
    fi
}

stress_test() {
    log_info "Running stress test..."
    log_info "  Gradually increasing load to find limits"
    echo ""

    for concurrency in 10 25 50 100; do
        log_info "Testing with $concurrency concurrent connections..."

        local result
        result=$(ab -n 1000 -c "$concurrency" -q "$URL/" 2>&1)

        local requests_per_sec
        requests_per_sec=$(echo "$result" | grep "Requests per second" | awk '{print $4}')

        local failed
        failed=$(echo "$result" | grep "Failed requests" | awk '{print $3}')

        echo "  Concurrency $concurrency: $requests_per_sec req/s, $failed failures"

        # Stop if we see failures
        if [ "$failed" -gt 0 ]; then
            log_warn "Failures detected at concurrency level $concurrency"
            break
        fi
    done

    echo ""
}

main() {
    log_info "LeWAF Load Test"
    log_info "==============="
    echo ""

    check_dependencies
    echo ""

    # Verify endpoint is accessible
    if ! curl -sf "$URL/health" > /dev/null 2>&1; then
        log_error "Endpoint not accessible: $URL"
        log_error "Is the application running?"
        exit 1
    fi

    # Run tests
    run_load_test
    analyze_results
    echo ""

    run_malicious_load_test
    echo ""

    stress_test

    log_info "Load testing complete! ✓"
}

# Run main function
main
