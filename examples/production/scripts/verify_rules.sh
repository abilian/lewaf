#!/usr/bin/env bash
#
# Verify CRS rules are loaded correctly
#
# Usage:
#   ./verify_rules.sh [config_file]
#
# Examples:
#   ./verify_rules.sh                    # Use default coraza.conf
#   ./verify_rules.sh /path/to/rules.conf

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIG_FILE="${1:-$PROJECT_ROOT/coraza.conf}"

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

check_config_file() {
    log_info "Checking configuration file..."

    if [ ! -f "$CONFIG_FILE" ]; then
        log_error "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi

    log_info "Configuration file: $CONFIG_FILE"
}

count_include_directives() {
    log_info "Counting Include directives..."

    local count
    count=$(grep -c "^Include" "$CONFIG_FILE" || echo "0")

    log_info "Found $count Include directives"
    echo "$count"
}

verify_included_files() {
    log_info "Verifying included files exist..."

    local missing=0
    local base_dir
    base_dir=$(dirname "$CONFIG_FILE")

    while IFS= read -r line; do
        # Extract path from Include directive
        local path
        path=$(echo "$line" | sed 's/^Include //' | tr -d '\r')

        # Make path absolute if relative
        if [[ ! "$path" =~ ^/ ]]; then
            path="$base_dir/$path"
        fi

        if [ ! -f "$path" ]; then
            log_error "Missing file: $path"
            missing=$((missing + 1))
        fi
    done < <(grep "^Include" "$CONFIG_FILE")

    if [ $missing -eq 0 ]; then
        log_info "✓ All included files exist"
        return 0
    else
        log_error "$missing included files are missing"
        return 1
    fi
}

parse_rules() {
    log_info "Parsing rules with LeWAF..."

    cd "$PROJECT_ROOT"

    # Create a temporary Python script to parse rules
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
import sys
from pathlib import Path

try:
    from lewaf.parser import parse_config_file

    config_file = sys.argv[1]
    rules = parse_config_file(config_file)

    print(f"Successfully loaded {len(rules)} rules")

    # Count by type
    sec_rules = sum(1 for r in rules if r.get('type') == 'SecRule')
    sec_actions = sum(1 for r in rules if r.get('type') == 'SecAction')
    sec_markers = sum(1 for r in rules if r.get('type') == 'SecMarker')

    print(f"  SecRule:   {sec_rules}")
    print(f"  SecAction: {sec_actions}")
    print(f"  SecMarker: {sec_markers}")

    # Count rules by phase
    phases = {}
    for rule in rules:
        if rule.get('type') == 'SecRule':
            actions = rule.get('actions', {})
            phase = actions.get('phase', 'unknown')
            phases[phase] = phases.get(phase, 0) + 1

    if phases:
        print("\nRules by phase:")
        for phase in sorted(phases.keys()):
            print(f"  Phase {phase}: {phases[phase]}")

    sys.exit(0)

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF

    # Run the script
    if command -v uv &> /dev/null; then
        uv run python "$temp_script" "$CONFIG_FILE"
        local exit_code=$?
    else
        python3 "$temp_script" "$CONFIG_FILE"
        local exit_code=$?
    fi

    rm "$temp_script"

    if [ $exit_code -eq 0 ]; then
        log_info "✓ Rules parsed successfully"
        return 0
    else
        log_error "Rule parsing failed"
        return 1
    fi
}

test_rule_matching() {
    log_info "Testing rule matching..."

    cd "$PROJECT_ROOT"

    # Create a temporary Python script to test rule matching
    local temp_script=$(mktemp)
    cat > "$temp_script" << 'EOF'
import sys
from pathlib import Path

try:
    from lewaf.engine import WAF

    config_file = sys.argv[1]

    # Initialize WAF
    waf = WAF(rule_files=[config_file])

    # Test cases
    test_cases = [
        {
            "name": "SQL Injection",
            "request": {
                "uri": "/?id=1' OR '1'='1",
                "method": "GET",
            },
            "should_block": True,
        },
        {
            "name": "XSS Attack",
            "request": {
                "uri": "/?q=<script>alert(1)</script>",
                "method": "GET",
            },
            "should_block": True,
        },
        {
            "name": "Clean Request",
            "request": {
                "uri": "/?id=123",
                "method": "GET",
            },
            "should_block": False,
        },
    ]

    passed = 0
    failed = 0

    for test in test_cases:
        tx = waf.new_transaction()
        tx.process_request_headers(
            method=test["request"]["method"],
            uri=test["request"]["uri"],
            protocol="HTTP/1.1",
            headers={},
        )

        blocked = tx.interruption is not None

        if blocked == test["should_block"]:
            print(f"  ✓ {test['name']}")
            passed += 1
        else:
            print(f"  ✗ {test['name']}")
            print(f"    Expected: {'blocked' if test['should_block'] else 'allowed'}")
            print(f"    Got: {'blocked' if blocked else 'allowed'}")
            failed += 1

    print(f"\nPassed: {passed}/{len(test_cases)}")

    if failed > 0:
        sys.exit(1)

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)
EOF

    # Run the script
    if command -v uv &> /dev/null; then
        uv run python "$temp_script" "$CONFIG_FILE"
        local exit_code=$?
    else
        python3 "$temp_script" "$CONFIG_FILE"
        local exit_code=$?
    fi

    rm "$temp_script"

    if [ $exit_code -eq 0 ]; then
        log_info "✓ Rule matching tests passed"
        return 0
    else
        log_error "Rule matching tests failed"
        return 1
    fi
}

main() {
    log_info "LeWAF Rule Verification"
    log_info "======================="
    echo ""

    check_config_file
    echo ""

    count_include_directives
    echo ""

    verify_included_files || exit 1
    echo ""

    parse_rules || exit 1
    echo ""

    test_rule_matching || exit 1
    echo ""

    log_info "All verifications passed! ✓"
}

# Run main function
main
