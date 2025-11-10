# Admin Path Blocking Test Suite

## Overview

This document describes the comprehensive test suite for validating admin path blocking functionality using the rule:

```
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny,msg:'ADMIN PATH forbidden'"
```

## Test Structure

The test suite is organized into three levels, following the testing pyramid:

### 1. Unit Tests
**Location**: `tests/a_unit/operators/test_admin_path_blocking_unit.py`
**Count**: 7 tests
**Purpose**: Test operator and transformation logic in isolation

**Tests**:
- `test_streq_operator_exact_match` - Verify @streq matches exact strings
- `test_lowercase_transformation` - Verify lowercase transformation normalizes case
- `test_streq_with_lowercase_transformation` - Verify @streq with lowercase transformation
- `test_streq_operator_case_sensitivity_without_transformation` - Verify case sensitivity
- `test_transformation_chain_with_streq` - Verify multiple transformations
- `test_admin_path_blocking_edge_cases` - Verify edge cases (empty string, trailing slash, etc.)
- `test_multiple_blocked_paths` - Verify multiple blocked paths

**Key Validations**:
- ✅ @streq operator matches exact strings only
- ✅ Lowercase transformation converts all case variations to lowercase
- ✅ Transformation returns tuple (transformed_value, changed_flag)
- ✅ Multiple transformations can be chained
- ✅ Edge cases handled correctly (empty string, trailing slash, path traversal)

### 2. Integration Tests
**Location**: `tests/b_integration/test_admin_path_blocking_integration.py`
**Count**: 14 tests
**Purpose**: Test complete WAF flow with transaction processing

**Tests**:
- `test_waf_blocks_lowercase_admin_path` - Block /admin (lowercase)
- `test_waf_blocks_uppercase_admin_path` - Block /ADMIN (uppercase)
- `test_waf_blocks_mixed_case_admin_path` - Block /Admin (mixed case)
- `test_waf_blocks_various_case_combinations` - Block all case variations
- `test_waf_allows_non_admin_paths` - Allow non-admin paths
- `test_waf_blocks_admin_with_query_string` - Query string behavior
- `test_waf_admin_blocking_different_http_methods` - Block all HTTP methods
- `test_transaction_state_after_blocking` - Verify transaction state
- `test_multiple_transactions_independent` - Verify transaction independence
- `test_waf_with_multiple_blocking_rules` - Multiple blocking rules
- `test_rule_parsing_correctness` - Verify rule parsing
- `test_admin_path_with_trailing_slash` - Trailing slash behavior
- `test_phase_1_execution_timing` - Verify phase 1 execution
- `test_integration_with_request_variables` - Verify REQUEST_URI variable

**Key Validations**:
- ✅ WAF blocks /admin in all case variations
- ✅ WAF allows non-admin paths
- ✅ Rule executes in Phase 1 (request headers)
- ✅ Transaction state correctly set after blocking
- ✅ Multiple transactions are independent
- ✅ Rule parsed correctly with all components
- ✅ REQUEST_URI variable correctly populated

### 3. End-to-End (E2E) Tests
**Location**: `tests/c_e2e/test_admin_path_blocking_e2e.py`
**Count**: 18 tests
**Purpose**: Test complete HTTP request/response cycle with server and client

**Tests**:
- `test_e2e_blocks_lowercase_admin` - HTTP 403 for /admin
- `test_e2e_blocks_uppercase_admin` - HTTP 403 for /ADMIN
- `test_e2e_blocks_mixed_case_admin` - HTTP 403 for /Admin
- `test_e2e_blocks_all_case_variations` - HTTP 403 for all case variations
- `test_e2e_allows_homepage` - HTTP 200 for /
- `test_e2e_allows_user_page` - HTTP 200 for /user
- `test_e2e_allows_api_endpoint` - HTTP 200 for /api/users
- `test_e2e_blocks_admin_all_http_methods` - Block GET, POST, PUT, DELETE
- `test_e2e_response_format` - Verify JSON response format
- `test_e2e_multiple_requests_independent` - Multiple independent requests
- `test_e2e_with_request_headers` - Blocking with various headers
- `test_e2e_admin_with_query_string` - Query string handling
- `test_e2e_concurrent_requests_simulation` - Concurrent request handling
- `test_e2e_with_multiple_blocking_rules` - Multiple blocking rules
- `test_e2e_custom_block_status_code` - Custom status code (401)
- `test_e2e_options_method` - OPTIONS method blocking
- `test_e2e_admin_path_performance` - Performance validation (<10ms/request)
- `test_e2e_full_request_lifecycle` - Complete request lifecycle

**Key Validations**:
- ✅ HTTP 403 response for blocked requests
- ✅ JSON response format with error, rule_id, message
- ✅ HTTP 200 for allowed requests
- ✅ All HTTP methods blocked
- ✅ Custom status codes supported
- ✅ Performance acceptable (<10ms per request)
- ✅ Concurrent requests handled correctly

## Test Coverage

### Total Tests: 39
- Unit: 7 tests (18%)
- Integration: 14 tests (36%)
- E2E: 18 tests (46%)

### Test Categories

**Functional Tests** (32 tests):
- Case sensitivity handling
- Path matching accuracy
- HTTP method coverage
- Transaction independence
- Multiple rule handling

**Edge Case Tests** (4 tests):
- Empty strings
- Trailing slashes
- Query strings
- Path traversal attempts

**Performance Tests** (2 tests):
- Request latency
- Concurrent request handling

**Configuration Tests** (1 test):
- Custom block status codes

## Rule Behavior

### Rule Details
```
SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny,msg:'ADMIN PATH forbidden'"
```

**Components**:
- **Variable**: `REQUEST_URI` - The request path (without query string)
- **Operator**: `@streq` - String equality (exact match)
- **Transformation**: `t:lowercase` - Convert to lowercase before matching
- **Phase**: `1` - Request headers phase
- **Action**: `deny` - Block the request
- **ID**: `101` - Rule identifier
- **Message**: `'ADMIN PATH forbidden'` - Rule message

### Matching Behavior

**Blocked Paths**:
- `/admin` ✅ (exact match, lowercase)
- `/ADMIN` ✅ (transformed to /admin)
- `/Admin` ✅ (transformed to /admin)
- `/aDmIn` ✅ (transformed to /admin)
- Any case variation of `/admin` ✅

**Allowed Paths**:
- `/` ✅ (different path)
- `/user` ✅ (different path)
- `/administrator` ✅ (different path, not exact match)
- `/admin/` ✅ (trailing slash makes it different)
- `/admin/users` ✅ (sub-path, not exact match)
- `/api/admin` ✅ (contains admin but not exact match)
- `admin` ✅ (no leading slash)
- `/admin?param=value` ✅ (query string not in REQUEST_URI in Starlette)

### Important Notes

1. **@streq is exact match**: Only blocks exactly `/admin`, not sub-paths
2. **Query strings**: Not included in REQUEST_URI in Starlette integration
3. **Case insensitive**: Due to `t:lowercase` transformation
4. **Phase 1**: Executes during request headers processing, before body
5. **HTTP methods**: Blocks all methods (GET, POST, PUT, DELETE, etc.)

## Running the Tests

### Run All Admin Path Blocking Tests
```bash
# Unit tests
uv run pytest tests/a_unit/operators/test_admin_path_blocking_unit.py -v

# Integration tests
uv run pytest tests/b_integration/test_admin_path_blocking_integration.py -v

# E2E tests
uv run pytest tests/c_e2e/test_admin_path_blocking_e2e.py -v
```

### Run Full Test Suite
```bash
uv run pytest --tb=short -q
```

### Expected Results
- **Total tests**: 700 (including all existing tests)
- **New tests**: 39 (7 unit + 14 integration + 18 E2E)
- **Status**: All passing ✅

## Integration Points

### Starlette Middleware
The E2E tests use the Starlette middleware (`lewaf.integrations.starlette.CorazaMiddleware`):

**Key Behaviors**:
- REQUEST_URI contains only the path (no query string)
- Default block response: HTTP 403 with JSON body
- Custom status codes return text/plain (not JSON)
- Response format: `{"error": "...", "rule_id": 101, "message": "..."}`

### Transaction Processing
The integration tests validate the transaction flow:

1. Create transaction: `tx = waf.new_transaction()`
2. Process URI: `tx.process_uri("/admin", "GET")`
3. Process phase 1: `result = tx.process_request_headers()`
4. Check result: `result["action"] == "deny"` and `result["rule_id"] == 101`

## Use Cases

### Protect Admin Panels
```python
from lewaf.integration import WAF

waf = WAF({
    "rules": [
        'SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny"',
        'SecRule REQUEST_URI "@streq /wp-admin" "id:102,phase:1,t:lowercase,deny"',
    ]
})
```

### Block Multiple Paths
```python
waf = WAF({
    "rules": [
        'SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny"',
        'SecRule REQUEST_URI "@streq /root" "id:102,phase:1,t:lowercase,deny"',
        'SecRule REQUEST_URI "@streq /config" "id:103,phase:1,t:lowercase,deny"',
    ]
})
```

### With Starlette
```python
from starlette.applications import Starlette
from lewaf.integrations.starlette import create_waf_app

app = Starlette(routes=[...])
waf_app = create_waf_app(app, rules=[
    'SecRule REQUEST_URI "@streq /admin" "id:101,phase:1,t:lowercase,deny"'
])
```

## Conclusion

This comprehensive test suite validates that lewaf correctly implements admin path blocking with:

- ✅ **Exact string matching** via @streq operator
- ✅ **Case-insensitive blocking** via t:lowercase transformation
- ✅ **Phase 1 execution** during request headers processing
- ✅ **HTTP method coverage** (GET, POST, PUT, DELETE, etc.)
- ✅ **Proper transaction state** management
- ✅ **HTTP response handling** (403 JSON response)
- ✅ **Performance validation** (<10ms per request)

The tests demonstrate that the engine is working correctly at all levels: unit (operators/transformations), integration (WAF/transaction), and end-to-end (HTTP server/client).
