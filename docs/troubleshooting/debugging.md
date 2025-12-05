# Debugging Guide

This guide covers debugging techniques for LeWAF during development and troubleshooting. For production troubleshooting, see the [Runbook](runbook.md).

---

## Table of Contents

- [Error Code Reference](#error-code-reference)
- [Logging Configuration](#logging-configuration)
- [Debug Logging](#debug-logging)
- [Python Debugging](#python-debugging)
- [Testing and Validation](#testing-and-validation)
- [Common Debugging Scenarios](#common-debugging-scenarios)

---

## Error Code Reference

LeWAF uses standardized error codes for categorization and monitoring.

### Error Code Categories

| Category | Code Range | Description |
|----------|------------|-------------|
| Configuration | WAF-0xxx | Configuration and startup errors |
| Parsing | PARSE-1xxx | Rule parsing errors |
| Rule Evaluation | RULE-2xxx | Rule execution errors |
| Body Processing | BODY-3xxx | Request body errors |
| Operators | OP-4xxx | Operator errors |
| Integration | INT-5xxx | Framework integration errors |
| Storage | STORE-6xxx | Backend storage errors |
| Proxy | PROXY-7xxx | Upstream proxy errors |

### Configuration Errors (WAF-0xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| WAF-0001 | `ConfigurationError` | General configuration error |
| WAF-0002 | `ConfigFileNotFoundError` | Configuration file not found |
| WAF-0003 | `ConfigValidationError` | Configuration validation failed |
| WAF-0004 | `EnvironmentVariableError` | Required environment variable missing |

### Parsing Errors (PARSE-1xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| PARSE-1000 | `ParseError` | General parsing error |
| PARSE-1001 | `SecRuleParseError` | Invalid SecRule format |
| PARSE-1002 | `IncludeRecursionError` | Include recursion limit exceeded |
| PARSE-1003 | `UnknownOperatorError` | Unknown operator in rule |
| PARSE-1004 | `UnknownActionError` | Unknown action in rule |

### Rule Evaluation Errors (RULE-2xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| RULE-2000 | `RuleEvaluationError` | General rule evaluation error |
| RULE-2001 | `OperatorEvaluationError` | Operator evaluation failed |
| RULE-2002 | `ActionExecutionError` | Action execution failed |
| RULE-2003 | `TransformationError` | Transformation failed |

### Body Processing Errors (BODY-3xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| BODY-3000 | `BodyProcessorError` | General body processing error |
| BODY-3001 | `InvalidJSONError` | Invalid JSON in request body |
| BODY-3002 | `InvalidXMLError` | Invalid XML in request body |
| BODY-3003 | `BodySizeLimitError` | Request body exceeds size limit |
| BODY-3004 | `InvalidMultipartError` | Invalid multipart/form-data |

### Operator Errors (OP-4xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| OP-4000 | `OperatorError` | General operator error |
| OP-4001 | `OperatorNotFoundError` | Operator not found in registry |
| OP-4002 | `OperatorArgumentError` | Invalid operator argument |

### Integration Errors (INT-5xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| INT-5000 | `IntegrationError` | General integration error |
| INT-5001 | `ASGIMiddlewareError` | ASGI middleware error |
| INT-5002 | `RequestProcessingError` | Request processing error |

### Storage Errors (STORE-6xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| STORE-6000 | `StorageError` | General storage error |
| STORE-6001 | `StorageBackendError` | Storage backend operation failed |
| STORE-6002 | `CollectionPersistenceError` | Collection persistence failed |

### Proxy Errors (PROXY-7xxx)

| Code | Exception | Description |
|------|-----------|-------------|
| PROXY-7000 | `ProxyError` | General proxy error |
| PROXY-7001 | `UpstreamRequestError` | Upstream request failed |
| PROXY-7002 | `UpstreamTimeoutError` | Upstream request timed out |

---

## Logging Configuration

### Basic Logging Setup

```python
import logging

# Configure root logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Enable LeWAF debug logging
logging.getLogger("lewaf").setLevel(logging.DEBUG)
```

### Structured Error Logging

Use LeWAF's structured logging utilities:

```python
from lewaf.logging.error_logger import (
    log_error,
    log_operator_error,
    log_transformation_error,
    log_storage_error,
    log_body_processing_error,
)

# Log a WAF exception with full context
try:
    process_body(body)
except InvalidJSONError as e:
    log_error(e, logger, transaction_id="tx-123")

# Log operator evaluation error
log_operator_error(
    operator_name="rx",
    error=ValueError("Invalid regex"),
    value=user_input,
    transaction_id="tx-123",
    rule_id=1001,
)
```

### Audit Logging

Configure audit logging for security events:

```python
from lewaf.logging.audit import configure_audit_logging, get_audit_logger

# Configure global audit logger
audit = configure_audit_logging(
    level="INFO",
    format_type="json",           # or "text"
    output="/var/log/lewaf/audit.log",
    mask_sensitive=True,          # PCI-DSS/GDPR compliance
    additional_fields={
        "service": "my-app",
        "environment": "production",
    }
)

# Log security events
audit.log_security_event(
    event_type="attack_detected",
    transaction_id="tx-123",
    source_ip="192.168.1.100",
    request={"method": "POST", "uri": "/api/login"},
    rule={"id": 942100, "msg": "SQL Injection Attack"},
    action="deny",
    processing_time_ms=5.2,
)
```

### JSON Log Format

Audit logs in JSON format look like:

```json
{
  "timestamp": "2025-11-26T10:30:45.123Z",
  "event_type": "attack_detected",
  "transaction_id": "tx-123",
  "source_ip": "192.168.1.100",
  "request": {
    "method": "POST",
    "uri": "/api/login"
  },
  "rule": {
    "id": 942100,
    "msg": "SQL Injection Attack"
  },
  "action": "deny",
  "processing_time_ms": 5.2
}
```

---

## Debug Logging

### Enable Debug Mode

```python
from lewaf.integration import WAF

# Create WAF with debug enabled
waf = WAF({
    "rules": [...],
    "settings": {
        "debug": True,
        "debug_log_level": 9,  # 0-9, higher = more verbose
    }
})
```

### Debug Transaction Processing

```python
import logging

# Enable transaction-level debugging
logging.getLogger("lewaf.transaction").setLevel(logging.DEBUG)
logging.getLogger("lewaf.rules").setLevel(logging.DEBUG)

# Process request with debug output
tx = waf.new_transaction()
tx.process_uri("/api/users?id=1 OR 1=1", "GET")
tx.process_request_headers({
    "Host": "example.com",
    "User-Agent": "test",
})

# Check matched rules
for match in tx.matched_rules:
    print(f"Rule {match.rule_id}: {match.message}")
```

### Debug Rule Evaluation

```python
# Enable rule evaluation debugging
logging.getLogger("lewaf.rules.rule").setLevel(logging.DEBUG)

# Shows for each rule:
# - Variables being checked
# - Operator evaluation results
# - Transformation applied
# - Actions executed
```

### Debug Operators

```python
# Enable operator debugging
logging.getLogger("lewaf.primitives.operators").setLevel(logging.DEBUG)

# Shows:
# - Pattern being matched
# - Input value (truncated)
# - Match result
# - Captured groups
```

---

## Python Debugging

### Using pdb

```python
import pdb

from lewaf.integration import WAF

waf = WAF({"rules": [...]})
tx = waf.new_transaction()

# Set breakpoint before processing
pdb.set_trace()
result = tx.process_uri("/api/test?attack=<script>", "GET")
```

### Using breakpoint() (Python 3.7+)

```python
tx = waf.new_transaction()

# Modern breakpoint
breakpoint()
result = tx.process_request_headers(headers)
```

### Using pudb (Enhanced Debugger)

```bash
# Install pudb
uv add pudb --dev

# Run with pudb
uv run python -m pudb your_script.py
```

### Remote Debugging with debugpy

```python
# Add to your application
import debugpy

debugpy.listen(("0.0.0.0", 5678))
print("Waiting for debugger attach...")
debugpy.wait_for_client()
```

### Profiling Rule Performance

```python
import cProfile
import pstats

from lewaf.integration import WAF

waf = WAF({"rules": rules})

# Profile rule loading
profiler = cProfile.Profile()
profiler.enable()

# Load and process
for _ in range(1000):
    tx = waf.new_transaction()
    tx.process_uri("/test", "GET")

profiler.disable()

# Print stats
stats = pstats.Stats(profiler)
stats.sort_stats("cumulative")
stats.print_stats(20)
```

---

## Testing and Validation

### Rule Validation

```python
from lewaf.integration import WAF
from lewaf.exceptions import SecRuleParseError

# Validate rule syntax
def validate_rules(rules: list[str]) -> list[str]:
    errors = []
    for i, rule in enumerate(rules):
        try:
            waf = WAF({"rules": [rule]})
        except SecRuleParseError as e:
            errors.append(f"Rule {i+1}: {e}")
    return errors

# Test rules
rules = [
    'SecRule ARGS "@rx <script" "id:1001,phase:2,deny"',
    'SecRule ARGS "@invalid test" "id:1002,phase:2,deny"',  # Invalid
]

errors = validate_rules(rules)
for error in errors:
    print(error)
```

### Test Request Processing

```python
import pytest
from lewaf.integration import WAF

def test_sql_injection_blocked():
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx (?i)(union.*select|select.*from)" '
            '"id:1001,phase:2,deny,msg:\'SQL Injection\'"'
        ]
    })

    tx = waf.new_transaction()
    tx.process_uri("/api?id=1 UNION SELECT * FROM users", "GET")
    result = tx.process_request_headers({"Host": "test.com"})

    assert result is not None
    assert result["rule_id"] == 1001

def test_legitimate_request_allowed():
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx <script" "id:1001,phase:2,deny"'
        ]
    })

    tx = waf.new_transaction()
    tx.process_uri("/api?name=john", "GET")
    result = tx.process_request_headers({"Host": "test.com"})

    assert result is None  # No block
```

### Test Body Processing

```python
def test_json_body_inspection():
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx attack" "id:1001,phase:2,deny"'
        ]
    })

    tx = waf.new_transaction()
    tx.process_uri("/api/data", "POST")
    tx.process_request_headers({
        "Host": "test.com",
        "Content-Type": "application/json",
    })

    # Process JSON body
    body = '{"query": "attack"}'
    result = tx.process_request_body(body.encode())

    assert result is not None
```

### Run LeWAF Tests

```bash
# Run all tests
uv run pytest

# Run specific test file
uv run pytest tests/a_unit/test_operators.py

# Run with verbose output
uv run pytest -v

# Run with coverage
uv run pytest --cov=lewaf

# Run only security tests
uv run pytest tests/c_e2e/
```

---

## Common Debugging Scenarios

### Scenario 1: Rule Not Triggering

**Symptoms**: Expected rule doesn't block attack.

**Debugging Steps**:

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("lewaf").setLevel(logging.DEBUG)

waf = WAF({"rules": your_rules})
tx = waf.new_transaction()

# Process step by step
print(f"Processing URI...")
tx.process_uri("/api/test?attack=payload", "GET")

print(f"Processing headers...")
result_headers = tx.process_request_headers({"Host": "test"})
print(f"Headers result: {result_headers}")

print(f"Processing body...")
result_body = tx.process_request_body(b"body content")
print(f"Body result: {result_body}")

# Check variables
print(f"ARGS: {tx.variables.args.get_all()}")
print(f"REQUEST_URI: {tx.variables.request_uri.get()}")
```

**Common Causes**:
1. **Wrong phase**: POST body is inspected in phase 2
2. **Missing transformation**: Pattern needs `t:lowercase`
3. **Variable not populated**: Check `SecRequestBodyAccess On`

### Scenario 2: False Positives

**Symptoms**: Legitimate requests being blocked.

**Debugging Steps**:

```python
# Find which rule triggered
tx = waf.new_transaction()
# ... process request ...

# After blocking
for match in tx.matched_rules:
    print(f"Rule {match.rule_id}: {match.message}")
    print(f"  Variable: {match.variable_name}")
    print(f"  Value: {match.matched_value}")
    print(f"  Pattern: {match.pattern}")

# Test rule in isolation
test_waf = WAF({"rules": [f'SecRule ARGS "@rx {pattern}" "id:1,phase:2,deny"']})
```

**Solutions**:
1. Add rule exception
2. Tune paranoia level
3. Whitelist specific endpoints

### Scenario 3: Performance Issues

**Symptoms**: High latency, CPU usage.

**Debugging Steps**:

```python
import time

waf = WAF({"rules": your_rules})

# Time rule loading
start = time.time()
print(f"Rules loaded in {time.time() - start:.3f}s")

# Time request processing
start = time.time()
for _ in range(100):
    tx = waf.new_transaction()
    tx.process_uri("/test", "GET")
    tx.process_request_headers({"Host": "test"})
elapsed = time.time() - start

print(f"100 requests in {elapsed:.3f}s ({100/elapsed:.1f} req/s)")
```

**Common Causes**:
1. Too many rules enabled
2. Complex regex patterns
3. Large request bodies

### Scenario 4: Body Processing Errors

**Symptoms**: BODY-3xxx errors in logs.

**Debugging Steps**:

```python
from lewaf.bodyprocessors import get_processor

# Test body processor directly
processor = get_processor("application/json")

try:
    result = processor.process(body_content)
    print(f"Parsed body: {result}")
except Exception as e:
    print(f"Parse error: {e}")

# Check if body access is enabled
print(f"Body access: {tx.variables.reqbody_processor.get()}")
print(f"Content-Type: {tx.variables.request_headers.get('content-type')}")
```

---

## Related Documentation

- [Runbook](runbook.md) - Production troubleshooting procedures
- [Security Hardening](../security/hardening.md) - Security best practices
- [Performance Tuning](../performance/tuning.md) - Performance optimization
- [API Reference](../api/reference.md) - Complete API documentation

---

**Questions or Issues?**
- GitHub Issues: https://github.com/abilian/lewaf/issues
- Documentation: https://lewaf.readthedocs.io
