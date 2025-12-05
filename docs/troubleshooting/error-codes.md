# Error Codes Reference

**LeWAF Error Code Catalog**

Complete reference for all LeWAF error codes established in Phase 15.

---

## Table of Contents

- [Overview](#overview)
- [Configuration Errors (WAF-0xxx)](#configuration-errors-waf-0xxx)
- [Parsing Errors (PARSE-1xxx)](#parsing-errors-parse-1xxx)
- [Rule Evaluation Errors (RULE-2xxx)](#rule-evaluation-errors-rule-2xxx)
- [Body Processing Errors (BODY-3xxx)](#body-processing-errors-body-3xxx)
- [Operator Errors (OP-4xxx)](#operator-errors-op-4xxx)
- [Integration Errors (INT-5xxx)](#integration-errors-int-5xxx)
- [Storage Errors (STORE-6xxx)](#storage-errors-store-6xxx)
- [Proxy Errors (PROXY-7xxx)](#proxy-errors-proxy-7xxx)

---

## Overview

LeWAF uses structured error codes following the format: `CATEGORY-NNNN`

### Error Code Structure

```
BODY-3001
 │    │
 │    └─ Unique identifier within category
 └────── Category prefix
```

### Categories

| Category | Prefix | Description |
|----------|--------|-------------|
| Configuration | WAF | Configuration and initialization errors |
| Parsing | PARSE | Rule parsing and validation errors |
| Rule Evaluation | RULE | Runtime rule execution errors |
| Body Processing | BODY | Request/response body processing errors |
| Operators | OP | Operator-related errors |
| Integration | INT | Framework integration errors |
| Storage | STORE | Backend storage errors |
| Proxy | PROXY | Upstream proxy errors |

---

## Configuration Errors (WAF-0xxx)

### WAF-0001: Configuration Error (Base)

**Description**: Generic configuration error

**Common Causes**:
- Invalid configuration syntax
- Conflicting directives
- Missing required settings

**Example**:
```
[WAF-0001] Configuration error: Invalid SecRuleEngine value 'OnOff'
```

**Resolution**:
```apache
# Valid values: On, Off, DetectionOnly
SecRuleEngine On
```

---

### WAF-0002: Config File Not Found

**Description**: Configuration file does not exist

**Common Causes**:
- Wrong file path
- File moved or deleted
- Permission issues

**Example**:
```
[WAF-0002] Configuration file not found: /etc/lewaf/lewaf.conf
```

**Resolution**:
```bash
# Check file exists
ls -la /etc/lewaf/lewaf.conf

# Check permissions
chmod 644 /etc/lewaf/lewaf.conf

# Verify path in startup command
lewaf --config /etc/lewaf/lewaf.conf
```

---

### WAF-0003: Config Validation Error

**Description**: Configuration syntax or validation failed

**Common Causes**:
- Typos in directives
- Invalid values
- Missing quotes

**Example**:
```
[WAF-0003] Configuration validation failed: Unknown directive 'SecRulEngien'
```

**Resolution**:
```apache
# Wrong
SecRulEngien On

# Correct
SecRuleEngine On
```

---

### WAF-0004: Environment Variable Error

**Description**: Required environment variable missing or invalid

**Common Causes**:
- Variable not set
- Wrong variable name
- Invalid value format

**Example**:
```
[WAF-0004] Environment variable error: LEWAF_REDIS_URL not set
```

**Resolution**:
```bash
# Set environment variable
export LEWAF_REDIS_URL="redis://localhost:6379/0"

# Or in systemd service
Environment="LEWAF_REDIS_URL=redis://localhost:6379/0"
```

---

## Parsing Errors (PARSE-1xxx)

### PARSE-1001: SecRule Parse Error

**Description**: Failed to parse SecRule directive

**Common Causes**:
- Invalid syntax
- Missing quotes
- Malformed operator

**Example**:
```
[PARSE-1001] Failed to parse SecRule: Expected operator, got '^attack$'
```

**Resolution**:
```apache
# Wrong
SecRule ARGS ^attack$

# Correct
SecRule ARGS "@rx ^attack$" "id:1000,phase:2,deny"
```

---

### PARSE-1002: Include Recursion Error

**Description**: Include file not found or circular include detected

**Common Causes**:
- File doesn't exist
- Circular includes (A includes B, B includes A)
- Permission denied

**Example**:
```
[PARSE-1002] Include recursion detected or file not found: /app/rules/crs.conf
```

**Resolution**:
```bash
# Check file exists
ls -la /app/rules/crs.conf

# Verify no circular includes
grep -r "Include" /app/rules/

# Use absolute paths
Include /app/rules/crs.conf
```

---

### PARSE-1003: Unknown Operator Error

**Description**: Operator not registered or typo in operator name

**Common Causes**:
- Typo in operator name (@rxx instead of @rx)
- Operator not loaded
- Custom operator not registered

**Example**:
```
[PARSE-1003] Unknown operator: @rxxx
```

**Resolution**:
```apache
# Wrong
SecRule ARGS "@rxxx ^attack$"

# Correct
SecRule ARGS "@rx ^attack$"

# List available operators
python -c "from lewaf.primitives.operators import list_operators; print(list_operators())"
```

---

### PARSE-1004: Unknown Action Error

**Description**: Action not registered or typo in action name

**Common Causes**:
- Typo in action name
- Action not loaded
- Custom action not registered

**Example**:
```
[PARSE-1004] Unknown action: denny
```

**Resolution**:
```apache
# Wrong
SecRule ARGS "@rx attack" "id:1000,phase:2,denny"

# Correct
SecRule ARGS "@rx attack" "id:1000,phase:2,deny"
```

---

## Rule Evaluation Errors (RULE-2xxx)

### RULE-2001: Operator Evaluation Error

**Description**: Error during operator evaluation

**Common Causes**:
- Invalid regex pattern
- Type mismatch
- Operator-specific error

**Example**:
```
[RULE-2001] Operator evaluation error: Invalid regex pattern '(?'
```

**Resolution**:
```apache
# Wrong - invalid regex
SecRule ARGS "@rx (?abc"

# Correct
SecRule ARGS "@rx ^abc$"

# Test regex separately
python -c "import re; re.compile(r'^abc$')"
```

---

### RULE-2002: Action Execution Error

**Description**: Error while executing rule action

**Common Causes**:
- Action configuration error
- Resource not available
- Permission denied

**Example**:
```
[RULE-2002] Action execution error: Failed to write to audit log
```

**Resolution**:
```bash
# Check log directory permissions
ls -la /app/logs/

# Create directory if missing
mkdir -p /app/logs
chown lewaf:lewaf /app/logs
```

---

### RULE-2003: Transformation Error

**Description**: Error during value transformation

**Common Causes**:
- Invalid input for transformation
- Encoding issues
- Transformation failure

**Example**:
```
[RULE-2003] Transformation error: Invalid base64 input
```

**Resolution**:
```apache
# Handle transformation errors gracefully
SecRule ARGS "@rx attack" "id:1000,phase:2,deny,t:base64Decode"

# Check REQBODY_ERROR for body transformation errors
SecRule REQBODY_ERROR "@eq 1" "id:1001,phase:2,log"
```

---

## Body Processing Errors (BODY-3xxx)

### BODY-3001: Invalid JSON Error

**Description**: Failed to parse JSON request body

**Common Causes**:
- Malformed JSON syntax
- Invalid encoding
- Truncated body

**Example**:
```
[BODY-3001] Invalid JSON syntax: Expecting ',' delimiter at line 1 column 15
Context: {"incomplete":
```

**Resolution**:
```bash
# Validate JSON before sending
echo '{"test":"value"}' | jq .

# Check REQBODY_ERROR variable
SecRule REQBODY_ERROR "@eq 1" "id:1001,phase:2,deny,\
  msg:'Request body processing failed'"
```

**Variables Set**:
- `REQBODY_ERROR=1`
- `REQBODY_ERROR_MSG="BODY-3001: Invalid JSON syntax..."`

---

### BODY-3002: Invalid XML Error

**Description**: Failed to parse XML request body

**Common Causes**:
- Malformed XML
- Mismatched tags
- Invalid characters

**Example**:
```
[BODY-3002] Invalid XML: mismatched tag: line 5, column 10
Context: <root><unclosed>
```

**Resolution**:
```bash
# Validate XML
xmllint --noout request.xml

# Check encoding
file -i request.xml
```

**Variables Set**:
- `REQBODY_ERROR=1`
- `REQBODY_ERROR_MSG="BODY-3002: Invalid XML..."`

---

### BODY-3003: Body Size Limit Error

**Description**: Request body exceeds configured limit

**Common Causes**:
- Large file upload
- Limit set too low
- Missing Content-Length check

**Example**:
```
[BODY-3003] Body size 15000000 exceeds limit 13107200
Content-Type: multipart/form-data
```

**Resolution**:
```apache
# Increase limit (in bytes)
SecRequestBodyLimit 20971520  # 20 MB

# Or reject large bodies
SecRequestBodyLimitAction Reject

# Check Content-Length header first
SecRule REQUEST_HEADERS:Content-Length "@gt 13107200" \
  "id:1001,phase:1,deny,msg:'Request too large'"
```

---

### BODY-3004: Invalid Multipart Error

**Description**: Failed to parse multipart/form-data body

**Common Causes**:
- Missing boundary
- Invalid boundary format
- Truncated multipart data

**Example**:
```
[BODY-3004] Invalid multipart format: Missing boundary in Content-Type header
Content-Type: multipart/form-data
```

**Resolution**:
```bash
# Ensure boundary is specified
curl -X POST \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
  -F "file=@test.txt" \
  http://localhost:8000/upload

# Boundary must match in headers and body
```

---

## Operator Errors (OP-4xxx)

### OP-4001: Operator Not Found Error

**Description**: Requested operator is not registered

**Common Causes**:
- Operator not loaded
- Typo in operator name
- Custom operator not registered

**Example**:
```
[OP-4001] Operator not found: @customOp
```

**Resolution**:
```python
# Register custom operator
from lewaf.primitives.operators import register_operator

@register_operator("customOp")
def custom_operator(value, param):
    return value == param

# Verify registration
from lewaf.primitives.operators import get_operator
print(get_operator("customOp"))
```

---

### OP-4002: Operator Argument Error

**Description**: Invalid argument passed to operator

**Common Causes**:
- Missing required parameter
- Wrong parameter type
- Invalid parameter value

**Example**:
```
[OP-4002] Operator argument error: @rx requires a regex pattern
```

**Resolution**:
```apache
# Wrong - missing parameter
SecRule ARGS "@rx" "id:1000,phase:2,deny"

# Correct
SecRule ARGS "@rx ^attack$" "id:1000,phase:2,deny"
```

---

## Integration Errors (INT-5xxx)

### INT-5001: ASGI Middleware Error

**Description**: Error in ASGI middleware processing

**Common Causes**:
- Middleware not properly configured
- ASGI spec violation
- Request processing failure

**Example**:
```
[INT-5001] ASGI middleware error: Failed to read request body
Transaction ID: tx-12345
```

**Resolution**:
```python
# Verify middleware configuration
from lewaf.integration.asgi import LeWAFMiddleware

app = FastAPI()
app.add_middleware(
    LeWAFMiddleware,
    config_path="/etc/lewaf/lewaf.conf",
    audit_log="/app/logs/audit.log"
)

# Check middleware order (LeWAF should be early)
```

---

### INT-5002: Request Processing Error

**Description**: Generic request processing failure

**Common Causes**:
- Invalid request format
- Missing required headers
- Framework-specific error

**Example**:
```
[INT-5002] Request processing error: Missing Content-Type header
```

**Resolution**:
```python
# Ensure proper request handling
@app.post("/upload")
async def upload(request: Request):
    # Verify Content-Type
    content_type = request.headers.get("content-type")
    if not content_type:
        raise HTTPException(400, "Content-Type required")
```

---

## Storage Errors (STORE-6xxx)

### STORE-6001: Storage Backend Error

**Description**: Error communicating with storage backend

**Common Causes**:
- Redis connection failed
- Network timeout
- Authentication failure

**Example**:
```
[STORE-6001] Storage backend error: Connection refused
Backend: redis
Operation: set
Collection: IP
Key: blocked_ips
```

**Resolution**:
```bash
# Test Redis connection
redis-cli ping

# Check Redis status
systemctl status redis

# Verify connection string
echo $LEWAF_REDIS_URL

# Test connectivity
telnet localhost 6379
```

---

### STORE-6002: Collection Persistence Error

**Description**: Failed to persist collection data

**Common Causes**:
- Disk full
- Permission denied
- Serialization error

**Example**:
```
[STORE-6002] Collection persistence error: Disk quota exceeded
Collection: USER_SESSIONS
Size: 1048576 bytes
```

**Resolution**:
```bash
# Check disk space
df -h

# Check permissions
ls -la /app/data/

# Clean up old data
redis-cli FLUSHDB
```

---

## Proxy Errors (PROXY-7xxx)

### PROXY-7001: Upstream Request Error

**Description**: Failed to forward request to upstream

**Common Causes**:
- Upstream server down
- Network error
- Invalid upstream URL

**Example**:
```
[PROXY-7001] Upstream request error: Connection refused
Upstream: http://backend:8080
```

**Resolution**:
```bash
# Test upstream connectivity
curl http://backend:8080/health

# Check network
ping backend

# Verify DNS resolution
nslookup backend
```

---

### PROXY-7002: Upstream Timeout Error

**Description**: Upstream request timed out

**Common Causes**:
- Upstream too slow
- Network latency
- Timeout set too low

**Example**:
```
[PROXY-7002] Upstream timeout: Request exceeded 30s
Upstream: http://backend:8080
Timeout: 30s
```

**Resolution**:
```python
# Increase timeout
from lewaf.proxy import ProxyConfig

config = ProxyConfig(
    upstream_url="http://backend:8080",
    timeout=60  # 60 seconds
)
```

---

## Quick Reference Table

| Code | Severity | Description | Common Fix |
|------|----------|-------------|------------|
| WAF-0001 | High | Configuration error | Check config syntax |
| WAF-0002 | High | Config file not found | Verify file path |
| WAF-0003 | High | Config validation failed | Fix syntax errors |
| WAF-0004 | Medium | Environment variable error | Set required env vars |
| PARSE-1001 | Medium | SecRule parse error | Fix rule syntax |
| PARSE-1002 | Medium | Include file not found | Check include path |
| PARSE-1003 | Medium | Unknown operator | Fix operator name |
| PARSE-1004 | Medium | Unknown action | Fix action name |
| RULE-2001 | Low | Operator evaluation error | Check operator params |
| RULE-2002 | Medium | Action execution error | Check action config |
| RULE-2003 | Low | Transformation error | Validate input data |
| BODY-3001 | Low | Invalid JSON | Validate JSON syntax |
| BODY-3002 | Low | Invalid XML | Validate XML syntax |
| BODY-3003 | Low | Body size exceeded | Increase limit |
| BODY-3004 | Low | Invalid multipart | Fix boundary |
| OP-4001 | Medium | Operator not found | Register operator |
| OP-4002 | Low | Invalid operator argument | Fix operator params |
| INT-5001 | High | ASGI middleware error | Check middleware config |
| INT-5002 | Medium | Request processing error | Validate request |
| STORE-6001 | High | Storage backend error | Check Redis connection |
| STORE-6002 | Medium | Persistence error | Check disk space |
| PROXY-7001 | High | Upstream request failed | Check upstream |
| PROXY-7002 | Medium | Upstream timeout | Increase timeout |

---

## Using Error Codes

### In Logs

Error codes appear in structured logs:

```json
{
  "timestamp": "2025-11-13T10:30:45.123Z",
  "error_code": "BODY-3001",
  "error_category": "body_processing",
  "message": "Invalid JSON syntax",
  "context": {
    "transaction_id": "tx-123"
  }
}
```

### Searching Logs

```bash
# Find all errors of a specific type
grep "BODY-3001" /app/logs/audit.log

# Count errors by code
grep "error_code" /app/logs/audit.log | \
  jq -r .error_code | sort | uniq -c | sort -rn

# Find errors for a transaction
grep "tx-123" /app/logs/audit.log | jq .
```

### Error Handling in Rules

```apache
# Check for body processing errors
SecRule REQBODY_ERROR "@eq 1" \
  "id:1001,phase:2,deny,\
   msg:'Request body processing failed: %{REQBODY_ERROR_MSG}'"

# Log specific error codes
SecRule REQBODY_ERROR_MSG "@contains BODY-3001" \
  "id:1002,phase:2,log,\
   msg:'Invalid JSON detected'"
```

---

## Next Steps

- **Troubleshooting Runbook**: See [runbook.md](runbook.md)
- **Monitoring**: See [../monitoring/prometheus.md](../monitoring/prometheus.md)
- **Debugging Guide**: See [debugging.md](debugging.md)

---

**Questions or Issues?**
- GitHub Issues: https://github.com/abilian/lewaf/issues
- Documentation: https://lewaf.readthedocs.io
