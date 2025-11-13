# LeWAF Quickstart Guide

Get started with LeWAF in 5 minutes.

---

## Table of Contents

1. [Installation](#installation)
2. [Basic Usage](#basic-usage)
3. [ASGI Middleware Integration](#asgi-middleware-integration)
4. [Configuration](#configuration)
5. [Writing Your First Rule](#writing-your-first-rule)
6. [Testing and Verification](#testing-and-verification)
7. [Next Steps](#next-steps)

---

## Installation

### Using pip

```bash
pip install lewaf
```

### Using uv (recommended)

```bash
uv pip install lewaf
```

### From source

```bash
git clone https://github.com/your-org/lewaf.git
cd lewaf
uv sync
```

---

## Basic Usage

### Simple Request Filtering

```python
from lewaf.integration import WAF

# Create WAF instance with inline rules
waf = WAF(config={
    "rules": [
        "SecRuleEngine On",
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny,status:403,msg:\'XSS attempt\'"'
    ],
    "rule_files": []
})

# Process a request
tx = waf.new_transaction()

# Set request details
tx.process_uri("/api/search?q=test", "GET")
tx.add_request_header("User-Agent", "Mozilla/5.0")

# Evaluate request
result = tx.process_request_headers()

if result:
    print(f"⛔ Request blocked: {result['message']}")
    print(f"   Rule ID: {result['rule_id']}")
    print(f"   Status: {result['status']}")
else:
    print("✅ Request allowed")
```

**Output**:
```
✅ Request allowed
```

### Detecting an Attack

```python
# Try with malicious input
tx = waf.new_transaction()
tx.process_uri("/api/search?q=<script>alert('xss')</script>", "GET")

result = tx.process_request_headers()

if result:
    print(f"⛔ Blocked: {result['message']}")  # "XSS attempt"
```

**Output**:
```
⛔ Blocked: XSS attempt
```

---

## ASGI Middleware Integration

### FastAPI

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

# Wrap with LeWAF middleware
app = ASGIMiddleware(
    app,
    config_file="config/lewaf.yaml"
)

@app.get("/api/users")
def get_users(name: str = ""):
    return {"users": [{"name": name}]}
```

**Test it**:
```bash
# Safe request
curl "http://localhost:8000/api/users?name=alice"
# ✅ Returns: {"users": [{"name": "alice"}]}

# Attack attempt
curl "http://localhost:8000/api/users?name=<script>alert(1)</script>"
# ⛔ Returns: 403 Forbidden
```

### Starlette

```python
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from lewaf.integration.asgi import ASGIMiddleware

async def homepage(request):
    return JSONResponse({"message": "Hello, world!"})

app = Starlette(routes=[
    Route("/", homepage),
])

# Add LeWAF protection
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### Flask (via WSGI adapter)

```python
from flask import Flask
from lewaf.integration.asgi import ASGIMiddleware
from asgiref.wsgi import WsgiToAsgi

app = Flask(__name__)

@app.route("/api/data")
def get_data():
    return {"data": "value"}

# Convert WSGI to ASGI and wrap with LeWAF
asgi_app = WsgiToAsgi(app)
protected_app = ASGIMiddleware(asgi_app, config_file="config/lewaf.yaml")
```

---

## Configuration

### Minimal Configuration File

Create `config/lewaf.yaml`:

```yaml
# Engine mode: On, DetectionOnly, or Off
engine: On

# Inline rules (optional)
rules:
  - "SecRuleEngine On"

# Rule files to load
rule_files:
  - "rules/crs-setup.conf"
  - "rules/REQUEST-*.conf"

# Request limits
request_limits:
  body_limit: 13107200      # 12.5 MB
  header_limit: 8192        # 8 KB
  request_line_limit: 8192  # 8 KB

# Storage backend
storage:
  backend: memory  # or "file", "redis"

# Audit logging
audit_logging:
  enabled: true
  format: json
  output: /var/log/lewaf/audit.log
  level: INFO
```

### Load Configuration

```python
from lewaf.config import load_config
from lewaf.integration import WAF

# Load from file
config = load_config("config/lewaf.yaml")

# Create WAF with loaded config
waf = WAF(config={
    "rules": config.rules,
    "rule_files": config.rule_files
})
```

---

## Writing Your First Rule

### SecLang Rule Syntax

```
SecRule VARIABLES "@OPERATOR argument" "ACTION1,ACTION2,..."
```

**Components**:
- **VARIABLES**: What to inspect (ARGS, REQUEST_HEADERS, etc.)
- **@OPERATOR**: How to match (rx, eq, contains, etc.)
- **ACTIONS**: What to do on match (deny, log, setvar, etc.)

### Example Rules

#### Block SQL Injection

```
SecRule ARGS "@rx (?i)(union|select|insert|update|delete)" \
    "id:1001,phase:2,deny,status:403,msg:'SQL injection attempt'"
```

#### Block XSS

```
SecRule ARGS "@rx (?i)<script" \
    "id:1002,phase:2,deny,status:403,msg:'XSS attempt detected'"
```

#### Rate Limiting

```
# Initialize IP collection
SecAction "id:2001,phase:1,nolog,initcol:IP=%{REMOTE_ADDR}"

# Increment request counter
SecAction "id:2002,phase:1,nolog,setvar:IP.requests=+1"

# Block if > 100 requests
SecRule IP:requests "@gt 100" \
    "id:2003,phase:1,deny,status:429,msg:'Rate limit exceeded'"
```

#### Custom Header Validation

```
SecRule REQUEST_HEADERS:X-API-Key "!@rx ^[A-Za-z0-9]{32}$" \
    "id:3001,phase:1,deny,status:401,msg:'Invalid API key format'"
```

### Rule File

Create `rules/custom.conf`:

```
# Custom WAF Rules
# Author: Your Name
# Date: 2025-11-13

# Enable rule engine
SecRuleEngine On

# Default actions for phase 1 and 2
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# Block common attack patterns
SecRule ARGS|REQUEST_HEADERS "@rx (?i)(union|select|insert|update|delete)" \
    "id:100001,phase:2,t:lowercase,deny,status:403,msg:'SQL injection detected'"

SecRule ARGS|REQUEST_HEADERS "@rx (?i)<script" \
    "id:100002,phase:2,t:lowercase,deny,status:403,msg:'XSS detected'"

# Validate Content-Type for POST requests
SecRule REQUEST_METHOD "@streq POST" \
    "id:100003,phase:1,chain"
    SecRule REQUEST_HEADERS:Content-Type "!@rx ^(application/json|application/x-www-form-urlencoded|multipart/form-data)" \
        "deny,status:415,msg:'Unsupported Content-Type'"
```

### Load Custom Rules

```python
waf = WAF(config={
    "rules": [],
    "rule_files": ["rules/custom.conf"]
})
```

Or in YAML config:

```yaml
rule_files:
  - "rules/custom.conf"
```

---

## Testing and Verification

### Unit Testing Your Rules

```python
import pytest
from lewaf.integration import WAF

@pytest.fixture
def waf():
    return WAF(config={
        "rules": [
            'SecRule ARGS:username "@eq admin" "id:1,phase:2,deny,msg:\'Admin blocked\'"'
        ],
        "rule_files": []
    })

def test_blocks_admin_username(waf):
    tx = waf.new_transaction()
    tx.process_uri("/login?username=admin", "GET")

    result = tx.process_request_headers()

    assert result is not None
    assert result["status"] == 403
    assert "Admin blocked" in result["message"]

def test_allows_normal_username(waf):
    tx = waf.new_transaction()
    tx.process_uri("/login?username=alice", "GET")

    result = tx.process_request_headers()

    assert result is None  # Not blocked
```

### Integration Testing

```python
from fastapi.testclient import TestClient
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.get("/api/search")
def search(q: str):
    return {"results": [q]}

# Wrap with WAF
app = ASGIMiddleware(app, config_dict={
    "rules": ['SecRule ARGS:q "@rx <script" "id:1,phase:2,deny"'],
    "rule_files": []
})

def test_blocks_xss():
    client = TestClient(app)

    # Safe request
    response = client.get("/api/search?q=test")
    assert response.status_code == 200

    # XSS attempt
    response = client.get("/api/search?q=<script>alert(1)</script>")
    assert response.status_code == 403
```

### Manual Testing

```bash
# Start server
uvicorn main:app --host 0.0.0.0 --port 8000

# Test safe request
curl -v "http://localhost:8000/api/search?q=test"
# Expected: 200 OK

# Test blocked request
curl -v "http://localhost:8000/api/search?q=<script>alert(1)</script>"
# Expected: 403 Forbidden
```

### Configuration Validation

```bash
# Validate configuration file
lewaf-validate config/lewaf.yaml

# Strict validation (fails on warnings)
lewaf-validate config/lewaf.yaml --strict

# Check rule files
lewaf-validate config/lewaf.yaml --check-rules
```

---

## Common Patterns

### 1. Multi-Phase Protection

```python
waf = WAF(config={
    "rules": [
        # Phase 1: Request headers
        'SecRule REQUEST_HEADERS:User-Agent "@rx bot" "id:1,phase:1,deny,msg:\'Bot blocked\'"',

        # Phase 2: Request body
        'SecRule ARGS "@rx <script" "id:2,phase:2,deny,msg:\'XSS blocked\'"',

        # Phase 3: Response headers
        'SecRule RESPONSE_HEADERS:X-Powered-By "@rx PHP" "id:3,phase:3,deny,msg:\'Info leak\'"',

        # Phase 4: Response body
        'SecRule RESPONSE_BODY "@rx (?i)error" "id:4,phase:4,log,msg:\'Error in response\'"'
    ],
    "rule_files": []
})
```

### 2. Conditional Rules (Chaining)

```python
rules = [
    # Only check POST requests
    'SecRule REQUEST_METHOD "@streq POST" "id:1,phase:2,chain,nolog"',
    'SecRule ARGS:password "@rx ^.{0,7}$" "deny,msg:\'Password too short\'"',
]
```

### 3. Variable Setting and Scoring

```python
rules = [
    # Initialize score
    'SecAction "id:1,phase:1,nolog,setvar:TX.anomaly_score=0"',

    # Increase score on suspicious activity
    'SecRule ARGS "@rx <script" "id:2,phase:2,log,setvar:TX.anomaly_score=+5"',
    'SecRule ARGS "@rx (union|select)" "id:3,phase:2,log,setvar:TX.anomaly_score=+5"',

    # Block if score too high
    'SecRule TX:anomaly_score "@gt 10" "id:4,phase:2,deny,status:403,msg:\'Anomaly score exceeded\'"',
]
```

### 4. IP Reputation Tracking

```python
rules = [
    # Initialize IP collection
    'SecAction "id:1,phase:1,nolog,initcol:IP=%{REMOTE_ADDR}"',

    # Track failed logins
    'SecRule ARGS:login_failed "@eq 1" "id:2,phase:2,nolog,setvar:IP.failed_logins=+1"',

    # Block after 5 failures
    'SecRule IP:failed_logins "@gt 5" "id:3,phase:1,deny,status:429,msg:\'Too many failures\'"',

    # Expire after 1 hour
    'SecRule IP:failed_logins "@gt 0" "id:4,phase:5,nolog,expirevar:IP.failed_logins=3600"',
]
```

---

## Environment-Specific Configuration

### Development

```yaml
# config/dev.yaml
engine: DetectionOnly  # Log only, don't block
audit_logging:
  enabled: true
  format: text
  output: stdout
  level: DEBUG
storage:
  backend: memory
```

### Staging

```yaml
# config/staging.yaml
engine: On
audit_logging:
  enabled: true
  format: json
  output: /var/log/lewaf/audit.log
  level: INFO
storage:
  backend: redis
  redis_host: ${REDIS_HOST:-localhost}
```

### Production

```yaml
# config/production.yaml
engine: On
audit_logging:
  enabled: true
  format: json
  output: /var/log/lewaf/audit.log
  level: WARNING
  mask_sensitive: true
storage:
  backend: redis
  redis_host: ${REDIS_HOST}
  redis_port: ${REDIS_PORT:-6379}
performance:
  regex_cache_size: 256
```

---

## Troubleshooting

### Rules Not Triggering

**Problem**: Rules don't seem to be matching.

**Solutions**:
1. Check rule phase matches processing call
2. Verify transformations are applied correctly
3. Enable debug logging
4. Test regex patterns separately

```python
# Debug rule matching
import logging
logging.basicConfig(level=logging.DEBUG)

# Check what variables are available
tx.process_uri("/test?q=value", "GET")
print(tx.variables.args.find_all())  # See all ARGS
```

### Performance Issues

**Problem**: WAF is slowing down requests.

**Solutions**:
1. Use Redis instead of file storage
2. Increase regex cache size
3. Disable unused rules
4. Use specific variables instead of broad matches

```yaml
# Optimize performance
performance:
  regex_cache_size: 512  # Increase cache
storage:
  backend: redis  # Fast storage
```

### False Positives

**Problem**: Legitimate requests are blocked.

**Solutions**:
1. Use DetectionOnly mode during tuning
2. Add exceptions for specific patterns
3. Adjust paranoia level
4. Review audit logs

```python
# Exception rule
rules = [
    # Allow specific user agent
    'SecRule REQUEST_HEADERS:User-Agent "@contains MyApp" "id:1,phase:1,allow,ctl:ruleEngine=Off"',

    # Then apply strict rules
    'SecRule ARGS "@rx <script" "id:2,phase:2,deny"',
]
```

---

## Next Steps

### 1. Learn More

- **[API Reference](../api/reference.md)** - Complete API documentation
- **[Custom Rules Guide](custom-rules.md)** - Advanced rule writing
- **[Error Codes](../troubleshooting/error-codes.md)** - Error reference

### 2. Integration Guides

- **[FastAPI Integration](integration-fastapi.md)** - FastAPI examples
- **[Flask Integration](integration-flask.md)** - Flask examples
- **[Starlette Integration](integration-starlette.md)** - Starlette examples

### 3. Production Deployment

- **[Docker Deployment](../deployment/docker.md)** - Containerized deployment
- **[Kubernetes Deployment](../deployment/kubernetes.md)** - K8s deployment
- **[Performance Tuning](../performance/tuning.md)** - Optimization guide

### 4. OWASP Core Rule Set (CRS)

Download and use production-ready rules:

```bash
# Download OWASP CRS
wget https://github.com/coreruleset/coreruleset/archive/v4.0.0.tar.gz
tar -xzf v4.0.0.tar.gz
mv coreruleset-4.0.0/rules ./

# Configure
cp rules/crs-setup.conf.example rules/crs-setup.conf

# Update config
echo "rule_files:" > config/lewaf.yaml
echo "  - rules/crs-setup.conf" >> config/lewaf.yaml
echo "  - rules/REQUEST-*.conf" >> config/lewaf.yaml
```

### 5. Monitoring and Observability

Set up monitoring with Prometheus:

```python
from lewaf.integration.asgi import ASGIMiddleware
from prometheus_client import Counter, Histogram

# Create metrics
requests_blocked = Counter('lewaf_requests_blocked_total', 'Blocked requests')
request_duration = Histogram('lewaf_request_duration_seconds', 'Request duration')

# Use middleware with metrics
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

---

## Complete Example Application

```python
from fastapi import FastAPI, HTTPException
from lewaf.integration.asgi import ASGIMiddleware
from lewaf.config import load_config

# Create FastAPI app
app = FastAPI(title="Protected API")

# Define routes
@app.get("/api/users/{user_id}")
def get_user(user_id: int):
    return {"id": user_id, "name": "Alice"}

@app.post("/api/users")
def create_user(name: str, email: str):
    return {"id": 1, "name": name, "email": email}

# Load WAF configuration
config = load_config("config/lewaf.yaml")

# Wrap with LeWAF middleware
app = ASGIMiddleware(
    app,
    config_file="config/lewaf.yaml",
    enable_hot_reload=True  # Reload on config change
)

# Run with: uvicorn main:app --reload
```

---

## Quick Reference

### Common SecLang Directives

| Directive | Purpose | Example |
|-----------|---------|---------|
| `SecRule` | Define a rule | `SecRule ARGS "@rx attack" "deny"` |
| `SecAction` | Unconditional action | `SecAction "id:1,setvar:TX.score=0"` |
| `SecRuleEngine` | Enable/disable engine | `SecRuleEngine On` |
| `SecDefaultAction` | Default phase actions | `SecDefaultAction "phase:2,log,pass"` |
| `Include` | Include rule file | `Include rules/*.conf` |

### Common Variables

| Variable | Contains |
|----------|----------|
| `ARGS` | All request arguments |
| `ARGS_GET` | Query string arguments |
| `ARGS_POST` | POST body arguments |
| `REQUEST_HEADERS` | Request headers |
| `REQUEST_URI` | Request URI |
| `REQUEST_BODY` | Request body |
| `REMOTE_ADDR` | Client IP address |
| `TX` | Transaction variables |

### Common Operators

| Operator | Purpose |
|----------|---------|
| `@rx` | Regular expression |
| `@eq` | Exact match |
| `@contains` | Substring match |
| `@gt` | Greater than |
| `@lt` | Less than |
| `@detectSQLi` | SQL injection detection |
| `@detectXSS` | XSS detection |

### Common Actions

| Action | Purpose |
|--------|---------|
| `deny` | Block request |
| `allow` | Allow request |
| `log` | Log match |
| `pass` | Continue processing |
| `setvar` | Set variable |
| `msg` | Set message |
| `severity` | Set severity |

---

**Ready to build secure applications with LeWAF!** 🚀

For questions or issues, check the [troubleshooting runbook](../troubleshooting/runbook.md).

---

**Last Updated**: 2025-11-13
**Version**: 1.0.0
