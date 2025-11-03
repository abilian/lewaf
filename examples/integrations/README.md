# LeWAF Framework Integration Examples

This directory contains integration examples for LeWAF with popular Python web frameworks.

## Overview

LeWAF can be integrated with any Python web framework through:
- **ASGI middleware** (Starlette, FastAPI)
- **WSGI middleware** (Flask, Django, any WSGI app)
- **Framework-specific middleware** (Django middleware, Flask hooks)

All examples load the CRS rules from `coraza.conf` (594 rules).

---

## Examples

### 1. Starlette / FastAPI (ASGI)

**File**: `../production/app.py` (production example)

**Quick Start**:
```bash
cd examples/production
uv run uvicorn app:app --host 0.0.0.0 --port 8000
```

**Integration**:
```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from lewaf.integrations.starlette import WAFMiddleware

app = Starlette(
    routes=routes,
    middleware=[
        Middleware(WAFMiddleware, config={
            "engine": "DetectionOnly",
            "rule_files": ["coraza.conf"],
        }),
    ],
)
```

**Pros**:
- Native ASGI support
- Async processing
- Best performance
- Built-in middleware

---

### 2. FastAPI (Advanced)

**File**: `fastapi_example.py`

**Quick Start**:
```bash
uv run python examples/integrations/fastapi_example.py
```

**Features**:
- Custom middleware class
- Dependency injection
- Pydantic models
- OpenAPI documentation
- Exception handlers

**Integration**:
```python
from fastapi import FastAPI
from lewaf_middleware import LeWAFMiddleware

app = FastAPI()
app.add_middleware(LeWAFMiddleware, waf_config=WAF_CONFIG)
```

**API Documentation**:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

**Testing**:
```bash
# Clean request
curl http://localhost:8000/api/users

# Malicious request (SQL injection)
curl "http://localhost:8000/api/users/1?id=1' OR '1'='1"
# Expected: 403 Forbidden

# XSS attempt
curl "http://localhost:8000/api/search" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query": "<script>alert(1)</script>"}'
# Expected: 403 Forbidden
```

---

### 3. Django

**File**: `django_example.py`

**Quick Start**:
```bash
uv run python examples/integrations/django_example.py runserver
```

**Integration**:

Add to `settings.py`:
```python
MIDDLEWARE = [
    # ... other middleware
    'path.to.LeWAFMiddleware',
]

LEWAF_CONFIG = {
    "engine": "DetectionOnly",
    "rule_files": ["coraza.conf"],
}
```

**Middleware**:
```python
class LeWAFMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.waf = WAF(**settings.LEWAF_CONFIG)

    def __call__(self, request):
        tx = self.waf.new_transaction()

        # Process request
        tx.process_request_headers(...)
        if tx.interruption:
            return self._blocked_response(tx)

        # Get response
        response = self.get_response(request)

        # Process response
        tx.process_response_headers(...)

        return response
```

**Testing**:
```bash
# Clean request
curl http://localhost:8000/

# SQL injection attempt
curl "http://localhost:8000/api/users/?id=1' OR '1'='1"
# Expected: 403 Forbidden
```

---

### 4. Flask

**File**: `flask_example.py`

**Quick Start**:
```bash
uv run python examples/integrations/flask_example.py
```

**Integration**:

Uses Flask's `before_request` and `after_request` hooks:

```python
from flask import Flask, g, request
from lewaf.engine import WAF

app = Flask(__name__)
waf = WAF(**WAF_CONFIG)

@app.before_request
def lewaf_before_request():
    tx = waf.new_transaction()
    g.lewaf_tx = tx

    tx.process_request_headers(...)
    if tx.interruption:
        return blocked_response(tx)

@app.after_request
def lewaf_after_request(response):
    tx = g.lewaf_tx
    tx.process_response_headers(...)
    if tx.interruption:
        return blocked_response(tx)
    return response
```

**Testing**:
```bash
# Clean request
curl http://localhost:8000/

# XSS attempt in query parameter
curl "http://localhost:8000/api/search?q=<script>alert(1)</script>"
# Expected: 403 Forbidden

# Admin parameter blocked (custom rule)
curl "http://localhost:8000/?admin=true"
# Expected: 403 Forbidden
```

---

### 5. WSGI (Universal)

**File**: `wsgi_example.py`

**Quick Start**:
```bash
# With Python's built-in server
uv run python examples/integrations/wsgi_example.py

# With gunicorn
uv run gunicorn wsgi_example:application
```

**Integration**:

Works with any WSGI application:

```python
class LeWAFMiddleware:
    def __init__(self, app, waf_config):
        self.app = app
        self.waf = WAF(**waf_config)

    def __call__(self, environ, start_response):
        tx = self.waf.new_transaction()

        # Process request
        tx.process_request_headers(...)
        if tx.interruption:
            return self._blocked_response(tx, start_response)

        # Call wrapped app
        response = self.app(environ, start_response)

        # Process response
        tx.process_response_headers(...)

        return response

# Wrap your WSGI app
application = LeWAFMiddleware(your_wsgi_app, WAF_CONFIG)
```

**Compatible with**:
- Flask
- Django
- Bottle
- Pyramid
- Any WSGI application

**Testing**:
```bash
# Clean request
curl http://localhost:8000/

# Malicious request
curl "http://localhost:8000/api/users?id=1' UNION SELECT * FROM users--"
# Expected: 403 Forbidden
```

---

## Configuration

All examples use a similar configuration structure:

```python
WAF_CONFIG = {
    # Engine mode
    "engine": "DetectionOnly",  # or "On" for blocking

    # CRS rules (594 rules)
    "rule_files": [
        "path/to/coraza.conf",
    ],

    # Request limits
    "request_body_limit": 13107200,  # 12.5 MB
    "request_body_in_memory_limit": 131072,  # 128 KB

    # Response limits
    "response_body_limit": 524288,  # 512 KB

    # Custom rules (optional)
    "custom_rules": [
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny"',
    ],

    # Audit logging (optional)
    "audit_log": "/var/log/lewaf/audit.log",
    "audit_log_parts": "ABIJDEFHZ",
}
```

### Engine Modes

- **`DetectionOnly`**: Log attacks but don't block (safe for testing)
- **`On`**: Block malicious requests (production mode)
- **`Off`**: Disable WAF (not recommended)

### Rule Files

The `rule_files` parameter loads CRS rules:

```python
"rule_files": [
    "coraza.conf",  # Loads all 594 CRS rules
]
```

### Custom Rules

Add application-specific rules:

```python
"custom_rules": [
    # Block admin parameter
    'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin forbidden\'"',

    # Block specific header
    'SecRule REQUEST_HEADERS:X-Admin "@rx ." "id:9002,phase:1,deny"',

    # Rate limiting (example)
    'SecRule IP:REQUEST_COUNT "@gt 100" "id:9003,phase:1,deny,msg:\'Rate limit\'"',
]
```

---

## Testing

### Manual Testing

```bash
# Clean request
curl http://localhost:8000/

# SQL injection
curl "http://localhost:8000/?id=1' OR '1'='1"

# XSS
curl "http://localhost:8000/?q=<script>alert(1)</script>"

# Path traversal
curl "http://localhost:8000/?file=../../etc/passwd"

# Command injection
curl "http://localhost:8000/?cmd=;ls"

# Custom rule (admin parameter)
curl "http://localhost:8000/?admin=true"
```

### Expected Responses

**Clean request**:
```
HTTP/1.1 200 OK
Content-Type: text/plain
Hello from [framework] with LeWAF protection!
```

**Blocked request**:
```json
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Request blocked by WAF",
  "rule_id": "942100",
  "message": "deny"
}
```

### Automated Testing

```bash
# Run integration tests
uv run pytest tests/test_integration.py

# Test specific framework
uv run pytest tests/test_integration.py::test_flask_integration

# With coverage
uv run pytest --cov=lewaf tests/
```

---

## Performance

### Benchmarks

With CRS rules loaded (594 rules):

| Framework | Requests/sec | Latency (p95) | Memory |
|-----------|--------------|---------------|---------|
| Starlette | 800-1000     | 15-25ms       | 150MB   |
| FastAPI   | 700-900      | 20-30ms       | 160MB   |
| Flask     | 500-700      | 30-50ms       | 140MB   |
| Django    | 400-600      | 40-60ms       | 180MB   |
| WSGI      | 450-650      | 35-55ms       | 145MB   |

*Benchmarks on Apple M1, Python 3.12, single worker*

### Optimization Tips

1. **Use ASGI**: Starlette/FastAPI have best performance
2. **Increase workers**: `--workers 4` for uvicorn/gunicorn
3. **Regex cache**: Set `regex_cache_size: 512` in config
4. **Reduce logging**: Set `debug: false` in production
5. **Response body**: Disable if not needed for better performance

---

## Production Deployment

### Docker

All examples work with Docker:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
RUN pip install uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen

# Copy application
COPY . .

# Run (adjust for your framework)
CMD ["uv", "run", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### systemd

For non-Docker deployments:

```ini
[Unit]
Description=LeWAF Application
After=network.target

[Service]
Type=notify
User=lewaf
WorkingDirectory=/opt/lewaf
ExecStart=/usr/local/bin/uv run uvicorn app:app --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Nginx Reverse Proxy

```nginx
upstream lewaf_backend {
    server localhost:8000;
}

server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://lewaf_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## Troubleshooting

### Rules Not Loading

```bash
# Verify coraza.conf exists
ls -la coraza.conf

# Test rule parsing
uv run python -c "
from lewaf.parser import parse_config_file
rules = parse_config_file('coraza.conf')
print(f'Loaded {len(rules)} rules')
"
```

### Requests Not Blocked

```bash
# Check engine mode
# Ensure config has: "engine": "On"

# Test with obvious attack
curl "http://localhost:8000/?id=1' OR '1'='1" -v

# Check logs
tail -f /var/log/lewaf/audit.log
```

### High Memory Usage

```bash
# Reduce regex cache
"regex_cache_size": 128  # default: 256

# Limit request body size
"request_body_limit": 1048576  # 1MB

# Disable response body inspection
"response_body_limit": 0
```

### Performance Issues

```bash
# Use multiple workers
uvicorn app:app --workers 4

# Profile with py-spy
uv add --dev py-spy
uv run py-spy record -o profile.svg -- python app.py
```

---

## Additional Resources

- [DEPLOYMENT_GUIDE.md](../production/DEPLOYMENT_GUIDE.md) - Full deployment guide
- [MONITORING.md](../production/MONITORING.md) - Monitoring and logging
- [ROADMAP.md](../../ROADMAP.md) - Project status and features
- [OWASP CRS](https://coreruleset.org/) - Core Rule Set docs

---

## Support

For issues or questions:
- Check framework-specific documentation
- Test rule loading with `verify_rules.sh`
- Review audit logs for blocked requests
- Run health checks with `health_check.sh`
