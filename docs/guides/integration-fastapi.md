# LeWAF FastAPI Integration Guide

Complete guide for integrating LeWAF with FastAPI applications.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Integration](#basic-integration)
3. [Configuration](#configuration)
4. [Advanced Patterns](#advanced-patterns)
5. [Testing](#testing)
6. [Production Deployment](#production-deployment)
7. [Troubleshooting](#troubleshooting)

---

## Quick Start

### Installation

```bash
pip install lewaf fastapi uvicorn
```

### Minimal Example

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello World"}

# Protect with LeWAF
app = ASGIMiddleware(app, config_dict={
    "rules": ['SecRule ARGS "@rx <script" "id:1,phase:2,deny"'],
    "rule_files": []
})

# Run with: uvicorn main:app --reload
```

**Test**:
```bash
# Safe request
curl http://localhost:8000/
# ✅ {"message": "Hello World"}

# Blocked request
curl "http://localhost:8000/?q=<script>alert(1)</script>"
# ⛔ 403 Forbidden
```

---

## Basic Integration

### Method 1: Configuration File (Recommended)

**File**: `config/lewaf.yaml`
```yaml
engine: On
rule_files:
  - "rules/crs-setup.conf"
  - "rules/REQUEST-*.conf"
```

**File**: `main.py`
```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI(
    title="Protected API",
    description="API protected by LeWAF"
)

# Define your routes
@app.get("/api/users")
def list_users():
    return {"users": []}

@app.post("/api/users")
def create_user(name: str, email: str):
    return {"id": 1, "name": name, "email": email}

# Wrap entire application
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### Method 2: Inline Configuration

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.get("/api/search")
def search(q: str):
    return {"results": [q]}

# Configure inline
app = ASGIMiddleware(
    app,
    config_dict={
        "rules": [
            "SecRuleEngine On",
            'SecRule ARGS "@rx (?i)<script" "id:1001,phase:2,deny,msg:\'XSS detected\'"',
            'SecRule ARGS "@rx (?i)(union|select)" "id:1002,phase:2,deny,msg:\'SQL injection\'"',
        ],
        "rule_files": []
    }
)
```

### Method 3: Shared WAF Instance (Multiple Apps)

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddlewareFactory

# Create factory with shared WAF instance
factory = ASGIMiddlewareFactory(config_file="config/lewaf.yaml")

# App 1: Public API
public_app = FastAPI()

@public_app.get("/public/info")
def public_info():
    return {"public": True}

# App 2: Admin API
admin_app = FastAPI()

@admin_app.get("/admin/users")
def admin_users():
    return {"users": []}

# Wrap both apps with same WAF instance
public_app = factory.wrap(public_app)
admin_app = factory.wrap(admin_app)
```

---

## Configuration

### Full Configuration Example

**File**: `config/lewaf-fastapi.yaml`
```yaml
# Engine mode
engine: On  # or DetectionOnly, Off

# Request limits
request_limits:
  body_limit: 10485760  # 10 MB for API
  header_limit: 8192
  request_line_limit: 8192

# Storage backend (for IP tracking, rate limiting)
storage:
  backend: redis
  redis_host: ${REDIS_HOST:-localhost}
  redis_port: ${REDIS_PORT:-6379}
  redis_db: 0
  ttl: 3600

# Audit logging
audit_logging:
  enabled: true
  format: json
  output: /var/log/lewaf/fastapi-audit.log
  level: INFO
  mask_sensitive: true
  additional_fields:
    app: fastapi-api
    environment: ${ENV:-development}

# Performance
performance:
  regex_cache_size: 256

# Rules
rule_files:
  - "rules/fastapi-custom.conf"
  - "rules/crs-setup.conf"
  - "rules/REQUEST-901-INITIALIZATION.conf"
  - "rules/REQUEST-903-APPLICATION-ATTACK-*/*.conf"
  - "rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf"
```

### Custom FastAPI Rules

**File**: `rules/fastapi-custom.conf`
```
# FastAPI-specific WAF Rules

SecRuleEngine On

# Default actions
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# === API-Specific Rules ===

# Require JSON Content-Type for POST/PUT/PATCH
SecRule REQUEST_METHOD "@rx ^(POST|PUT|PATCH)$" \
    "id:10001,phase:1,chain,t:uppercase"
    SecRule REQUEST_URI "@rx ^/api/" \
        "chain"
        SecRule REQUEST_HEADERS:Content-Type "!@rx ^application/json" \
            "deny,status:415,msg:'API requires application/json Content-Type'"

# Validate JSON body structure
SecRule REQUEST_HEADERS:Content-Type "@rx application/json" \
    "id:10002,phase:2,chain"
    SecRule REQUEST_BODY "@rx ^\s*$" \
        "deny,status:400,msg:'Empty JSON body'"

# API key validation
SecRule REQUEST_HEADERS:X-API-Key "!@rx ^[A-Za-z0-9]{32,64}$" \
    "id:10003,phase:1,deny,status:401,msg:'Invalid or missing API key'"

# Rate limiting per IP
SecAction "id:10004,phase:1,nolog,initcol:IP=%{REMOTE_ADDR}"

SecAction "id:10005,phase:1,nolog,setvar:IP.requests=+1"

SecRule IP:requests "@gt 100" \
    "id:10006,phase:1,deny,status:429,msg:'Rate limit: max 100 requests/hour'"

# Block known bad user agents
SecRule REQUEST_HEADERS:User-Agent "@pmFromFile rules/bad-bots.txt" \
    "id:10007,phase:1,deny,status:403,msg:'Blocked user agent'"

# Path traversal protection
SecRule REQUEST_URI "@rx \.\." \
    "id:10008,phase:1,deny,status:400,msg:'Path traversal attempt'"

# Require authentication for protected endpoints
SecRule REQUEST_URI "@rx ^/api/(admin|internal)/" \
    "id:10009,phase:1,chain"
    SecRule REQUEST_HEADERS:Authorization "!@rx ^Bearer " \
        "deny,status:401,msg:'Authentication required'"
```

---

## Advanced Patterns

### 1. Per-Route Protection

```python
from fastapi import FastAPI, Request
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

# Public routes (no extra protection)
@app.get("/public/status")
def public_status():
    return {"status": "ok"}

# Protected routes
@app.post("/api/admin/users")
def admin_create_user(name: str):
    return {"id": 1, "name": name}

# Protect entire app
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### 2. Custom Blocking Response

```python
from fastapi import FastAPI, Response
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.get("/api/data")
def get_data():
    return {"data": "value"}

# Middleware handles blocking automatically
# Blocked requests return HTTP 403 with message from rule
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### 3. IP Whitelist/Blacklist

```python
# In rules/fastapi-custom.conf
SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" \
    "id:20001,phase:1,allow,msg:'Internal network - allow all'"

SecRule REMOTE_ADDR "@ipMatchFromFile rules/blocked-ips.txt" \
    "id:20002,phase:1,deny,status:403,msg:'IP blocked'"
```

**File**: `rules/blocked-ips.txt`
```
192.0.2.1
198.51.100.0/24
203.0.113.42
```

### 4. Request/Response Logging

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware
import logging

logging.basicConfig(level=logging.INFO)

app = FastAPI()

@app.get("/api/sensitive")
def sensitive_data():
    return {"secret": "value"}

# Enable audit logging in config
app = ASGIMiddleware(
    app,
    config_dict={
        "rules": ['SecRule ARGS "@rx attack" "id:1,deny,log"'],
        "rule_files": []
    }
)

# Audit logs will show blocked requests
```

### 5. Dynamic Configuration Reload

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.get("/api/data")
def get_data():
    return {"data": "value"}

# Enable hot reload
app = ASGIMiddleware(
    app,
    config_file="config/lewaf.yaml",
    enable_hot_reload=True  # Reload on SIGHUP signal
)

# Reload config: kill -HUP <process_id>
```

### 6. GraphQL Protection

```python
from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter
from lewaf.integration.asgi import ASGIMiddleware
import strawberry

@strawberry.type
class Query:
    @strawberry.field
    def hello(self) -> str:
        return "Hello World"

schema = strawberry.Schema(query=Query)
graphql_app = GraphQLRouter(schema)

app = FastAPI()
app.include_router(graphql_app, prefix="/graphql")

# Protect GraphQL endpoint
app = ASGIMiddleware(app, config_dict={
    "rules": [
        # Limit query depth/complexity
        'SecRule REQUEST_BODY "@rx \\{[^}]*\\{[^}]*\\{[^}]*\\{" \
            "id:30001,phase:2,deny,msg:\'Query too deep\'"',

        # Limit query length
        'SecRule REQUEST_BODY "@rx ^.{10000,}" \
            "id:30002,phase:2,deny,msg:\'Query too long\'"',
    ],
    "rule_files": []
})
```

### 7. File Upload Protection

```python
from fastapi import FastAPI, File, UploadFile
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    return {"filename": file.filename, "size": len(await file.read())}

# Protect uploads
app = ASGIMiddleware(app, config_dict={
    "rules": [
        # Limit file size
        'SecRule FILES_COMBINED_SIZE "@gt 10485760" \
            "id:40001,phase:2,deny,status:413,msg:\'File too large (max 10MB)\'"',

        # Restrict file types
        'SecRule FILES:file "@rx \\.(exe|dll|bat|sh)$" \
            "id:40002,phase:2,deny,msg:\'Dangerous file type\'"',

        # Scan file content (example: no embedded scripts in images)
        'SecRule FILES "@rx <script" \
            "id:40003,phase:2,deny,msg:\'Malicious file content\'"',
    ],
    "rule_files": []
})
```

---

## Testing

### Unit Tests

```python
from fastapi.testclient import TestClient
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

def create_app():
    app = FastAPI()

    @app.get("/api/search")
    def search(q: str):
        return {"results": [q]}

    return ASGIMiddleware(app, config_dict={
        "rules": ['SecRule ARGS:q "@rx <script" "id:1,phase:2,deny"'],
        "rule_files": []
    })

def test_blocks_xss():
    app = create_app()
    client = TestClient(app)

    # Safe request
    response = client.get("/api/search?q=test")
    assert response.status_code == 200
    assert response.json() == {"results": ["test"]}

    # XSS attempt
    response = client.get("/api/search?q=<script>alert(1)</script>")
    assert response.status_code == 403

def test_allows_safe_html_entities():
    app = create_app()
    client = TestClient(app)

    response = client.get("/api/search?q=&lt;test&gt;")
    assert response.status_code == 200
```

### Integration Tests

```python
import pytest
from fastapi.testclient import TestClient
from main import app  # Your FastAPI app with LeWAF

@pytest.fixture
def client():
    return TestClient(app)

def test_sql_injection_blocked(client):
    response = client.get("/api/users?id=1 UNION SELECT * FROM passwords")
    assert response.status_code == 403

def test_normal_request_allowed(client):
    response = client.get("/api/users?id=123")
    assert response.status_code == 200

def test_post_with_json(client):
    response = client.post(
        "/api/users",
        json={"name": "Alice", "email": "alice@example.com"}
    )
    assert response.status_code == 200

def test_post_with_malicious_json(client):
    response = client.post(
        "/api/users",
        json={"name": "<script>alert(1)</script>", "email": "test@example.com"}
    )
    assert response.status_code == 403
```

### Load Testing

```python
# locustfile.py
from locust import HttpUser, task, between

class FastAPIUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def get_users(self):
        self.client.get("/api/users")

    @task(1)
    def create_user(self):
        self.client.post("/api/users", json={
            "name": "Test User",
            "email": "test@example.com"
        })

# Run: locust -f locustfile.py --host http://localhost:8000
```

---

## Production Deployment

### Docker Deployment

**Dockerfile**:
```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/
COPY config/ ./config/
COPY rules/ ./rules/

# Non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fastapi-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fastapi-app
  template:
    metadata:
      labels:
        app: fastapi-app
    spec:
      containers:
        - name: app
          image: fastapi-app:latest
          ports:
            - containerPort: 8000
          env:
            - name: REDIS_HOST
              value: "redis-service"
            - name: ENV
              value: "production"
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 30
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            initialDelaySeconds: 10
```

### Environment Variables

```python
# app/config.py
import os
from lewaf.integration.asgi import ASGIMiddleware
from fastapi import FastAPI

def create_app():
    app = FastAPI()

    # ... your routes ...

    # Use environment-specific config
    env = os.getenv("ENV", "development")
    config_file = f"config/{env}.yaml"

    return ASGIMiddleware(
        app,
        config_file=config_file,
        enable_hot_reload=(env == "production")
    )

app = create_app()
```

### Health Checks

```python
from fastapi import FastAPI
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/ready")
def ready():
    # Check dependencies (DB, Redis, etc.)
    return {"status": "ready"}

# WAF middleware
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")

# Health checks should bypass WAF - they run on unprotected endpoints
```

---

## Troubleshooting

### Issue 1: Request Body Not Inspected

**Problem**: POST requests with body are not being checked.

**Solution**: Ensure Content-Type is set correctly.

```python
# Correct
client.post("/api/users", json={"name": "test"})  # Sets Content-Type: application/json

# Incorrect
client.post("/api/users", data={"name": "test"})  # Sets Content-Type: application/x-www-form-urlencoded
```

### Issue 2: Performance Degradation

**Problem**: LeWAF is slowing down requests significantly.

**Solutions**:
1. Use Redis storage instead of file
2. Increase regex cache size
3. Profile and optimize rules

```yaml
# config/lewaf.yaml
storage:
  backend: redis
  redis_host: localhost

performance:
  regex_cache_size: 512
```

### Issue 3: WebSocket Support

**Problem**: WebSocket connections fail through LeWAF middleware.

**Solution**: LeWAF currently supports HTTP/HTTPS only. Exclude WebSocket endpoints:

```python
from fastapi import FastAPI, WebSocket
from lewaf.integration.asgi import ASGIMiddleware

app = FastAPI()

# Regular HTTP endpoint (protected)
@app.get("/api/data")
def get_data():
    return {"data": "value"}

# WebSocket endpoint (not protected by WAF)
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    # WebSocket logic

# WAF middleware
app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### Issue 4: False Positives

**Problem**: Legitimate requests are being blocked.

**Solution**: Add exceptions or tune rules.

```
# In rules/exceptions.conf
SecRule REQUEST_URI "@rx ^/api/search" \
    "id:99001,phase:1,ctl:ruleRemoveById=1001,nolog"
```

---

## Best Practices

### 1. Configuration Management

- ✅ Use separate configs for dev/staging/prod
- ✅ Store sensitive data in environment variables
- ✅ Version control your rule files
- ✅ Test rules in DetectionOnly mode first

### 2. Performance

- ✅ Use Redis for storage in production
- ✅ Enable regex caching
- ✅ Monitor WAF performance metrics
- ✅ Optimize rules (specific variables over broad matches)

### 3. Security

- ✅ Keep LeWAF and rules up to date
- ✅ Use OWASP CRS as baseline
- ✅ Add application-specific rules
- ✅ Enable audit logging
- ✅ Mask sensitive data in logs

### 4. Monitoring

- ✅ Track blocked requests
- ✅ Monitor false positive rate
- ✅ Set up alerts for attack patterns
- ✅ Regular log review

---

## Complete Example

**File**: `app/main.py`
```python
from fastapi import FastAPI, HTTPException, Depends
from lewaf.integration.asgi import ASGIMiddleware
from pydantic import BaseModel
import os

# Models
class User(BaseModel):
    name: str
    email: str

class UserResponse(BaseModel):
    id: int
    name: str
    email: str

# Create app
app = FastAPI(
    title="Protected FastAPI App",
    description="API protected by LeWAF",
    version="1.0.0"
)

# Routes
@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/api/users", response_model=list[UserResponse])
def list_users():
    return [
        {"id": 1, "name": "Alice", "email": "alice@example.com"},
        {"id": 2, "name": "Bob", "email": "bob@example.com"},
    ]

@app.get("/api/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int):
    if user_id == 1:
        return {"id": 1, "name": "Alice", "email": "alice@example.com"}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/users", response_model=UserResponse)
def create_user(user: User):
    return {"id": 3, "name": user.name, "email": user.email}

# Apply LeWAF protection
env = os.getenv("ENV", "development")
app = ASGIMiddleware(
    app,
    config_file=f"config/{env}.yaml",
    enable_hot_reload=(env == "production")
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

---

## Related Documentation

- [Quickstart Guide](quickstart.md)
- [API Reference](../api/reference.md)
- [Custom Rules Guide](custom-rules.md)
- [Django Integration](integration-django.md)
- [Flask Integration](integration-flask.md)
- [Starlette Integration](integration-starlette.md)
- [Docker Deployment](../deployment/docker.md)
- [Kubernetes Deployment](../deployment/kubernetes.md)

---

**Last Updated**: 2025-11-13
**Version**: 1.0.0
