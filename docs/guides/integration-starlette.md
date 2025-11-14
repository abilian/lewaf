# Starlette Integration Guide

This guide covers integrating LeWAF with Starlette applications. Starlette is a lightweight ASGI framework that provides the foundation for FastAPI and other modern Python web frameworks.

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Basic Integration](#basic-integration)
4. [Configuration Options](#configuration-options)
5. [Advanced Patterns](#advanced-patterns)
6. [Testing](#testing)
7. [Production Deployment](#production-deployment)
8. [Troubleshooting](#troubleshooting)
9. [Complete Examples](#complete-examples)

---

## Introduction

### Why Starlette?

Starlette is an ideal choice for integrating LeWAF because:

- **Native ASGI**: No WSGI-to-ASGI conversion required (unlike Flask)
- **Lightweight**: Minimal overhead, maximum performance
- **Flexible**: Fine-grained control over request/response processing
- **Modern**: Built for async/await from the ground up
- **Foundation**: Powers FastAPI and other frameworks

### Integration Architecture

```
HTTP Request
    ↓
Starlette Application
    ↓
LeWAF ASGI Middleware (inspects request)
    ↓
├─ Safe Request → Your Routes → Response
└─ Attack Detected → 403 Forbidden
```

---

## Prerequisites

### Installation

```bash
# Install LeWAF
uv add lewaf

# Install Starlette
uv add starlette

# Install ASGI server (for production)
uv add uvicorn

# Optional: Testing utilities
uv add httpx pytest pytest-asyncio
```

### Verify Installation

```bash
python -c "import lewaf, starlette; print('✅ All packages installed')"
```

---

## Basic Integration

### Method 1: Inline Configuration (Quick Start)

Perfect for development and simple applications:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

# Define routes
async def homepage(request):
    return JSONResponse({"message": "Hello, World!"})

async def search(request):
    query = request.query_params.get("q", "")
    return JSONResponse({"results": [query]})

# Create Starlette app
app = Starlette(
    routes=[
        Route("/", homepage),
        Route("/search", search),
    ]
)

# Wrap with LeWAF (inline config)
config = {
    "rules": [
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny,log,msg:\'XSS Attack\'"',
        'SecRule ARGS "@rx (?i:union.*select)" "id:2,phase:2,deny,log,msg:\'SQL Injection\'"',
    ],
    "rule_files": []
}

# Apply LeWAF middleware
protected_app = ASGIMiddleware(app, config_dict=config)

# Run with Uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(protected_app, host="0.0.0.0", port=8000)
```

**Test it**:
```bash
# Safe request
curl http://localhost:8000/search?q=python
# Returns: {"results": ["python"]}

# Attack attempt
curl "http://localhost:8000/search?q=<script>alert(1)</script>"
# Returns: 403 Forbidden
```

### Method 2: Configuration File (Recommended)

Better for production with complex rule sets:

**Step 1: Create configuration file** (`config/lewaf.yaml`):

```yaml
# LeWAF Configuration for Starlette
rules:
  # XSS Protection
  - 'SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx <script" "id:100,phase:2,deny,status:403,log,msg:''XSS Attack Detected''"'

  # SQL Injection Protection
  - 'SecRule ARGS|ARGS_NAMES|REQUEST_BODY "@rx (?i:union.*select|insert.*into|delete.*from)" "id:101,phase:2,deny,status:403,log,msg:''SQL Injection Attempt''"'

  # Path Traversal Protection
  - 'SecRule REQUEST_URI "@rx \\.\\./|\\.\\.\\\\" "id:102,phase:1,deny,status:403,log,msg:''Path Traversal Attempt''"'

  # Command Injection Protection
  - 'SecRule ARGS|REQUEST_BODY "@rx [;&|`$(){}]" "id:103,phase:2,deny,status:403,log,msg:''Command Injection Attempt''"'

rule_files: []

# Logging
log:
  level: INFO
  format: json
```

**Step 2: Load in application**:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

async def homepage(request):
    return JSONResponse({"message": "Protected by LeWAF"})

async def api_search(request):
    query = request.query_params.get("q", "")
    # Your business logic here
    return JSONResponse({"query": query, "results": []})

async def api_user(request):
    user_id = request.path_params["user_id"]
    return JSONResponse({"user_id": user_id, "name": "John Doe"})

app = Starlette(
    routes=[
        Route("/", homepage),
        Route("/api/search", api_search),
        Route("/api/users/{user_id:int}", api_user),
    ]
)

# Load LeWAF from config file
protected_app = ASGIMiddleware(app, config_file="config/lewaf.yaml")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(protected_app, host="0.0.0.0", port=8000)
```

---

## Configuration Options

### Environment-Based Configuration

Use different configs per environment:

```python
import os
from starlette.applications import Starlette
from lewaf.integration.asgi import ASGIMiddleware

app = Starlette(routes=[...])

# Load environment-specific config
env = os.getenv("ENVIRONMENT", "development")
config_file = f"config/lewaf.{env}.yaml"

protected_app = ASGIMiddleware(app, config_file=config_file)
```

**Directory structure**:
```
config/
├── lewaf.development.yaml   # Lenient rules, verbose logging
├── lewaf.staging.yaml        # Moderate rules, moderate logging
└── lewaf.production.yaml     # Strict rules, minimal logging
```

### Dynamic Configuration

Update rules at runtime (advanced):

```python
from starlette.applications import Starlette
from lewaf.integration.asgi import ASGIMiddleware

app = Starlette(routes=[...])

# Initial config
config = {"rules": [], "rule_files": []}
protected_app = ASGIMiddleware(app, config_dict=config)

# Access WAF instance
waf_instance = protected_app.waf

# Add rules dynamically (be cautious in production)
def add_custom_rule(rule_string):
    waf_instance.parser.from_string(rule_string)

# Example: Add rule based on threat intelligence
add_custom_rule('SecRule REQUEST_HEADERS:User-Agent "@rx BadBot" "id:999,phase:1,deny"')
```

---

## Advanced Patterns

### Pattern 1: Custom Error Responses

Customize the blocked request response:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

class CustomWAFMiddleware(ASGIMiddleware):
    """Custom WAF middleware with branded error responses"""

    async def send_blocked_response(self):
        """Send custom JSON response for blocked requests"""
        response = JSONResponse(
            {
                "error": "Request Blocked",
                "message": "Your request was blocked by our security system",
                "incident_id": self.transaction.id,
                "support": "contact@example.com"
            },
            status_code=403,
            headers={
                "X-WAF-Block-Reason": "Security Policy Violation",
                "X-Incident-ID": self.transaction.id
            }
        )

        await response(self.scope, self.receive, self.send)

async def homepage(request):
    return JSONResponse({"status": "ok"})

app = Starlette(routes=[Route("/", homepage)])

# Use custom middleware
protected_app = CustomWAFMiddleware(app, config_file="config/lewaf.yaml")
```

### Pattern 2: Route-Specific Protection

Apply different rules to different routes:

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount
from lewaf.integration.asgi import ASGIMiddleware

# Public API - lenient rules
public_config = {
    "rules": [
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',
    ],
    "rule_files": []
}

# Admin API - strict rules
admin_config = {
    "rules": [
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',
        'SecRule ARGS "@rx [;&|`$()]" "id:2,phase:2,deny"',
        'SecRule REQUEST_METHOD "@rx ^(GET|POST)$" "id:3,phase:1,deny"',
    ],
    "rule_files": []
}

# Public routes
async def public_search(request):
    return JSONResponse({"results": []})

public_app = Starlette(routes=[Route("/search", public_search)])
protected_public = ASGIMiddleware(public_app, config_dict=public_config)

# Admin routes
async def admin_users(request):
    return JSONResponse({"users": []})

admin_app = Starlette(routes=[Route("/users", admin_users)])
protected_admin = ASGIMiddleware(admin_app, config_dict=admin_config)

# Main app with mounted sub-apps
app = Starlette(routes=[
    Mount("/api", protected_public),
    Mount("/admin", protected_admin),
])
```

### Pattern 3: Middleware Stack

Combine LeWAF with other middleware:

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

async def homepage(request):
    return JSONResponse({"message": "Hello"})

# Define middleware stack
middleware = [
    # TrustedHost first (reject untrusted hosts early)
    Middleware(
        TrustedHostMiddleware,
        allowed_hosts=["example.com", "*.example.com"]
    ),
    # CORS second (handle OPTIONS requests)
    Middleware(
        CORSMiddleware,
        allow_origins=["https://example.com"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    ),
    # GZip last (compress responses)
    Middleware(GZipMiddleware, minimum_size=1000),
]

# Create app with middleware
app = Starlette(
    routes=[Route("/", homepage)],
    middleware=middleware
)

# LeWAF wraps everything
protected_app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

**Middleware execution order**:
```
Request → LeWAF → TrustedHost → CORS → GZip → Your Routes
```

### Pattern 4: Request Context and Logging

Access WAF transaction details in your routes:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.middleware.base import BaseHTTPMiddleware
from lewaf.integration.asgi import ASGIMiddleware
import logging

logger = logging.getLogger(__name__)

class WAFLoggingMiddleware(BaseHTTPMiddleware):
    """Log WAF transaction details"""

    async def dispatch(self, request, call_next):
        # Access WAF transaction from request state
        waf_tx = getattr(request.state, "waf_transaction", None)

        if waf_tx:
            logger.info(f"WAF Transaction: {waf_tx.id}")

        response = await call_next(request)

        if waf_tx and waf_tx.interruption:
            logger.warning(f"Request blocked: {waf_tx.interruption}")

        return response

async def homepage(request):
    # Access WAF context in route
    waf_tx = getattr(request.state, "waf_transaction", None)

    return JSONResponse({
        "message": "Hello",
        "waf_transaction_id": waf_tx.id if waf_tx else None
    })

app = Starlette(routes=[Route("/", homepage)])
app.add_middleware(WAFLoggingMiddleware)

protected_app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### Pattern 5: File Upload Protection

Protect file upload endpoints:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware
import magic  # python-magic library

async def upload_file(request):
    """Protected file upload endpoint"""
    form = await request.form()
    uploaded_file = form.get("file")

    if not uploaded_file:
        return JSONResponse({"error": "No file provided"}, status_code=400)

    # Additional validation (beyond WAF)
    content = await uploaded_file.read()

    # Check file type
    mime_type = magic.from_buffer(content, mime=True)
    allowed_types = ["image/jpeg", "image/png", "image/gif"]

    if mime_type not in allowed_types:
        return JSONResponse(
            {"error": f"File type {mime_type} not allowed"},
            status_code=400
        )

    # Check file size (10MB limit)
    if len(content) > 10 * 1024 * 1024:
        return JSONResponse(
            {"error": "File too large (max 10MB)"},
            status_code=400
        )

    # Process file...
    return JSONResponse({
        "message": "File uploaded successfully",
        "filename": uploaded_file.filename,
        "size": len(content),
        "type": mime_type
    })

app = Starlette(routes=[Route("/upload", upload_file, methods=["POST"])])

# WAF config with file upload rules
config = {
    "rules": [
        # Limit upload size
        'SecRule FILES_SIZES "@gt 10485760" "id:1,phase:2,deny,msg:\'File too large\'"',

        # Block dangerous extensions
        'SecRule FILES_NAMES "@rx \\.(php|exe|sh|bat)$" "id:2,phase:2,deny,msg:\'Dangerous file type\'"',

        # Block PHP in file content
        'SecRule FILES "@rx <?php" "id:3,phase:2,deny,msg:\'PHP code in upload\'"',
    ],
    "rule_files": []
}

protected_app = ASGIMiddleware(app, config_dict=config)
```

### Pattern 6: GraphQL Protection

Protect GraphQL endpoints:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware
import json

async def graphql(request):
    """GraphQL endpoint with WAF protection"""
    body = await request.body()

    try:
        data = json.loads(body)
        query = data.get("query", "")
        variables = data.get("variables", {})

        # Your GraphQL execution logic here
        result = {"data": {"message": "Query executed"}}

        return JSONResponse(result)

    except json.JSONDecodeError:
        return JSONResponse(
            {"error": "Invalid JSON"},
            status_code=400
        )

app = Starlette(routes=[Route("/graphql", graphql, methods=["POST"])])

# GraphQL-specific WAF rules
config = {
    "rules": [
        # Limit query depth (prevent nested query attacks)
        'SecRule REQUEST_BODY "@rx \\{.*\\{.*\\{.*\\{.*\\{" "id:1,phase:2,deny,msg:\'Query too deep\'"',

        # Limit query length
        'SecRule REQUEST_BODY "@gt 10000" "id:2,phase:2,deny,msg:\'Query too long\'"',

        # Block introspection in production
        'SecRule REQUEST_BODY "@rx __schema|__type" "id:3,phase:2,deny,msg:\'Introspection blocked\'"',

        # Block dangerous fields
        'SecRule REQUEST_BODY "@rx (?i:password|secret|token)" "id:4,phase:2,deny,msg:\'Sensitive field access\'"',
    ],
    "rule_files": []
}

protected_app = ASGIMiddleware(app, config_dict=config)
```

### Pattern 7: WebSocket Protection

Protect WebSocket connections:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket
from lewaf.integration.asgi import ASGIMiddleware

async def homepage(request):
    return JSONResponse({"message": "WebSocket server"})

async def websocket_endpoint(websocket: WebSocket):
    """Protected WebSocket endpoint"""
    await websocket.accept()

    try:
        while True:
            # Receive message
            data = await websocket.receive_text()

            # Validate message (additional protection)
            if len(data) > 1000:
                await websocket.send_text(json.dumps({
                    "error": "Message too long"
                }))
                await websocket.close(code=1008)  # Policy violation
                break

            # Check for malicious patterns
            if "<script>" in data.lower() or "javascript:" in data.lower():
                await websocket.send_text(json.dumps({
                    "error": "Invalid message content"
                }))
                await websocket.close(code=1008)
                break

            # Echo message back
            await websocket.send_text(f"Echo: {data}")

    except Exception as e:
        await websocket.close(code=1011)  # Internal error

app = Starlette(
    routes=[
        Route("/", homepage),
        WebSocketRoute("/ws", websocket_endpoint),
    ]
)

# WAF config for WebSocket
config = {
    "rules": [
        # Standard HTTP rules still apply to upgrade request
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',

        # Block suspicious user agents
        'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler)" "id:2,phase:1,deny"',
    ],
    "rule_files": []
}

protected_app = ASGIMiddleware(app, config_dict=config)
```

**Note**: LeWAF inspects the initial HTTP upgrade request but not the WebSocket frames. You must validate WebSocket messages in your endpoint logic.

---

## Testing

### Testing with Starlette TestClient

**Basic test**:

```python
# tests/test_app.py
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from lewaf.integration.asgi import ASGIMiddleware

async def search(request):
    query = request.query_params.get("q", "")
    return JSONResponse({"query": query})

app = Starlette(routes=[Route("/search", search)])

config = {
    "rules": [
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',
    ],
    "rule_files": []
}

protected_app = ASGIMiddleware(app, config_dict=config)

def test_safe_request():
    """Test that safe requests pass through"""
    client = TestClient(protected_app)
    response = client.get("/search?q=python")

    assert response.status_code == 200
    assert response.json() == {"query": "python"}

def test_blocked_request():
    """Test that attacks are blocked"""
    client = TestClient(protected_app)
    response = client.get("/search?q=<script>alert(1)</script>")

    assert response.status_code == 403
```

### Async Testing with HTTPX

For more realistic async testing:

```python
# tests/test_app_async.py
import pytest
from httpx import AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

async def api_user(request):
    user_id = request.path_params["user_id"]
    return JSONResponse({"user_id": user_id})

app = Starlette(routes=[Route("/api/users/{user_id:int}", api_user)])

config = {
    "rules": [
        'SecRule REQUEST_URI "@rx \\.\\." "id:1,phase:1,deny"',
    ],
    "rule_files": []
}

protected_app = ASGIMiddleware(app, config_dict=config)

@pytest.mark.asyncio
async def test_safe_user_request():
    """Test valid user ID request"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/api/users/123")

        assert response.status_code == 200
        assert response.json() == {"user_id": 123}

@pytest.mark.asyncio
async def test_path_traversal_blocked():
    """Test path traversal attempt is blocked"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/api/users/../admin")

        assert response.status_code == 403
```

### Testing Custom Middleware

```python
# tests/test_custom_middleware.py
import pytest
from httpx import AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

class CustomWAFMiddleware(ASGIMiddleware):
    async def send_blocked_response(self):
        response = JSONResponse(
            {"error": "Custom block message"},
            status_code=403
        )
        await response(self.scope, self.receive, self.send)

async def homepage(request):
    return JSONResponse({"status": "ok"})

app = Starlette(routes=[Route("/", homepage)])

config = {
    "rules": [
        'SecRule ARGS "@rx attack" "id:1,phase:2,deny"',
    ],
    "rule_files": []
}

protected_app = CustomWAFMiddleware(app, config_dict=config)

@pytest.mark.asyncio
async def test_custom_error_response():
    """Test custom error response is used"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/?q=attack")

        assert response.status_code == 403
        assert response.json() == {"error": "Custom block message"}
```

### Integration Testing

Test the complete application flow:

```python
# tests/test_integration.py
import pytest
from httpx import AsyncClient
from your_app import app, protected_app  # Your actual app

@pytest.mark.asyncio
async def test_complete_user_flow():
    """Test complete user workflow with WAF protection"""
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        # Step 1: Homepage loads
        response = await client.get("/")
        assert response.status_code == 200

        # Step 2: Search works with safe query
        response = await client.get("/api/search?q=python")
        assert response.status_code == 200
        results = response.json()
        assert "results" in results

        # Step 3: Attack is blocked
        response = await client.get("/api/search?q=<script>alert(1)</script>")
        assert response.status_code == 403

        # Step 4: Login still works
        response = await client.post(
            "/api/login",
            json={"username": "user", "password": "pass"}
        )
        assert response.status_code in [200, 401]  # Either success or auth failure, not WAF block

@pytest.mark.asyncio
async def test_performance_under_load():
    """Test app performance with WAF enabled"""
    import time

    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        start = time.time()

        # Make 100 requests
        for i in range(100):
            response = await client.get(f"/api/search?q=query{i}")
            assert response.status_code == 200

        duration = time.time() - start

        # Should complete 100 requests in under 5 seconds
        assert duration < 5.0
        print(f"100 requests completed in {duration:.2f}s ({100/duration:.1f} req/s)")
```

---

## Production Deployment

### Option 1: Uvicorn (Simple)

**Single worker**:
```bash
uvicorn app:protected_app --host 0.0.0.0 --port 8000
```

**Multiple workers** (use Gunicorn for proper worker management):
```bash
gunicorn app:protected_app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile - \
  --error-logfile -
```

### Option 2: Docker

**Dockerfile**:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen

# Copy application
COPY . .

# Expose port
EXPOSE 8000

# Run with Gunicorn + Uvicorn workers
CMD ["uv", "run", "gunicorn", "app:protected_app", \
     "--workers", "4", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000"]
```

**Build and run**:
```bash
docker build -t myapp:latest .
docker run -p 8000:8000 -e ENVIRONMENT=production myapp:latest
```

### Option 3: Kubernetes

**deployment.yaml**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: starlette-waf-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: starlette-waf
  template:
    metadata:
      labels:
        app: starlette-waf
    spec:
      containers:
      - name: app
        image: myapp:latest
        ports:
        - containerPort: 8000
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: WORKERS
          value: "4"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: starlette-waf-service
spec:
  selector:
    app: starlette-waf
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

**Add health check endpoints**:

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware

async def health(request):
    """Liveness probe - is app running?"""
    return JSONResponse({"status": "healthy"})

async def ready(request):
    """Readiness probe - is app ready for traffic?"""
    # Check database, cache, etc.
    return JSONResponse({"status": "ready"})

async def homepage(request):
    return JSONResponse({"message": "Hello"})

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/ready", ready),
        Route("/", homepage),
    ]
)

protected_app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
```

### Option 4: Systemd Service

For traditional Linux servers:

**/etc/systemd/system/starlette-waf.service**:

```ini
[Unit]
Description=Starlette WAF Application
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/myapp
Environment="PATH=/opt/myapp/.venv/bin"
ExecStart=/opt/myapp/.venv/bin/gunicorn app:protected_app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --access-logfile /var/log/starlette-waf/access.log \
    --error-logfile /var/log/starlette-waf/error.log
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start**:
```bash
sudo systemctl enable starlette-waf
sudo systemctl start starlette-waf
sudo systemctl status starlette-waf
```

### Option 5: Nginx Reverse Proxy

**nginx.conf**:

```nginx
upstream starlette_backend {
    server 127.0.0.1:8000;
    server 127.0.0.1:8001;
    server 127.0.0.1:8002;
}

server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://starlette_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Static files (bypass WAF for better performance)
    location /static/ {
        alias /opt/myapp/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

---

## Troubleshooting

### Issue 1: AttributeError: 'Request' object has no attribute 'state'

**Symptom**:
```python
AttributeError: 'Request' object has no attribute 'state'
```

**Cause**: Starlette version mismatch or middleware ordering issue.

**Solution**: Ensure Starlette >= 0.28.0 and check middleware order:
```bash
uv add starlette>=0.28.0
```

### Issue 2: WebSocket Connections Blocked

**Symptom**: WebSocket upgrade requests return 403 Forbidden.

**Cause**: WAF rules blocking WebSocket upgrade request headers.

**Solution**: Add exception for WebSocket connections:
```yaml
rules:
  # Allow WebSocket upgrade requests
  - 'SecRule REQUEST_HEADERS:Upgrade "@rx ^websocket$" "id:1000,phase:1,pass,nolog"'

  # Your other rules...
  - 'SecRule ARGS "@rx <script" "id:1001,phase:2,deny"'
```

### Issue 3: High Memory Usage

**Symptom**: Application memory grows over time.

**Cause**: Possibly related to transaction caching or rule compilation.

**Solution**:
```python
# Limit transaction history
config = {
    "rules": [...],
    "rule_files": [],
    "max_transaction_history": 100  # Limit stored transactions
}
```

### Issue 4: Slow Response Times

**Symptom**: Requests take significantly longer with WAF enabled.

**Diagnosis**:
```python
import time
from starlette.middleware.base import BaseHTTPMiddleware

class TimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        response.headers["X-Response-Time"] = f"{duration:.4f}s"
        print(f"{request.method} {request.url.path} - {duration:.4f}s")

        return response

app.add_middleware(TimingMiddleware)
```

**Solutions**:
- Optimize regex patterns in rules (avoid backtracking)
- Reduce number of rules
- Use more specific rule targeting (don't inspect everything)
- Consider caching rule compilation results

### Issue 5: CORS Preflight Requests Blocked

**Symptom**: OPTIONS requests return 403.

**Cause**: WAF blocking preflight requests.

**Solution**: Ensure CORS middleware runs before WAF or add exception:
```yaml
rules:
  # Allow OPTIONS requests (CORS preflight)
  - 'SecRule REQUEST_METHOD "@streq OPTIONS" "id:999,phase:1,pass,nolog"'
```

### Issue 6: File Upload Timeouts

**Symptom**: Large file uploads timeout or fail.

**Cause**: Request body inspection on large files.

**Solution**:
```yaml
rules:
  # Skip body inspection for file uploads
  - 'SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart/form-data" "id:998,phase:1,pass,ctl:requestBodyAccess=Off"'
```

---

## Complete Examples

### Example 1: REST API with Database

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from lewaf.integration.asgi import ASGIMiddleware
import databases
import sqlalchemy

# Database setup
DATABASE_URL = "postgresql://user:password@localhost/dbname"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String),
    sqlalchemy.Column("email", sqlalchemy.String),
)

# Routes
async def list_users(request):
    """List all users"""
    query = users.select()
    results = await database.fetch_all(query)
    return JSONResponse([dict(r) for r in results])

async def get_user(request):
    """Get single user by ID"""
    user_id = request.path_params["user_id"]
    query = users.select().where(users.c.id == user_id)
    result = await database.fetch_one(query)

    if result is None:
        return JSONResponse({"error": "User not found"}, status_code=404)

    return JSONResponse(dict(result))

async def create_user(request):
    """Create new user"""
    data = await request.json()

    # Validate input
    if not data.get("username") or not data.get("email"):
        return JSONResponse(
            {"error": "username and email required"},
            status_code=400
        )

    query = users.insert().values(
        username=data["username"],
        email=data["email"]
    )
    user_id = await database.execute(query)

    return JSONResponse(
        {"id": user_id, "username": data["username"], "email": data["email"]},
        status_code=201
    )

# Startup/shutdown
async def startup():
    await database.connect()

async def shutdown():
    await database.disconnect()

# Create app
app = Starlette(
    routes=[
        Route("/users", list_users, methods=["GET"]),
        Route("/users", create_user, methods=["POST"]),
        Route("/users/{user_id:int}", get_user, methods=["GET"]),
    ],
    on_startup=[startup],
    on_shutdown=[shutdown],
)

# WAF configuration
config = {
    "rules": [
        # SQL Injection protection
        'SecRule ARGS|REQUEST_BODY "@rx (?i:union.*select|insert.*into|delete.*from|drop.*table)" '
        '"id:1,phase:2,deny,status:403,log,msg:\'SQL Injection\'"',

        # XSS protection
        'SecRule ARGS|REQUEST_BODY "@rx <script|javascript:|onerror=" '
        '"id:2,phase:2,deny,status:403,log,msg:\'XSS Attack\'"',

        # Email validation
        'SecRule ARGS:email "!@rx ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$" '
        '"id:3,phase:2,deny,status:400,log,msg:\'Invalid email format\'"',
    ],
    "rule_files": []
}

protected_app = ASGIMiddleware(app, config_dict=config)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(protected_app, host="0.0.0.0", port=8000)
```

### Example 2: Multi-Tenant SaaS Application

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.middleware.base import BaseHTTPMiddleware
from lewaf.integration.asgi import ASGIMiddleware
import jwt

SECRET_KEY = "your-secret-key"

# Tenant identification middleware
class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Extract tenant from subdomain or header
        host = request.headers.get("host", "")
        subdomain = host.split(".")[0]

        # Store tenant in request state
        request.state.tenant_id = subdomain

        response = await call_next(request)
        return response

# Authentication middleware
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Public endpoints
        if request.url.path in ["/login", "/health"]:
            return await call_next(request)

        # Check JWT token
        token = request.headers.get("Authorization", "").replace("Bearer ", "")

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.state.user_id = payload["user_id"]
        except jwt.InvalidTokenError:
            return JSONResponse(
                {"error": "Invalid or missing token"},
                status_code=401
            )

        response = await call_next(request)
        return response

# Routes
async def health(request):
    return JSONResponse({"status": "healthy"})

async def login(request):
    data = await request.json()

    # Validate credentials (simplified)
    if data.get("username") == "admin" and data.get("password") == "secret":
        token = jwt.encode(
            {"user_id": 1, "username": "admin"},
            SECRET_KEY,
            algorithm="HS256"
        )
        return JSONResponse({"token": token})

    return JSONResponse({"error": "Invalid credentials"}, status_code=401)

async def tenant_data(request):
    """Get tenant-specific data"""
    tenant_id = request.state.tenant_id
    user_id = request.state.user_id

    return JSONResponse({
        "tenant": tenant_id,
        "user": user_id,
        "data": f"Data for tenant {tenant_id}"
    })

# Create app
app = Starlette(
    routes=[
        Route("/health", health),
        Route("/login", login, methods=["POST"]),
        Route("/api/data", tenant_data),
    ]
)

# Add middleware
app.add_middleware(TenantMiddleware)
app.add_middleware(AuthMiddleware)

# Tenant-specific WAF configs
def get_tenant_config(tenant_id):
    """Load tenant-specific WAF configuration"""
    # In production, load from database
    configs = {
        "tenant1": {
            "rules": [
                'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',
            ],
            "rule_files": []
        },
        "tenant2": {
            "rules": [
                'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',
                'SecRule REQUEST_URI "@rx admin" "id:2,phase:1,deny"',
            ],
            "rule_files": []
        },
    }
    return configs.get(tenant_id, configs["tenant1"])

# Custom WAF middleware with tenant awareness
class TenantAwareWAFMiddleware(ASGIMiddleware):
    async def __call__(self, scope, receive, send):
        # Extract tenant from host header
        headers = dict(scope.get("headers", []))
        host = headers.get(b"host", b"").decode()
        tenant_id = host.split(".")[0]

        # Load tenant-specific config
        config = get_tenant_config(tenant_id)

        # Update WAF config
        self.config = config

        # Call parent
        await super().__call__(scope, receive, send)

protected_app = TenantAwareWAFMiddleware(app, config_dict={"rules": [], "rule_files": []})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(protected_app, host="0.0.0.0", port=8000)
```

### Example 3: API Gateway with Rate Limiting

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route, Mount
from starlette.middleware.base import BaseHTTPMiddleware
from lewaf.integration.asgi import ASGIMiddleware
import time
from collections import defaultdict

# Simple rate limiter
class RateLimiter:
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(list)

    def is_allowed(self, client_id):
        now = time.time()
        window_start = now - self.window_seconds

        # Remove old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > window_start
        ]

        # Check limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False

        # Record request
        self.requests[client_id].append(now)
        return True

rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Use IP address as client ID
        client_ip = request.client.host

        if not rate_limiter.is_allowed(client_ip):
            return JSONResponse(
                {"error": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": "60"}
            )

        response = await call_next(request)
        return response

# Microservice 1: Users
async def users_list(request):
    return JSONResponse({"users": ["alice", "bob"]})

users_app = Starlette(routes=[Route("/", users_list)])

# Microservice 2: Products
async def products_list(request):
    return JSONResponse({"products": ["laptop", "phone"]})

products_app = Starlette(routes=[Route("/", products_list)])

# Gateway
async def gateway_health(request):
    return JSONResponse({"status": "ok"})

gateway = Starlette(
    routes=[
        Route("/health", gateway_health),
        Mount("/api/users", users_app),
        Mount("/api/products", products_app),
    ]
)

# Add rate limiting
gateway.add_middleware(RateLimitMiddleware)

# WAF protection
config = {
    "rules": [
        # Standard protections
        'SecRule ARGS "@rx <script" "id:1,phase:2,deny"',
        'SecRule REQUEST_URI "@rx \\.\\." "id:2,phase:1,deny"',

        # API-specific rules
        'SecRule REQUEST_METHOD "!@rx ^(GET|POST|PUT|DELETE|OPTIONS)$" "id:3,phase:1,deny"',

        # Block suspicious user agents
        'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler|scanner)" "id:4,phase:1,deny"',
    ],
    "rule_files": []
}

protected_gateway = ASGIMiddleware(gateway, config_dict=config)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(protected_gateway, host="0.0.0.0", port=8000)
```

---

## Best Practices

### 1. Configuration Management

- **Use config files** for production, inline configs for development
- **Version control** your WAF rules alongside application code
- **Environment-specific rules**: Stricter in production, lenient in development
- **Document custom rules**: Explain why each rule exists

### 2. Performance Optimization

- **Target rules carefully**: Only inspect what's necessary
- **Optimize regex**: Avoid backtracking, use non-capturing groups
- **Cache where possible**: Rule compilation is cached automatically
- **Monitor overhead**: Use timing middleware to measure impact

### 3. Security Hygiene

- **Defense in depth**: WAF is one layer, not the only layer
- **Input validation**: Still validate in application logic
- **Update rules regularly**: Keep up with new attack patterns
- **Log and monitor**: Review blocked requests for false positives

### 4. Testing Strategy

- **Unit tests**: Test individual rules and WAF integration
- **Integration tests**: Test complete request flows
- **Load tests**: Ensure WAF doesn't create bottlenecks
- **Security tests**: Use tools like OWASP ZAP to validate protections

### 5. Deployment

- **Gradual rollout**: Test in staging before production
- **Monitor metrics**: Track block rates, false positives, latency
- **Have rollback plan**: Can quickly disable WAF if needed
- **Document incidents**: Learn from blocked attacks

---

## Next Steps

- **[Custom Rules Guide](./custom-rules.md)** - Learn to write advanced WAF rules
- **[Django Integration](./integration-django.md)** - Django integration examples
- **[FastAPI Integration](./integration-fastapi.md)** - FastAPI integration examples
- **[Flask Integration](./integration-flask.md)** - Flask integration examples
- **[API Reference](./api-reference.md)** - Complete API documentation
- **[Troubleshooting Guide](./troubleshooting.md)** - Common issues and solutions
- **[Performance Tuning](./performance.md)** - Optimize WAF performance

---

## Additional Resources

- **Starlette Documentation**: https://www.starlette.io/
- **OWASP ModSecurity Core Rule Set**: https://coreruleset.org/
- **LeWAF GitHub**: https://github.com/yourusername/lewaf
- **Security Best Practices**: https://owasp.org/www-project-web-security-testing-guide/

---

**Questions or Issues?** File an issue on GitHub or reach out to the community.
