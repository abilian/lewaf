# LeWAF Flask Integration Guide

Complete guide for integrating LeWAF with Flask applications.

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
pip install lewaf flask asgiref
```

**Note**: LeWAF is an ASGI middleware, so Flask (WSGI) needs `asgiref` to bridge WSGI→ASGI.

### Minimal Example

```python
from flask import Flask, request, jsonify
from lewaf.integration.asgi import ASGIMiddleware
from asgiref.wsgi import WsgiToAsgi

app = Flask(__name__)

@app.route('/')
def index():
    return jsonify({"message": "Hello World"})

@app.route('/api/search')
def search():
    query = request.args.get('q', '')
    return jsonify({"results": [query]})

# Convert Flask (WSGI) to ASGI
asgi_app = WsgiToAsgi(app)

# Wrap with LeWAF middleware
protected_app = ASGIMiddleware(
    asgi_app,
    config_dict={
        "rules": ['SecRule ARGS "@rx <script" "id:1,phase:2,deny"'],
        "rule_files": []
    }
)

# Run with uvicorn (ASGI server)
# uvicorn main:protected_app --reload
```

**Test**:
```bash
# Safe request
curl http://localhost:8000/api/search?q=test
# ✅ {"results": ["test"]}

# Attack attempt
curl "http://localhost:8000/api/search?q=<script>alert(1)</script>"
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

**File**: `app.py`
```python
from flask import Flask
from lewaf.integration.asgi import ASGIMiddleware
from asgiref.wsgi import WsgiToAsgi

app = Flask(__name__)

# Your Flask routes
@app.route('/api/users')
def get_users():
    return {"users": [{"id": 1, "name": "Alice"}]}

@app.route('/api/users', methods=['POST'])
def create_user():
    from flask import request
    data = request.get_json()
    return {"id": 2, "name": data.get("name")}

# Convert to ASGI
asgi_app = WsgiToAsgi(app)

# Protect with LeWAF
protected_app = ASGIMiddleware(asgi_app, config_file="config/lewaf.yaml")

if __name__ == '__main__':
    # Development: Use Flask dev server (no WAF)
    # app.run(debug=True)

    # Production: Use uvicorn with WAF
    import uvicorn
    uvicorn.run(protected_app, host="0.0.0.0", port=8000)
```

### Method 2: Inline Configuration

```python
from flask import Flask
from lewaf.integration.asgi import ASGIMiddleware
from asgiref.wsgi import WsgiToAsgi

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    return {"data": "value"}

asgi_app = WsgiToAsgi(app)

# Configure inline
protected_app = ASGIMiddleware(
    asgi_app,
    config_dict={
        "rules": [
            'SecRule ARGS "@rx (?i)<script" "id:1,deny,msg:\'XSS\'"',
            'SecRule ARGS "@rx (?i)(union|select)" "id:2,deny,msg:\'SQLi\'"',
        ],
        "rule_files": []
    }
)
```

### Method 3: Application Factory Pattern

```python
# app/__init__.py
from flask import Flask
from lewaf.integration.asgi import ASGIMiddleware
from asgiref.wsgi import WsgiToAsgi

def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(f'config.{config_name}Config')

    # Register blueprints
    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    return app

def create_protected_app(config_name='development'):
    """Create Flask app with WAF protection"""
    flask_app = create_app(config_name)
    asgi_app = WsgiToAsgi(flask_app)

    return ASGIMiddleware(
        asgi_app,
        config_file=f"config/{config_name}.yaml"
    )

# main.py
from app import create_protected_app

app = create_protected_app('production')

# Run: uvicorn main:app
```

---

## Configuration

### Full Configuration Example

**File**: `config/lewaf-flask.yaml`
```yaml
engine: On

request_limits:
  body_limit: 10485760  # 10 MB
  header_limit: 8192
  request_line_limit: 8192

storage:
  backend: redis
  redis_host: ${REDIS_HOST:-localhost}
  redis_port: ${REDIS_PORT:-6379}
  redis_db: 0
  ttl: 3600

audit_logging:
  enabled: true
  format: json
  output: /var/log/lewaf/flask-audit.log
  level: INFO
  mask_sensitive: true
  additional_fields:
    app: flask-api
    environment: ${ENV:-development}

rule_files:
  - "rules/flask-custom.conf"
  - "rules/crs-setup.conf"
  - "rules/REQUEST-*.conf"
```

### Custom Flask Rules

**File**: `rules/flask-custom.conf`
```
# Flask-specific WAF Rules

SecRuleEngine On

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# === Flask-Specific Rules ===

# Require JSON Content-Type for API endpoints
SecRule REQUEST_URI "@rx ^/api/" \
    "id:20001,phase:1,chain,t:lowercase"
    SecRule REQUEST_METHOD "@rx ^(POST|PUT|PATCH)$" \
        "chain"
        SecRule REQUEST_HEADERS:Content-Type "!@rx ^application/json" \
            "deny,status:415,msg:'API requires application/json'"

# Validate Flask session cookies
SecRule REQUEST_COOKIES:session "@rx ^[A-Za-z0-9+/=]{40,}$" \
    "id:20002,phase:1,pass,msg:'Valid Flask session cookie'"

# Block access to Flask debug endpoints in production
SecRule REQUEST_URI "@rx ^/_debug" \
    "id:20003,phase:1,deny,status:404,msg:'Debug endpoint blocked'"

# Rate limiting per IP
SecAction "id:20004,phase:1,nolog,initcol:IP=%{REMOTE_ADDR}"

SecAction "id:20005,phase:1,nolog,setvar:IP.requests=+1"

SecRule IP:requests "@gt 100" \
    "id:20006,phase:1,deny,status:429,msg:'Rate limit exceeded'"

# Block SQL injection in Flask query params
SecRule ARGS "@detectSQLi" \
    "id:20007,phase:2,deny,status:403,msg:'SQL injection detected'"

# Block XSS in form data
SecRule ARGS "@detectXSS" \
    "id:20008,phase:2,deny,status:403,msg:'XSS detected'"

# Validate email format
SecRule ARGS:email "!@rx ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}$" \
    "id:20009,phase:2,deny,status:400,msg:'Invalid email format'"
```

---

## Advanced Patterns

### 1. Blueprint-Level Protection

```python
from flask import Flask, Blueprint
from lewaf.integration.asgi import ASGIMiddleware
from asgiref.wsgi import WsgiToAsgi

app = Flask(__name__)

# Public blueprint (no extra protection)
public_bp = Blueprint('public', __name__)

@public_bp.route('/status')
def status():
    return {"status": "ok"}

app.register_blueprint(public_bp, url_prefix='/public')

# Admin blueprint (needs authentication)
admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users')
def admin_users():
    return {"users": []}

app.register_blueprint(admin_bp, url_prefix='/admin')

# Convert and protect
asgi_app = WsgiToAsgi(app)
protected_app = ASGIMiddleware(asgi_app, config_file="config/lewaf.yaml")
```

### 2. Custom Error Handlers

```python
from flask import Flask, jsonify
from asgiref.wsgi import WsgiToAsgi
from lewaf.integration.asgi import ASGIMiddleware

app = Flask(__name__)

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        "error": "Forbidden",
        "message": "Request blocked by WAF",
        "code": 403
    }), 403

@app.errorhandler(429)
def rate_limit(error):
    return jsonify({
        "error": "Too Many Requests",
        "message": "Rate limit exceeded",
        "retry_after": 3600
    }), 429

@app.route('/api/data')
def get_data():
    return {"data": "value"}

asgi_app = WsgiToAsgi(app)
protected_app = ASGIMiddleware(asgi_app, config_file="config/lewaf.yaml")
```

### 3. Request/Response Logging

```python
from flask import Flask, request, g
import time
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

@app.before_request
def before_request():
    g.start_time = time.time()

@app.after_request
def after_request(response):
    if hasattr(g, 'start_time'):
        elapsed = time.time() - g.start_time
        app.logger.info(
            f"{request.method} {request.path} - "
            f"Status: {response.status_code} - "
            f"Time: {elapsed:.3f}s"
        )
    return response

@app.route('/api/users')
def get_users():
    return {"users": []}

# ... WAF protection as before
```

### 4. Session Management

```python
from flask import Flask, session, request
from asgiref.wsgi import WsgiToAsgi
from lewaf.integration.asgi import ASGIMiddleware

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Use environment variable in production

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    # Validate credentials
    if data.get('username') == 'admin':
        session['user_id'] = 1
        session['username'] = data['username']
        return {"success": True}
    return {"success": False}, 401

@app.route('/api/protected')
def protected():
    if 'user_id' not in session:
        return {"error": "Unauthorized"}, 401
    return {"data": "sensitive"}

asgi_app = WsgiToAsgi(app)
protected_app = ASGIMiddleware(asgi_app, config_file="config/lewaf.yaml")
```

### 5. Database Integration

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from asgiref.wsgi import WsgiToAsgi
from lewaf.integration.asgi import ASGIMiddleware

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

@app.route('/api/users')
def get_users():
    users = User.query.all()
    return {
        "users": [{"id": u.id, "name": u.name, "email": u.email} for u in users]
    }

@app.route('/api/users', methods=['POST'])
def create_user():
    data = request.get_json()
    user = User(name=data['name'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return {"id": user.id, "name": user.name}

# Protect with WAF
asgi_app = WsgiToAsgi(app)
protected_app = ASGIMiddleware(asgi_app, config_file="config/lewaf.yaml")
```

### 6. File Upload Protection

```python
from flask import Flask, request
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {"error": "No file part"}, 400

    file = request.files['file']
    if file.filename == '':
        return {"error": "No selected file"}, 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return {"success": True, "filename": filename}

    return {"error": "Invalid file type"}, 400

# WAF rules in config should include file upload protection:
# SecRule FILES "@rx \\.(exe|dll|bat)$" "deny,msg:'Dangerous file type'"
```

---

## Testing

### Unit Tests

```python
import pytest
from flask import Flask
from asgiref.wsgi import WsgiToAsgi
from lewaf.integration.asgi import ASGIMiddleware
from httpx import AsyncClient

def create_app():
    app = Flask(__name__)

    @app.route('/api/search')
    def search():
        from flask import request
        q = request.args.get('q', '')
        return {"results": [q]}

    asgi_app = WsgiToAsgi(app)
    return ASGIMiddleware(asgi_app, config_dict={
        "rules": ['SecRule ARGS:q "@rx <script" "id:1,phase:2,deny"'],
        "rule_files": []
    })

@pytest.mark.asyncio
async def test_blocks_xss():
    app = create_app()

    async with AsyncClient(app=app, base_url="http://test") as client:
        # Safe request
        response = await client.get("/api/search?q=test")
        assert response.status_code == 200
        assert response.json() == {"results": ["test"]}

        # XSS attempt
        response = await client.get("/api/search?q=<script>alert(1)</script>")
        assert response.status_code == 403

@pytest.mark.asyncio
async def test_allows_safe_html():
    app = create_app()

    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/api/search?q=&lt;test&gt;")
        assert response.status_code == 200
```

### Integration Tests with Flask Test Client

```python
import pytest
from app import create_protected_app

@pytest.fixture
def client():
    app = create_protected_app('testing')
    # Note: Flask test client doesn't work with ASGI apps
    # Use httpx.AsyncClient instead (see above)
    return app

def test_sql_injection_blocked():
    # Use httpx for ASGI apps
    import asyncio
    from httpx import AsyncClient

    async def run_test():
        async with AsyncClient(app=client(), base_url="http://test") as ac:
            response = await ac.get("/api/users?id=1 UNION SELECT * FROM passwords")
            assert response.status_code == 403

    asyncio.run(run_test())
```

---

## Production Deployment

### Gunicorn with Uvicorn Workers

**File**: `wsgi.py`
```python
from app import create_protected_app

app = create_protected_app('production')

# Run with:
# gunicorn wsgi:app -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:8000
```

### Systemd Service

**File**: `/etc/systemd/system/flask-waf.service`
```ini
[Unit]
Description=Flask Application with LeWAF
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/flask-app
Environment="PATH=/opt/flask-app/venv/bin"
ExecStart=/opt/flask-app/venv/bin/gunicorn wsgi:app \
    -k uvicorn.workers.UvicornWorker \
    -w 4 \
    -b 127.0.0.1:8000 \
    --access-logfile /var/log/flask-app/access.log \
    --error-logfile /var/log/flask-app/error.log

Restart=always

[Install]
WantedBy=multi-user.target
```

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
COPY wsgi.py .

# Non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["gunicorn", "wsgi:app", "-k", "uvicorn.workers.UvicornWorker", \
     "-w", "4", "-b", "0.0.0.0:8000"]
```

### Nginx Reverse Proxy

**File**: `/etc/nginx/sites-available/flask-app`
```nginx
upstream flask_app {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://flask_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Troubleshooting

### Issue 1: "Module not found: lewaf"

**Problem**: Import error when running the app.

**Solution**:
```bash
pip install lewaf
# Or if using virtual environment:
source venv/bin/activate
pip install lewaf
```

### Issue 2: "Cannot use Flask test client"

**Problem**: `app.test_client()` doesn't work with ASGI apps.

**Solution**: Use `httpx.AsyncClient` for testing:
```python
from httpx import AsyncClient
import pytest

@pytest.mark.asyncio
async def test_endpoint():
    async with AsyncClient(app=protected_app, base_url="http://test") as client:
        response = await client.get("/api/users")
        assert response.status_code == 200
```

### Issue 3: "WSGI to ASGI conversion issues"

**Problem**: Some Flask extensions don't work well with ASGI.

**Solutions**:
1. Use ASGI-compatible alternatives
2. Test thoroughly before production
3. Consider using Flask-specific WAF if ASGI conversion problematic

### Issue 4: Performance Degradation

**Problem**: WSGI→ASGI conversion adds overhead.

**Solutions**:
1. Use Redis for storage (not memory/file)
2. Increase worker count
3. Enable caching
4. Monitor and profile

```yaml
# config/lewaf.yaml
storage:
  backend: redis

performance:
  regex_cache_size: 512
```

---

## Best Practices

### 1. Configuration

- ✅ Use separate configs for dev/staging/prod
- ✅ Store sensitive data in environment variables
- ✅ Version control rule files
- ✅ Test in DetectionOnly mode first

### 2. Performance

- ✅ Use Redis for storage in production
- ✅ Enable regex caching
- ✅ Monitor WAF performance
- ✅ Tune worker count

### 3. Security

- ✅ Keep LeWAF updated
- ✅ Use OWASP CRS as baseline
- ✅ Add Flask-specific rules
- ✅ Enable audit logging
- ✅ Mask sensitive data

### 4. Testing

- ✅ Use httpx.AsyncClient for tests
- ✅ Test both safe and malicious input
- ✅ Monitor false positive rate
- ✅ Load test with WAF enabled

---

## Complete Example

```python
# app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app(config_name='development'):
    app = Flask(__name__)
    app.config.from_object(f'config.{config_name}Config')

    db.init_app(app)

    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    return app

# app/api.py
from flask import Blueprint, request, jsonify
from app import db
from app.models import User

api_bp = Blueprint('api', __name__)

@api_bp.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify({
        "users": [u.to_dict() for u in users]
    })

@api_bp.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    user = User(name=data['name'], email=data['email'])
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201

# wsgi.py
from app import create_app
from asgiref.wsgi import WsgiToAsgi
from lewaf.integration.asgi import ASGIMiddleware
import os

flask_app = create_app(os.getenv('FLASK_ENV', 'production'))
asgi_app = WsgiToAsgi(flask_app)

app = ASGIMiddleware(
    asgi_app,
    config_file=f"config/{os.getenv('FLASK_ENV', 'production')}.yaml",
    enable_hot_reload=True
)

# Run: gunicorn wsgi:app -k uvicorn.workers.UvicornWorker -w 4
```

---

## Related Documentation

- [Quickstart Guide](quickstart.md)
- [API Reference](../api/reference.md)
- [Django Integration](integration-django.md)
- [FastAPI Integration](integration-fastapi.md)
- [Starlette Integration](integration-starlette.md)
- [Custom Rules Guide](custom-rules.md)
- [Docker Deployment](../deployment/docker.md)

---

**Last Updated**: 2025-11-13
**Version**: 1.0.0
